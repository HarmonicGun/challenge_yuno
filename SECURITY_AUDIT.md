# Security Audit Report

**Auditor:** Internal review
**Scope:** All source files in `rotation/`
**Date:** 2026-03-31
**Standard:** Production-level critique. Each issue references the exact file and line.

---

## Summary

| Severity | Count |
|---|---|
| HIGH | 6 |
| MEDIUM | 9 |
| LOW | 6 |

---

## HIGH Severity

---

### H1 — Secrets stored in plaintext

**File:** `store.py:67-72`

```python
data.setdefault(secret_id, {})[version_id] = {
    "value": value,   # ← raw credential string, no encryption
    ...
}
```

The entire credential is written as a UTF-8 string to `data/secrets.json`. Any process, user, or backup tool with filesystem read access retrieves all live credentials in one `cat`. There is no encryption at rest, no key derivation, and no envelope. This alone negates every other control in the system if the file is ever exfiltrated.

**Fix:** Encrypt the `value` field before write. Use envelope encryption: generate a plaintext data key, encrypt the credential value with AES-256-GCM, encrypt the data key with a KMS master key, store `{"ciphertext": ..., "encrypted_data_key": ..., "iv": ...}`. The plaintext data key must never touch disk. On `_read`, decrypt the data key first, then the value. Swap KMS call for a local key file only in test environments, never in production.

---

### H2 — Non-atomic activate/grace transition creates split-brain window

**File:** `rotate.py:153-155`

```python
store.set_version_state(secret_id, new_version_id, "active")   # write 1
# ← process kill here → two active versions
if old_version_id:
    store.set_version_state(secret_id, old_version_id, "grace") # write 2
```

These are two separate file writes. Each calls `_read()` → modify → `_write()`. If the process is killed (SIGKILL, OOM, power loss) between them, the store is left with both the old and the new version in state `active`. The rollback handler at `rotate.py:214` only restores from state `grace` — it will not fix a double-active state because it never checks for it:

```python
if v and v["state"] == "grace":   # ← only handles grace, not double-active
    store.set_version_state(secret_id, old_version_id, "active")
```

**Impact:** Services that re-fetch their credential after a restart may get either version non-deterministically. The next rotation run will see an `active` version and proceed, silently leaving a permanent second active version in the store.

**Fix:** Batch both transitions in a single `_write()` call. Add a `transition_versions(secret_id, activate_id, demote_id)` method to `SecretsStore` that reads once, applies both state changes, and writes once. One atomic file rename = one consistent transition.

---

### H3 — IAM is not enforced at the store layer

**File:** `store.py` (entire file), `rotate.py:125-128`

`SecretsStore` has no identity parameter on any method. Any code that does `from store import SecretsStore` gets unrestricted read/write access to all secrets with no IAM check. The orchestrator calls `store.put_version(...)` and `store.set_version_state(...)` directly with no `PolicyEngine.evaluate()` call.

```python
# rotate.py:125 — no IAM check before writing
store.put_version(secret_id, new_version_id, cred["value"], "pending", ...)
```

Compare: `dev_cli.py` and `break_glass.py` both call `PolicyEngine.evaluate()` before reads. The orchestrator — which has write access — does not.

**Impact:** Any future code added to the orchestrator, any import of `store.py` from a new script, bypasses all access control. The IAM layer only protects the CLI tools, not the store itself.

**Fix:** Either move the store behind an authenticated HTTP API (Vault, AWS Secrets Manager) so the network boundary enforces identity, or add a mandatory `caller_identity` parameter to every `SecretsStore` mutating method and call `PolicyEngine.evaluate()` inside the store before executing the operation. The second option is defensive-in-depth; the first is the correct production architecture.

---

### H4 — Static approval codes committed to source

**File:** `break_glass.py:44-47`

```python
_VALID_APPROVAL_CODES = {
    "ops@yuno.co":   "BG-OPS-2026",
    "admin@yuno.co": "BG-ADM-2026",
}
```

These are static strings in version-controlled source code. Anyone who has ever cloned the repository, received a code review, or read a build log that printed this file has permanent, irrevocable break-glass access. Rotating these values requires a code deploy. There is no per-incident uniqueness; the same code works for any emergency indefinitely.

**Impact:** The 2-party approval control is entirely fictional. A single actor who has read the source can activate break-glass alone, at any time, without anyone else knowing until the audit log is reviewed.

**Fix:** Remove `_VALID_APPROVAL_CODES` entirely. In production, use time-based OTP (RFC 6238 TOTP) with per-approver seeds stored in a hardware security module or a secrets manager, never in source. The approval code is valid for 30 seconds. For a mock, generate a random code at activation time, print it once, and require the activating engineer to relay it verbally to the approver who reads it back — simulating out-of-band verification.

---

### H5 — `--force` overrides lock silently with no audit event

**File:** `rotate.py:93`, `rotate.py:105-109`

```python
if existing and existing.get("status") == "in_progress" and not force:
    ...
    return False
# If force=True, falls through here with no log entry
store.set_rotation_state(secret_id, {
    "trace_id": trace_id,
    "status": "in_progress",
    ...
})
```

When `--force` is passed, the in-progress lock from a prior rotation is silently discarded. No audit event records that the lock was overridden, who did it, or what the overridden trace ID was. The `rotate_start` event that follows shows a clean start with no indication the lock was forced.

**Impact:** An operator (or attacker with shell access) can use `--force` to inject a second parallel rotation mid-flight, overwriting state that the first rotation is actively using. Post-incident review has no record of the override. PCI-DSS Req 10.2 requires logging all privileged actions — a lock override is a privileged action.

**Fix:** Emit an audit event immediately when `--force` is used, before proceeding:
```python
emit("lock_force_override", "success", details={
    "overridden_trace": existing["trace_id"],
    "overridden_started_at": existing.get("started_at"),
    "forced_by": ORCHESTRATOR_IDENTITY,
})
```
Also print a console warning naming the overridden trace ID.

---

### H6 — Version ID collision on same-second rotation starts

**File:** `rotate.py:124`

```python
new_version_id = f"v{int(time.time())}"
```

Unix timestamp at second precision. Two rotations of the same secret started within the same wall-clock second produce identical version IDs (`v1774924266`). The second `put_version` call silently overwrites the first pending version with a different credential value, same state. The first rotation then proceeds to activate and verify a version whose credential it never generated.

**Impact:** One credential is lost with no audit trail. The activated version may be from the wrong rotation job. The overwritten credential was issued by the provider and is now live at the provider but not tracked in the store — it can never be revoked.

**Fix:** Use a UUID-based version ID, not a timestamp: `f"v{uuid.uuid4().hex[:16]}"`. Add a guard in `put_version` that raises if the version ID already exists:
```python
if version_id in data.get(secret_id, {}):
    raise ValueError(f"Version {version_id} already exists for '{secret_id}'")
```

---

## MEDIUM Severity

---

### M1 — Token file has no integrity protection

**File:** `dev_cli.py:67-68`

```python
token = json.loads(TOKEN_FILE.read_text())
if time.time() > token["expires_at"]:
```

The token file at `~/.yuno_dev_token` is plaintext JSON. A local attacker with write access to the home directory can set `"expires_at": 9999999999` to make the token never expire, or change `"principal"` from `"user:developer"` to `"system:orchestrator"` — which is then passed directly to `PolicyEngine.evaluate()` as the identity. The IAM policy for `system:orchestrator` allows `secrets:PutVersion` and `secrets:Rotate`.

**Fix:** Sign the token at issuance with an HMAC-SHA256 over its canonical JSON representation using a server-side key. Verify the signature in `_load_token` before trusting any field. The key must not be stored in the token file.

---

### M2 — Audit log write failure silently corrupts rotation state

**File:** `audit.py:89-90`, `rotate.py:199-232`

```python
with open(self.path, "a") as f:
    f.write(json.dumps(asdict(event)) + "\n")  # ← if this raises, caller sees exception
```

If the audit log write fails (disk full, permissions error, NFS timeout), the exception propagates to the `emit()` call in `rotate.py`. The `emit()` call is inline inside the rotation flow. A disk-full error on the `emit("activate", ...)` call at `rotate.py:157` would be caught by the outer `except Exception` at line 199, triggering rollback. The rollback itself then calls `emit("rotate_failed", ...)`, which also fails for the same reason. The final `store.set_rotation_state(...)` call in the except block may or may not succeed depending on whether the store is on the same filesystem.

**Impact:** An audit log write failure mid-rotation causes rollback to trigger, audits the rollback failure too (failing again), and leaves the rotation state as `failed` with `rollback_ok=False`. The credential the provider already issued is permanently leaked — it was generated and issued but never stored as active and never revoked.

**Fix:** Separate audit failures from rotation failures. Wrap each `emit()` in a try/except that logs to stderr and a secondary sink (syslog, stdout) but does not re-raise. The rotation must continue even if the audit write fails. Then alert separately on audit write failures. Under PCI-DSS Req 10.7, failures of audit controls must be detected and alerted on.

---

### M3 — `put_version` allows silent overwrite of any version

**File:** `store.py:58-73`

`put_version` contains no guard against overwriting an existing version. Callers can overwrite `active` or `grace` versions by passing an existing `version_id`. There is no check, no error, no audit event. This is exploitable if an attacker controls the `version_id` argument.

**Fix:** Add existence check:
```python
if version_id in data.get(secret_id, {}):
    raise ValueError(f"Version '{version_id}' already exists — use set_version_state to update state")
```

---

### M4 — `set_version_state` accepts arbitrary state strings

**File:** `store.py:75-82`

```python
def set_version_state(self, secret_id: str, version_id: str, state: str):
```

`state` is an unvalidated `str`. Any caller can set `state="compromised"`, `state="active_backup"`, or any other value. Code elsewhere that checks `v["state"] in ("active", "grace")` will silently treat unexpected states as invalid, but no error is raised at write time. A typo (`"acitve"`) silently produces a version that can never be rotated out.

**Fix:** Validate against the allowed state set before writing:
```python
VALID_STATES = {"pending", "active", "grace", "revoked"}
if state not in VALID_STATES:
    raise ValueError(f"Invalid state '{state}'. Must be one of {VALID_STATES}")
```

---

### M5 — `__rotation_state__` key co-mingled in secret namespace

**File:** `store.py:92-103`

The rotation lock is stored at `data["__rotation_state__"]` in the same dict as secrets. `get_versions("__rotation_state__")` would return the entire lock state as if it were a secret's version map. An iteration bug in new code could expose lock state or — more dangerously — attempt to rotate `__rotation_state__` as a secret, corrupting the lock.

**Fix:** Use a separate file (`data/rotation_state.json`) for the lock, or at minimum add a filter in `get_versions()` that raises on reserved keys:
```python
_RESERVED = {"__rotation_state__"}
def get_versions(self, secret_id: str) -> dict:
    if secret_id in _RESERVED:
        raise ValueError(f"'{secret_id}' is a reserved key")
```

---

### M6 — Failed authentication logs claimed identity as verified identity

**File:** `dev_cli.py:104`

```python
if password != _MOCK_USERS[user]:
    audit.log(f"user:{user}", "__auth__", "read", "failure", ...)
```

`user` is the email provided on the command line — entirely attacker-controlled. On a failed auth, the audit log records `identity: "user:attacker@evil.com"` as if that were a verified identity. An attacker probing the system can inject arbitrary strings into the identity field of the audit log, polluting forensic analysis.

**Fix:** Log claimed identity separately from verified identity. Use a constant for the identity field on pre-auth failures (`identity: "unauthenticated"`), and move the actual email into `details.claimed_identity`. Only use the email as the identity field after successful authentication.

---

### M7 — No minimum grace period enforced

**File:** `rotate.py:259-265`

```python
parser.add_argument("--grace", type=int, default=15, ...)
```

`--grace 0` is accepted silently. Zero-second grace means the old version is revoked immediately after activation with no drain window. Any in-flight request using the old credential at the provider fails with an auth error the instant `activate` completes. This violates the zero-downtime guarantee the system is designed to provide.

**Fix:** Enforce a minimum at argument parse time:
```python
if args.grace < 5:
    parser.error("--grace must be at least 5 seconds")
```
For PCI environments, enforce a minimum that matches the longest expected request duration plus one standard deviation.

---

### M8 — Username enumeration on login

**File:** `dev_cli.py:99-100`

```python
if user not in _MOCK_USERS:
    _die(f"Unknown user: {user}")
```

The error message distinguishes between "unknown user" and "wrong password" (`_die("Authentication failed.")`). An attacker can enumerate valid email addresses by observing which error appears. Valid addresses are then targeted for further attacks (password brute-force, phishing).

**Fix:** Return the same error regardless of whether the user exists or the password is wrong:
```python
if user not in _MOCK_USERS or password != _MOCK_USERS[user]:
    audit.log("unauthenticated", "__auth__", "read", "failure",
              details={"claimed_user": user, "reason": "invalid credentials"})
    _die("Authentication failed.")
```

---

### M9 — `audit.tail()` reads entire log into memory

**File:** `audit.py:98`

```python
lines = self.path.read_text().splitlines()
return [json.loads(l) for l in lines[-n:] if l.strip()]
```

On a system with 12 months of audit events at even moderate volume (100 events/day), the log file is ~20MB. At high volume (10,000 events/day across all services) it exceeds 1GB within a year. `read_text()` loads the entire file into memory before slicing. This is an operational hazard, and if called from within a rotation job, could cause OOM-kill mid-rotation.

**Fix:** Seek from the end of the file using binary mode:
```python
def tail(self, n: int = 20) -> list[dict]:
    from collections import deque
    with open(self.path, "rb") as f:
        lines = deque(f, maxlen=n)
    return [json.loads(l) for l in lines if l.strip()]
```

---

## LOW Severity

---

### L1 — Trace ID and token ID are truncated UUIDs

**File:** `rotate.py:85`, `dev_cli.py:51`, `break_glass.py:102`

```python
trace_id = str(uuid.uuid4())[:8]   # 32 bits
token_id  = str(uuid.uuid4())[:12] # 48 bits
```

Truncating UUIDs defeats their collision-resistance. With 32-bit trace IDs, birthday paradox gives ~50% collision probability at ~65,000 IDs. Collisions corrupt forensic correlation: two different rotation jobs share a `trace_id`, making audit reconstruction impossible. Token ID collisions could also confuse logout tracking.

**Fix:** Use the full UUID string (`str(uuid.uuid4())`) for all identifiers that must be unique and traceable.

---

### L2 — `_save_token` is not an atomic write

**File:** `dev_cli.py:74-76`

```python
TOKEN_FILE.write_text(json.dumps(token, indent=2))
TOKEN_FILE.chmod(0o600)
```

`write_text` is not atomic. If the process dies during the write, the token file is partially written. On next `_load_token`, `json.loads()` raises `JSONDecodeError` with a Python traceback, not a clean "please login again" message. Also, `chmod(0o600)` is set after the write — there is a brief window where the file exists at default permissions.

**Fix:** Write to a temp file in the same directory, chmod it, then `rename()` to `TOKEN_FILE`. This mirrors the pattern correctly used in `store.py:_write()`.

---

### L3 — `REGISTRY` is a mutable module-level dict

**File:** `schemas.py:48`

```python
REGISTRY: dict[str, SecretRecord] = { ... }
```

Any code that imports `schemas` can do `REGISTRY["provider_api_key"] = SecretRecord(...)` or `REGISTRY.clear()`. This is especially dangerous if it's ever used as a policy reference — adding a new entry to `REGISTRY` without a corresponding IAM statement would create a secret the IAM layer doesn't know about.

**Fix:**
```python
import types
REGISTRY = types.MappingProxyType({...})
```

---

### L4 — `break_glass.py` session file not protected against corruption

**File:** `break_glass.py:57`

```python
session = json.loads(SESSION_FILE.read_text())
```

If `SESSION_FILE` is corrupted (partial write, manual edit, filesystem error), `json.loads` raises an unhandled `json.JSONDecodeError` with a full Python stack trace. For a security-critical path, the failure mode should be a clean error message, not an internal traceback. Stack traces can leak file paths and line numbers.

**Fix:** Wrap in `try/except json.JSONDecodeError` and print a clean error:
```python
try:
    session = json.loads(SESSION_FILE.read_text())
except (json.JSONDecodeError, KeyError):
    SESSION_FILE.unlink(missing_ok=True)
    _die("Session file corrupted. Please re-activate.")
```

---

### L5 — Passwords stored as plaintext in source (mock)

**File:** `dev_cli.py:44-47`

```python
_MOCK_USERS = {
    "dev@yuno.co":   "dev-password",
    "ops@yuno.co":   "ops-password",
}
```

Even as a mock, storing plaintext passwords normalizes a dangerous pattern. If this is ever used as a template for a real auth module, the pattern carries forward.

**Fix:** Store bcrypt/scrypt hashes. Even in tests, use `passlib` or `hashlib.scrypt` to hash on first use. The test credentials remain `dev-password` but what is stored and compared is the hash.

---

### L6 — No IAM action defined for `secrets:DeleteVersion`

**File:** `iam.py:31-39`, `rotate.py:208`

```python
store.delete_version(secret_id, new_version_id)  # rotate.py:208
```

`delete_version` is called during rollback but there is no `secrets:DeleteVersion` action in the IAM `Action` Literal and no policy statement covering it. If the store is ever moved behind an authenticated API, delete operations would have no policy to match against and would be denied — breaking rollback silently.

**Fix:** Add `"secrets:DeleteVersion"` to the `Action` Literal and add a statement granting it to `system:orchestrator` only. Call `PolicyEngine.evaluate()` before delete in the same way reads are checked.

---

## Rollback Correctness — Specific Scenario Analysis

The rollback handler at `rotate.py:206-231` handles three cases. Here is where each fails:

| Scenario | Handled? | Failure |
|---|---|---|
| Crash after GENERATE, before PROPAGATE | YES | Pending version deleted cleanly |
| Crash after PROPAGATE, before VERIFY | YES | Pending version deleted cleanly |
| Crash after VERIFY, before ACTIVATE (first write) | YES | Pending version deleted; old still active |
| Crash between ACTIVATE write 1 and write 2 **(H2)** | **NO** | Two active versions; rollback only checks for `grace` |
| Crash after ACTIVATE, during GRACE | YES | Both versions in store; rollback reverts `grace` → `active` and deletes new |
| Crash during REVOKE (step 7) | Partial | Old version stays `grace` indefinitely; never revoked; never restored to active |
| Rollback itself crashes **(H1 variant)** | Partial | `rollback_ok=False` logged; state unknown |

The unhandled revoke-crash case at the last row is notable: if the process dies during step 7, the old version is permanently stranded in state `grace`. It is not `active` (so services won't be told to use it), and it is not `revoked` (so the provider still accepts it). The next rotation run calls `get_active_version()` which returns the new version correctly, but `old_version_id` at line 113 points to the *new* version (which just became active), not the grace-stranded one. The grace-stranded version is never cleaned up by any code path.

**Fix:** On startup (or before each rotation), scan for versions stuck in `grace` state older than `grace_seconds * 2` and emit an alert. Add a `--cleanup` command to the orchestrator that forces a revoke of any orphaned grace-state versions.

---

## Zero-Downtime Claim vs. Reality

The system correctly implements pre-fetch before activate. However, zero-downtime has two additional assumptions that are not verified:

1. **All services pre-fetch successfully before activation.** This is verified in STEP 3. If a service is down during propagation, rotation correctly aborts. ✓

2. **Services use the grace-period window correctly.** This is NOT verified. The system trusts that services will complete in-flight requests using the old credential before the grace period expires. If a service has long-running requests (e.g., a payment batch job taking 20 minutes) and `--grace 15` is passed, those requests fail. There is no check between grace period length and maximum service request duration. The system silently accepts `--grace 0` (see M7). ✗

3. **The provider accepts both credentials simultaneously.** The mock always returns `True` for validation. A real provider may have a revocation propagation delay. If the provider revokes the old credential before all its edge nodes have flushed the old key, services still using the grace-period credential get auth failures. This is a provider-side race that the system has no control over, but it should be documented as a dependency assumption, not an absolute guarantee.
