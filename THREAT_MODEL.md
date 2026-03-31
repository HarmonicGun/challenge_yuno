# Threat Model & Design Decisions

**System:** Yuno Secrets Lifecycle Automation
**Scope:** `rotation/` — store, IAM, audit, rotation orchestrator, dev CLI, break-glass
**Date:** 2026-03-31

---

## System Trust Boundaries

```
[External Provider API] ── HTTPS ──> provider.py
                                          |
[Secrets Store]  <──── read/write ── rotate.py (system:orchestrator)
data/secrets.json                         |
                                     iam.py (policy gate)
[Audit Log]      <──── append ────── audit.py
data/audit.log                            |
                                    ┌─────┴──────┐
                              dev_cli.py     break_glass.py
                            (user:developer) (system:break-glass)
                                    |               |
                               ~/.yuno_dev_token  data/break_glass_session.json
```

Trust levels (high → low):
1. `system:orchestrator` — full read/write, rotation, revoke
2. `system:break-glass` — read-only, requires 2-party approval
3. `user:developer` — read-only, TTL-gated, masked by default
4. `service:<name>` — read-only, single secret each

---

## Attack Scenarios

### A1 — Direct theft of `data/secrets.json`

**Attacker:** External actor who gains filesystem read access (e.g., via path traversal, misconfigured S3 bucket, leaked backup).

**Impact:** All three credentials exposed in plaintext. Immediate full compromise of `checkout`, `webhooks`, and `refunds` payment flows.

**Current controls:**
- File permissions (OS-level, weak if root is compromised)
- No encryption at rest — values stored as plaintext strings in JSON

**Gap:** `store.py:_read/_write` performs no encryption. The `value` field in `data/secrets.json` is a raw string.

**Mitigation path:** Wrap `_write` with envelope encryption: generate a data key via KMS `GenerateDataKey`, encrypt the value, store the encrypted blob + encrypted data key. Decrypt on `_read`. The plaintext data key never persists to disk.

**Residual risk after mitigation:** KMS key compromise → all secrets exposed. Mitigate with KMS key rotation and access logging.

---

### A2 — Token file theft (`~/.yuno_dev_token`)

**Attacker:** Local user on the same machine, or attacker with read access to the developer's home directory (e.g., via another compromised process, malicious dotfile loader).

**Impact:** Attacker can call `dev_cli.py get <secret>` as `user:developer` until token TTL expires. Max window: 8 hours (configured default), hard ceiling 24h.

**Current controls:**
- `chmod 600` on token file (`dev_cli.py:_save_token`)
- TTL checked on every command (`dev_cli.py:_load_token`)
- All reads logged with `masked: true/false` in audit details

**Gap:** No token revocation list. A stolen token remains valid until TTL. `dev_cli.py logout` only deletes the local file — it does not invalidate the token server-side because there is no server.

**Mitigation path:** Move token validation server-side. Store issued tokens in `data/dev_tokens.json` with a revoked flag. `logout` marks the token revoked. Every `get` checks this list before proceeding.

**Residual risk:** Even with server-side revocation, a token stolen before logout was called has an attack window equal to time-between-theft-and-logout. Reduce TTL default from 8h to 1h for PCI environments.

---

### A3 — Insider abuse via break-glass

**Attacker:** Malicious on-call engineer who self-approves break-glass access (collusion or coercion of the approver).

**Impact:** Full read access to all three credentials under `system:break-glass`. No rotation or write access possible due to explicit IAM deny.

**Current controls:**
- 2-party approval via session-unique one-time code (`break_glass.py:_require_approver_confirmation`): a fresh 8-char hex code is generated at activation time, printed to the requester's terminal, and must be read to the named approver over the phone. The approver reads it back; the requester types it in. No static code exists in source.
- Immediate alert fires on `activate` and every `get` (`break_glass.py:_alert`)
- Session capped at 2h, non-configurable (`MAX_TTL_SECONDS = 7200`)
- Reason string is mandatory (min 10 chars) and logged with approver identity

**Gap:** The one-time code is typed by the requester, not the approver — a colluding pair can trivially bypass this. The alert is the primary compensating control.

**Mitigation path:** Replace the terminal prompt with TOTP verification against the approver's registered device (e.g., PagerDuty manual escalation, AWS SSM OpsItems with MFA, or a Duo push). The approver's approval action must originate from their device, not the requester's terminal.

**Residual risk:** Colluding insider pair can still activate. Compensating control: post-incident review is mandatory (BREAK_GLASS.md), and the alert wakes a third party (on-call) who can revoke if suspicious.

---

### A4 — Rotation race condition / state split

**Attacker:** Two rotation triggers fire simultaneously for the same secret (e.g., a cron overlap + manual trigger).

**Impact:** Two `pending` versions created. Both try to activate. One succeeds, the other's `activate` call sets a different version to `grace` — the real active version is now in an unexpected state. Services may fail auth against neither version.

**Current controls:**
- OS-level exclusive file lock: `store.py:rotation_lock()` uses `fcntl.flock(LOCK_EX | LOCK_NB)` on a per-secret `.lock_<secret_id>` file. Atomic at the kernel level — two processes cannot both acquire it simultaneously.
- Advisory in-JSON lock: `rotate.py:rotate()` also writes `status = in_progress` under `__rotation_state__` for cross-process visibility and audit trail.
- Atomic temp-file rename prevents partial reads of the store during any write.

**Residual risk:** `fcntl.flock` is single-host. Distributed deployments (multiple orchestrator replicas on separate machines) need a distributed lock (e.g., DynamoDB conditional write, Redis `SET NX PX`). The `--force` flag can override a stuck advisory lock but not the OS lock — the OS lock must expire or be released by the holding process.

---

### A5 — Audit log tampering

**Attacker:** Insider or compromised process attempts to delete or rewrite audit entries to erase access evidence.

**Impact:** Loss of forensic trail; inability to detect A3 or A2 post-incident.

**Current controls:**
- `audit.py` opens in `"a"` (append) mode only — no `seek`, no truncate in any code path
- Audit log stored at `data/audit.log`, separate from `data/secrets.json`
- No delete or overwrite path exists in the codebase

**Gap:** Both files are on the same filesystem. A process with write access to the `data/` directory can `rm audit.log` or `truncate` it outside of Python. There is no immutability enforcement at the OS or storage layer.

**Mitigation path:**
- Production: write to CloudWatch Logs (no delete without explicit IAM action) or S3 with Object Lock (WORM — write once, read many).
- Single-host: `chattr +a data/audit.log` after creation (Linux append-only inode flag, requires root to remove).

**Residual risk:** Root-level attacker can always bypass filesystem controls. The audit log must be shipped to an external, separately-permissioned sink in real deployments.

---

### A6 — Service identity spoofing (cross-secret read)

**Attacker:** Compromised `checkout` service process attempts to read `webhook_secret` or `refund_token` by directly calling the store.

**Impact:** Credential cross-contamination; `checkout` can now forge webhook signatures or initiate refunds.

**Current controls:**
- `iam.py:PolicyEngine.evaluate()` enforces per-service bindings: `service:checkout` → `provider_api_key` only
- Explicit deny is not needed here — the allow list is the boundary

**Gap:** The policy engine is enforced in application code. If an attacker bypasses the application layer and reads `data/secrets.json` directly, IAM is irrelevant (see A1).

**Gap 2:** In the mock, services are `MockService` instances in the orchestrator's process — there is no actual network boundary between "checkout" and the secrets store. In production, each service must authenticate with a cryptographic identity (mTLS client cert or AWS IAM role) before the store will respond.

**Mitigation path:** Move the store behind an authenticated API (e.g., HashiCorp Vault, AWS Secrets Manager). Each service authenticates with its IAM role. The store enforces the policy server-side, not in the calling process.

---

### A7 — Secrets leakage in CI/CD logs

**Attacker:** Developer accidentally runs `dev_cli.py get <secret> --reveal` inside a CI pipeline. The value appears in the build log, which may be accessible to all engineers.

**Impact:** Credential exposure to all CI log readers.

**Current controls:**
- `--reveal` requires typing the secret name as confirmation — accidental piped input would produce the wrong string and abort
- `masked: true` is the default; `masked: false` is logged separately and distinguishable in audit

**Gap:** The confirmation prompt reads from stdin. In a CI pipeline, `echo "provider_api_key" | python3 dev_cli.py get provider_api_key --reveal` works silently.

**Mitigation path:** In `cmd_get`, check `sys.stdin.isatty()` before allowing `--reveal`. If stdin is not a terminal (i.e., piped input in CI), reject the reveal regardless of input.

---

## Blast Radius Analysis

| Component compromised | Secrets exposed | Write access? | Audit visible? | Max impact |
|---|---|---|---|---|
| `data/secrets.json` (read) | All 3 credentials, all versions | No | Yes, if log intact | Full credential theft |
| `data/secrets.json` (write) | All 3 credentials | Yes | Yes, if log intact | Credential replacement / DoS |
| `data/audit.log` (delete) | None | No | Log destroyed | Forensic blackout |
| `~/.yuno_dev_token` | 3 credentials (read-only, TTL-limited) | No | Yes (reads logged) | Limited, time-bounded |
| `system:orchestrator` identity | All 3 credentials | Yes — can rotate/revoke | Yes | Full lifecycle control |
| `service:checkout` identity | `provider_api_key` only | No | Yes | Single-credential read |
| `system:break-glass` session | All 3 credentials (read-only, 2h) | No (explicitly denied) | Yes + alert | Limited, time-bounded |
| Mock approval codes leaked | Enables break-glass activation | No | Yes + alert | Same as break-glass above |

---

## Design Trade-offs

### Security vs. Developer Experience

**Grace period duration**
- Longer grace → smoother rotation (services have more time to drain in-flight requests)
- Longer grace → wider window where both old and new credential are valid → larger exposure if old is already compromised
- Current default: `rotate.py` uses `--grace` flag, schemas define per-secret defaults (300–900s). Production should be 5–15 minutes, not hours.

**Masked values in `dev_cli.py`**
- Default masking (`pk_live_...af16`) protects against shoulder-surfing and terminal recording
- But forces `--reveal` workflow, adding friction during incidents
- Trade-off accepted: masking is cheap friction that prevents the most common leakage vector (screen capture, log paste). `--reveal` adds ~5 seconds.

**Break-glass: unmasked values**
- Values shown in full during break-glass, compensated by immediate alert
- Alternative (mask even in break-glass) was rejected: if the system is broken and you need the credential, a masked value is useless
- The alert is the control, not the mask

**Short-lived tokens (8h default)**
- Reduces stolen-token window vs. long-lived API keys
- But forces re-authentication mid-shift, which is friction
- `--ttl` is configurable up to 24h; PCI environments should enforce ≤ 1h via policy

### Speed vs. Safety (Rotation)

**Health check gate before activation**
- Adds ~200ms per service but prevents activating a credential that services can't use
- Skipping this gate for speed would risk activating a bad credential and causing auth failures with no rollback path

**Propagate-before-activate pattern**
- Services pre-fetch in step 3 before the new version goes active in step 5
- Alternative: activate first, rely on services to pick it up on next poll
- Activate-first creates a gap window where the active credential exists in the store but no service has it yet. Any request in that window using the old (now grace) credential is fine, but any new service instance that restarts mid-rotation gets the new one and may not have validated it. Pre-fetch is the safer pattern.

**File-backed store vs. real secrets manager**
- File store was chosen for portability and auditability of the design
- Trade-off: no access control at the storage layer, no envelope encryption, single-host only
- AWS Secrets Manager or Vault would enforce access control server-side, add encryption, and support distributed deployments — but introduce cloud provider dependency

---

## Residual Risks

| Risk | Likelihood | Impact | Owner | Accepted? |
|---|---|---|---|---|
| Plaintext secrets in `data/secrets.json` | High (no KMS) | Critical | Platform | No — requires KMS before production |
| Static mock approval codes | High (in source) | High | Security | No — requires TOTP or SSM OpsItems |
| No token revocation list | Medium | Medium | Platform | Conditional — acceptable if TTL ≤ 1h |
| Single-host file lock (TOCTOU race) | Low (single orchestrator) | High | Platform | Conditional — acceptable for single-host; fix before multi-replica |
| Audit log on same host as secrets | Medium | High | Infra | No — requires external log sink in production |
| `--reveal` usable in CI pipelines | Low (requires intent) | Medium | Developer culture + code | Partial — `isatty()` check recommended |
| Mock provider API never actually revokes | N/A (mock) | N/A | — | Yes — by design |
| No mTLS between services and store | High (no network boundary) | High | Arch | No — requires store-as-service before production |

---

## PCI-DSS Mapping

### Requirement 3 — Protect Stored Account Data

| Sub-requirement | Implementation | Gap |
|---|---|---|
| 3.4 — Render PAN unreadable in storage | `provider_api_key` tagged `pci_scope: true` in `schemas.py:REGISTRY` | Secret values stored as plaintext strings. KMS envelope encryption not yet implemented. |
| 3.5 — Protect cryptographic keys | N/A until encryption is implemented | Key management policy needed: key rotation, least-privilege KMS access, separation of key from data |
| 3.7 — Protect keys used to secure stored data | N/A | See 3.5 |

**Immediate action required:** `store.py:put_version` must encrypt the `value` field before writing. Decryption key must not be stored alongside the ciphertext.

---

### Requirement 8 — Identify Users and Authenticate Access

| Sub-requirement | Implementation | Gap |
|---|---|---|
| 8.2 — Unique IDs for all users | `iam.py`: every principal is a unique named string (`user:dev@yuno.co`, `service:checkout`, etc.) | Mock users are hardcoded in `dev_cli.py:_MOCK_USERS`. Production requires directory integration. |
| 8.3 — Secure individual authentication | `dev_cli.py` requires password + issues TTL token. `break_glass.py` requires 2-party approval code. | Approval codes are static strings in source — not compliant. Requires TOTP or hardware token. |
| 8.6 — System/application accounts managed via policies | `iam.py:POLICY` defines explicit allow statements per principal | Policy is code, not an IAM service. Changes require a code deploy. |
| 8.8 — Service providers support customer MFA | Break-glass has 2-party approval (mock). Dev CLI has single-factor (password only). | Dev CLI requires a second factor (TOTP) to be PCI-compliant for privileged access. |

---

### Requirement 10 — Log and Monitor All Access

| Sub-requirement | Implementation | Gap |
|---|---|---|
| 10.2 — Log all individual access to cardholder data | Every `get`, `read`, `break_glass` action logged in `audit.py` with `secret_id`, `identity`, `version`, `masked` flag | Log is local file. Not shipped to a SIEM or external sink. |
| 10.3 — Protect audit logs from modification | `audit.py` opens in append-only mode. No delete path in code. | OS-level: file can be truncated by root or any process with `data/` write access. No `chattr +a` or Object Lock. |
| 10.4 — Secure audit log review | `AuditLog.tail()` provides basic read. `grep '"action": "break_glass"'` is documented in runbook. | No alerting on anomalous patterns (e.g., burst reads, access outside business hours). SIEM integration needed. |
| 10.5 — Retain audit logs ≥ 12 months | Not implemented | `audit.log` has no rotation or archival policy. File grows unbounded. |
| 10.7 — Detect failures of audit controls | Not implemented | No monitoring of whether `audit.py` is writing successfully (e.g., disk full, permission error silently drops events). |

**Minimum to be PCI-compliant on Req 10:**
1. Ship `audit.log` to CloudWatch Logs or S3 with Object Lock in real time
2. Define a 12-month retention policy on the log group/bucket
3. Set an alarm on log write failures (CloudWatch metric filter on ERROR-level events)
