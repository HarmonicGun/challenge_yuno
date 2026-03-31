# PCI DSS v4.0 Compliance Mapping

**System:** Yuno Secrets Lifecycle Automation
**Scope:** Payment provider credential storage, rotation, access, and audit
**Standard:** PCI DSS v4.0
**Date:** 2026-03-31
**Prepared for:** QSA / Compliance auditor review

---

## How to read this document

Each entry states:
- The PCI DSS requirement and what it mandates
- The specific control implemented in this system
- The exact source file and line where the control lives
- The evidence an auditor should examine
- The compliance status and any open remediation item

**Status legend:**
- `SATISFIED` — control is implemented and verifiable in current code
- `PARTIAL` — control exists but has a documented gap requiring remediation before production
- `NOT MET` — control is absent; system must not enter production scope without remediation

---

## Requirement 3 — Protect Stored Account Data

---

### 3.4.1 — Sensitive authentication data must be rendered unreadable using strong cryptography wherever stored

**What it requires:** Any stored credential used to authenticate to cardholder data systems must be encrypted using industry-accepted algorithms and key lengths. Cleartext storage is prohibited.

**Control implemented:**
All secret values are encrypted with AES-256-GCM before being written to `data/secrets.json`. A unique 96-bit random nonce is generated per write. The ciphertext includes a 128-bit authentication tag (GCM), providing both confidentiality and integrity. Plaintext never touches disk.

**Implementation:**
- `crypto.py:31–35` — `encrypt()`: generates nonce via `os.urandom(12)`, calls `AESGCM(key).encrypt()`, returns `base64(nonce).base64(ciphertext+tag)`
- `crypto.py:38–43` — `decrypt()`: reverses the above; raises `InvalidTag` if ciphertext is tampered
- `store.py:139` — `put_version()` calls `crypto.encrypt(value)` before writing to the store
- `store.py:53,58,64` — all read paths call `crypto.decrypt()` before returning values to callers

**Evidence for auditor:**
1. Inspect `data/secrets.json` — the `value` field for every version must be a base64-encoded blob in `<nonce>.<ciphertext>` format, not a readable string.
2. Run `python3 -c "import json; d=json.load(open('rotation/data/secrets.json')); [print(v['value'][:20]) for versions in d.values() if isinstance(versions,dict) for v in versions.values() if 'value' in v]"` — output must contain no `pk_live_`, `whsec_`, or `rt_` prefixes.
3. Review `crypto.py` — confirm `AESGCM` from the `cryptography` library with `bit_length=256`.

**Status: PARTIAL**

Open item: The AES key is stored at `data/store.key` (file, mode 600). This satisfies confidentiality from unprivileged users but does not meet 3.7.1 (key rotation) or 3.6.1 (formal key custodianship). Before production:
1. Replace `crypto._load_key()` with a call to AWS KMS `GenerateDataKey` or HashiCorp Vault Transit. The plaintext data key must exist only in process memory.
2. Establish a key rotation schedule (minimum annual per 3.7.1).
3. Designate a key custodian with documented acceptance of responsibility.

---

### 3.5.1 — Cryptographic keys used to protect stored account data must themselves be secured

**What it requires:** Keys must be protected against disclosure and misuse. Access to keys must be restricted to the fewest custodians necessary.

**Control implemented:**
`data/store.key` is created with `chmod 0o600` (`crypto.py:26`). It is not embedded in code or environment variables. It is excluded from the application's normal data paths and has no IAM policy granting service accounts access to it.

**Evidence for auditor:**
1. `ls -la rotation/data/store.key` — must show `-rw-------` (owner read/write only).
2. Confirm `store.key` is absent from version control: `git log --all --full-history -- rotation/data/store.key` must return no commits.
3. Confirm `store.key` is in `.gitignore` or equivalent exclusion.

**Status: PARTIAL**

Open item: File-based key has no access logging, no rotation mechanism, and no split-knowledge protection. Remediation is the same as 3.4.1: move to KMS/Vault where key access is logged, rotatable, and never materialises on the application host.

---

## Requirement 7 — Restrict Access to System Components and Cardholder Data by Business Need to Know

---

### 7.2.1 — An access control system is in place that restricts access based on a user's need to know

**What it requires:** Access to system components and data must be restricted to individuals whose job requires it. Default must be deny-all.

**Control implemented:**
`iam.py` implements a policy engine with default-deny posture. Every access requires an explicit `Allow` statement. An explicit `Deny` overrides any `Allow`. No wildcards are permitted in principal, action, or resource fields.

**Implementation:**
- `iam.py:164–202` — `PolicyEngine.evaluate()`: iterates statements, raises `AccessDenied` on explicit Deny or on no-match
- `iam.py:197` — implicit deny: if `allow_matched` is False after all statements, raises `AccessDenied`
- `store.py:123–128,146–152,186–188` — `put_version`, `set_version_state`, `delete_version` each call `self._engine.evaluate(caller_identity, action, secret_id)` before executing

**Evidence for auditor:**
1. Attempt a cross-service read: `python3 -c "from rotation.iam import PolicyEngine; PolicyEngine().evaluate('service:checkout','secrets:GetValue','webhook_secret')"` — must raise `AccessDenied`.
2. Attempt a service write: `python3 -c "from rotation.iam import PolicyEngine; PolicyEngine().evaluate('service:checkout','secrets:PutVersion','provider_api_key')"` — must raise `AccessDenied`.
3. Review `iam.py:63–155` — confirm no `"*"` in any `principals`, `actions`, or `resources` list.

**Status: PARTIAL**

Open item: IAM is enforced at the application layer, not at the storage layer. Direct filesystem access to `data/secrets.json` bypasses all policy checks. Remediation: move the store behind an authenticated API (AWS Secrets Manager, Vault) so the network boundary enforces identity. Until then, OS-level file permissions (`chmod 600 data/secrets.json`) must be verified on every deployment.

---

### 7.2.2 — Access is assigned based on job classification and function (least privilege)

**What it requires:** Each principal must have access only to the resources required for its specific role — no more.

**Control implemented:**
Each service is bound to exactly one secret. No service has access to another service's credential or to any write operation.

| Principal | Permitted actions | Permitted secrets |
|---|---|---|
| `service:checkout` | `GetValue`, `ListVersions` | `provider_api_key` only |
| `service:webhooks` | `GetValue`, `ListVersions` | `webhook_secret` only |
| `service:refunds` | `GetValue`, `ListVersions` | `refund_token` only |
| `system:orchestrator` | All rotation actions | All three secrets |
| `user:developer` | `GetValue`, `ListVersions` | All three (masked by default) |
| `system:break-glass` | `GetValue`, `ListVersions` | All three (explicit Deny on write/rotate/revoke) |

**Implementation:**
- `iam.py:66–91` — one `Allow` statement per service, one secret per statement
- `iam.py:143–154` — explicit `Deny` for `system:break-glass` on all mutation actions
- `schemas.py:48–67` — `REGISTRY` maps each secret to its single `owner_service`

**Evidence for auditor:**
1. Review `iam.py:POLICY` — count `Allow` statements for each `service:*` principal. Each must reference exactly one `resources` entry.
2. Verify no service principal appears in the orchestrator statement or any write-action statement.

**Status: SATISFIED**

---

## Requirement 8 — Identify Users and Authenticate Access to System Components

---

### 8.2.1 — All user and administrator accounts are uniquely identified

**What it requires:** Every user and non-consumer system account must have a unique identifier. Shared or generic accounts are prohibited.

**Control implemented:**
Every principal in the system carries a unique, typed identifier string. Human identities include the individual's email as the audit record's `user` field even when the IAM principal is the shared role `user:developer`.

| Account type | Identifier format | Example |
|---|---|---|
| Human developer | `user:developer` (role) + `email` in audit `details` | `"email": "dev@yuno.co"` |
| Service machine identity | `service:<name>` | `service:checkout` |
| Orchestrator | `system:orchestrator` | — |
| Break-glass session | `system:break-glass` + `approver` in audit `details` | `"approver": "ops@yuno.co"` |

**Implementation:**
- `audit.py:43` — `AuditEvent.identity` is a required field; empty string raises `ValueError`
- `dev_cli.py:114` — login audit event records `details.email` alongside the role principal
- `break_glass.py:122` — activation audit event records `details.approver`

**Evidence for auditor:**
1. Pull any 10 events from `data/audit.log` — every event must have a non-empty `identity` field.
2. For `action: "read"` events, verify `details.email` is present to identify the individual behind the `user:developer` role.

**Status: PARTIAL**

Open item: `_MOCK_USERS` (`dev_cli.py:44`) stores credentials in source code. Production requires integration with a directory service (LDAP, OIDC). Until then, the user list is static and account lifecycle (onboarding/offboarding) is manual.

---

### 8.3.6 — Passwords and passphrases must meet minimum complexity requirements

**What it requires:** Passwords must be at least 12 characters and contain a mix of character types.

**Control implemented:**
Passwords are validated via lookup against `_MOCK_USERS` (`dev_cli.py:103`). The mock passwords (`dev-password`, `ops-password`) do not meet this requirement.

**Status: NOT MET**

Remediation: Remove `_MOCK_USERS` entirely. Delegate authentication to a compliant identity provider (OIDC/SAML). The password complexity requirement is then enforced by the IdP, not by this application.

---

### 8.4.2 — MFA is required for all access into the CDE for personnel with non-consumer access

**What it requires:** Multi-factor authentication must be used for all administrative and privileged access to cardholder data environment components.

**Control implemented (partial):**
Break-glass access requires a second factor in the form of a verbal out-of-band confirmation code (`break_glass.py:46–55`). A session-unique 8-character hex code is generated, displayed to the activating operator, and must be read back after the approver receives it verbally. This simulates a second factor.

Developer CLI (`dev_cli.py`) uses single-factor authentication only (password).

**Evidence for auditor:**
1. Review `break_glass.py:46–55` (`_require_approver_confirmation`) — confirm code is generated via `secrets.token_hex(4)` (cryptographically random, not timestamp-based), displayed once, and compared against user input.
2. Confirm the code is not logged (`data/audit.log` must not contain the approval code value).

**Status: PARTIAL**

Open items:
- Developer CLI has no second factor. All developer access to PCI-scoped secrets requires MFA per 8.4.2. Remediation: integrate TOTP (RFC 6238) at login in `dev_cli.py`.
- Break-glass approval code uses verbal relay, not a cryptographic proof. Remediation: integrate TOTP with the approver's registered device, or use AWS SSM OpsItems with MFA confirmation as the approval channel.

---

### 8.6.2 — System and application accounts must not have the ability to log in interactively

**What it requires:** Non-human accounts used by applications must be restricted to the specific programmatic access they need. They must not be usable for interactive logins.

**Control implemented:**
Service identities (`service:checkout`, `service:webhooks`, `service:refunds`) are defined only as strings in `iam.py:POLICY`. They have no password, no token issuance path, and no entry in `_MOCK_USERS`. There is no code path through which a service identity can invoke `dev_cli.py login`.

**Evidence for auditor:**
1. Search for any code path that issues a session token for a `service:*` principal — must return no results: `grep -r "service:" rotation/ | grep -v iam.py | grep -v services.py | grep -v rotate.py`.
2. Confirm `dev_cli.py:44` (`_MOCK_USERS`) contains only human email addresses.

**Status: SATISFIED**

---

## Requirement 10 — Log and Monitor All Access to System Components and Cardholder Data

---

### 10.2.1 — Audit logs capture required data for all events

**What it requires:** Audit logs must record: user identification, type of event, date/time, success or failure, origination of event, identity of affected data/component.

**Control implemented:**
Every audit event is an `AuditEvent` dataclass (`audit.py:42–58`) with the following fields — all mandatory (empty string raises `ValueError` at write time):

| PCI-required field | System field | Where set |
|---|---|---|
| User identification | `identity` | caller-supplied; validated non-empty at `audit.py:54` |
| Type of event | `action` | `AuditAction` Literal (`audit.py:28–36`) |
| Date and time | `timestamp` | ISO-8601 UTC, set by `AuditLog.log()` at `audit.py:85` |
| Success or failure | `status` | `"success"` or `"failure"`, validated non-empty |
| Origination | `trace_id` | UUID correlating all events in a rotation job |
| Affected data component | `secret_id` + `version` | secret ID (never value); version ID |

Secret values never appear in any log field. The `details` dict may contain `email`, `masked`, `approver`, and similar contextual fields but is structurally prohibited from containing secret values by convention and code review.

**Evidence for auditor:**
1. Pull a sample of 20 events from `data/audit.log` and verify all seven fields are present and non-null on every line.
2. `grep -i "pk_live\|whsec\|rt_" data/audit.log` — must return no output.
3. Review `audit.py:52–58` (`__post_init__`) — confirm the validation loop covers `identity`, `secret_id`, `action`, `status`, `trace_id`.

**Status: SATISFIED** (field completeness)

---

### 10.2.2 — Audit logs are protected to prevent modifications

**What it requires:** Audit log data must be protected from destruction and unauthorised modifications. Mechanisms must prevent logs being altered after the fact.

**Control implemented:**
`audit.py:89` opens the log file in `"a"` (append-only) mode. There is no `seek`, `truncate`, or overwrite call anywhere in the codebase. The log file and the secrets store file are at separate paths (`data/audit.log` vs `data/secrets.json`).

**Evidence for auditor:**
1. `grep -rn "open.*audit" rotation/` — all matches must use mode `"a"`, never `"w"`, `"r+"`, or `"a+"`.
2. `grep -rn "truncate\|unlink\|remove\|os.remove" rotation/audit.py` — must return no results.

**Status: PARTIAL**

Open item: File-mode append-only is enforced only at the Python layer. Any OS process with write access to `data/` can truncate or delete the file. Before production:
1. Apply `chattr +a data/audit.log` (Linux append-only inode flag) immediately after file creation.
2. Ship events in real time to an immutable external sink: AWS CloudWatch Logs (no-delete policy) or S3 with Object Lock (COMPLIANCE mode, WORM).
3. The application log file then becomes a local buffer only; the authoritative audit trail is the external sink.

---

### 10.3.3 — Audit log files are promptly backed up to a centralised log server

**What it requires:** Audit logs must be backed up to a separate, centralised server or media difficult to alter.

**Control implemented:**
Not implemented. `data/audit.log` is a local file with no shipping, forwarding, or replication.

**Status: NOT MET**

Remediation: Replace the `with open(self.path, "a")` write in `audit.py:89` with a dual write: append locally (buffer) and call a log aggregator API synchronously. If the remote write fails, the rotation must be halted (not silently continued with audit loss). Suitable targets: CloudWatch Logs `PutLogEvents`, Splunk HEC, Datadog Logs API.

---

### 10.5.1 — Retain audit logs for at least 12 months, with at least three months immediately available

**What it requires:** Audit log history must be retained for a minimum of 12 months. The most recent three months must be immediately accessible for analysis.

**Control implemented:**
Not implemented. `data/audit.log` is a single unbounded append file with no archival policy, rotation schedule, or retention enforcement.

**Status: NOT MET**

Remediation:
1. Configure the external log sink (see 10.3.3) with a 12-month retention policy.
2. Set a lifecycle rule to move logs older than 90 days to cold storage (S3 Glacier, CloudWatch log archival) while keeping the last 90 days in hot tier.
3. Implement local log rotation (`logrotate` or application-level) to cap local file size; the external sink is the retention authority.

---

### 10.7.1 — Failures of critical security controls are detected and reported

**What it requires:** Failures of audit logging and other critical security controls must be detected, alerted on, and responded to promptly.

**Control implemented (partial):**
If `audit.py:log()` raises an exception (disk full, permission error), the exception propagates to the caller. In `rotate.py`, this would cause the rotation to fail and trigger rollback. This is an implicit failure signal but not a monitored alert.

There is no heartbeat, no metric emission, and no alerting when the audit log is unavailable.

**Status: PARTIAL**

Remediation:
1. Wrap the audit write in `audit.py:89` in a try/except. On failure: write to `stderr`, increment a failure counter, and emit a metric to CloudWatch (`PutMetricData`).
2. Set a CloudWatch alarm on `AuditWriteFailures > 0` with `SNS` notification to on-call.
3. For the rotation orchestrator: if an audit write fails during a rotation, the rotation must halt — credential changes without an audit trail are a PCI violation.

---

## Compliance Status Summary

| Requirement | Sub-requirement | Status | Must fix before production |
|---|---|---|---|
| 3 | 3.4.1 — Encryption at rest | PARTIAL | Move key to KMS/Vault |
| 3 | 3.5.1 — Key protection | PARTIAL | Move key to KMS/Vault |
| 7 | 7.2.1 — Access control system | PARTIAL | Move store behind authenticated API |
| 7 | 7.2.2 — Least privilege | SATISFIED | — |
| 8 | 8.2.1 — Unique account IDs | PARTIAL | Replace mock users with IdP |
| 8 | 8.3.6 — Password complexity | NOT MET | Delegate auth to compliant IdP |
| 8 | 8.4.2 — MFA for privileged access | PARTIAL | Add TOTP to dev CLI; harden break-glass approval |
| 8 | 8.6.2 — No interactive login for system accounts | SATISFIED | — |
| 10 | 10.2.1 — Required log fields | SATISFIED | — |
| 10 | 10.2.2 — Log tamper protection | PARTIAL | Ship to immutable external sink; `chattr +a` locally |
| 10 | 10.3.3 — Centralised log server | NOT MET | Implement real-time log shipping |
| 10 | 10.5.1 — 12-month retention | NOT MET | Configure retention policy on external sink |
| 10 | 10.7.1 — Detect audit failures | PARTIAL | Emit metric + alert on audit write failure |

**Controls that are SATISFIED in the current codebase:** 7.2.2, 8.2.1 (partially), 8.6.2, 10.2.1

**Controls blocking production use:** 3.4.1 (key management), 8.3.6, 10.3.3, 10.5.1

**Controls requiring remediation but not blocking a sandbox/dev deployment:** 3.5.1, 7.2.1, 8.4.2, 10.2.2, 10.7.1
