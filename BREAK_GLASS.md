# Break-Glass Emergency Access — Runbook

**Owner:** Security / Platform On-Call
**Last reviewed:** 2026-03-31
**Script:** `rotation/break_glass.py`
**IAM principal:** `system:break-glass`

---

## When to Use

Break-glass access is for **read-only credential retrieval when all normal access paths are unavailable**.

| Condition | Use break-glass? |
|---|---|
| `dev_cli.py` auth system unreachable | YES |
| Need to verify a credential during a live incident | YES |
| Secrets Manager API returning errors | YES |
| Rotation orchestrator stuck / needs credential to debug | YES |
| Normal dev access but you forgot your password | NO — fix auth |
| Routine secret inspection | NO — use `dev_cli.py` |
| Rotating a compromised secret | NO — fix `rotate.py`, restore normal path first |

Break-glass is a **last resort**. Every use is alerted to on-call. Post-incident review is mandatory.

---

## Safeguards

| Safeguard | Implementation |
|---|---|
| 2-party approval | Activation requires a code from a second named approver |
| Hard TTL | Session expires in 2 hours maximum, non-configurable |
| Read-only | `secrets:Rotate`, `secrets:Revoke`, `secrets:PutVersion` are **explicitly denied** in IAM |
| Immediate alert | Every `activate` and `get` fires an alert to on-call |
| Full audit | Every event written to append-only audit log with `action=break_glass` |
| Values unmasked | Values shown in full — masking defeats the purpose, but the alert compensates |
| Session file isolated | `data/break_glass_session.json`, separate from secrets store |

---

## Procedure

### Step 1 — Declare the incident

Before activating, create an incident record:
- Open a ticket (PagerDuty / Linear / your tracker)
- State: what failed, what you need, who is approving
- Record the ticket ID — you will need it in step 2

### Step 2 — Obtain approval

Contact a second on-call operator. They provide their approval code.

Mock codes (replace with OTP in production):
```
ops@yuno.co   → BG-OPS-2026
admin@yuno.co → BG-ADM-2026
```

### Step 3 — Activate session

```bash
cd rotation/

python3 break_glass.py activate \
  --reason "INCIDENT-123: secrets manager API down, verifying refund_token for payments team" \
  --approver ops@yuno.co \
  --approval-code BG-OPS-2026
```

Expected output:
```
[ALERT] BREAK-GLASS ACTIVATED by approver=ops@yuno.co session=<id> reason='...'

┌────────────────────────────────────────────────────┐
│  !! BREAK-GLASS SESSION ACTIVE !!                  │
│  READ-ONLY. All access is logged and alerted.      │
└────────────────────────────────────────────────────┘
Session ID : <id>
Expires    : 119m 59s
```

If activation fails:
- `Invalid approver or approval code` → verify the approver email and code, try again
- `No active break-glass session` after prior failure → you were denied, do not retry without re-contacting approver

### Step 4 — Read the secret(s) you need

```bash
python3 break_glass.py get <secret_id>

# Available: provider_api_key | webhook_secret | refund_token
```

Each `get` fires an immediate alert to on-call with the secret ID and version.
Copy only what you need. Do not store values in plaintext outside the terminal session.

Check remaining TTL at any time:
```bash
python3 break_glass.py status
```

### Step 5 — End the session

End immediately when done — do not wait for expiry.

```bash
python3 break_glass.py end
```

This:
- Deletes the local session file
- Emits a `break_glass / session_end` audit event with total duration

### Step 6 — Post-incident review (mandatory)

Within 24 hours of session end:
1. File a post-mortem documenting: incident cause, secrets accessed, duration, resolution
2. Confirm the accessed credential was not exposed (check whether it needs rotation)
3. If the normal auth path is restored, rotate any secret accessed under break-glass as a precaution
4. Review the audit trail to confirm no unexpected accesses occurred:

```bash
grep '"action": "break_glass"' rotation/data/audit.log
```

---

## Audit Requirements

Every event emitted during a break-glass session includes:

```json
{
  "identity":  "system:break-glass",
  "secret_id": "<id or __auth__>",
  "action":    "break_glass",
  "status":    "success | failure",
  "trace_id":  "<session_id>",
  "version":   "<version_id or null>",
  "details": {
    "approver":       "ops@yuno.co",
    "reason":         "INCIDENT-123: ...",
    "ttl_remaining":  "119m 45s"
  }
}
```

Events emitted per session:

| Trigger | `secret_id` | `status` |
|---|---|---|
| `activate` (success) | `__auth__` | `success` |
| `activate` (bad code) | `__auth__` | `failure` |
| `get` (success) | `<secret_id>` | `success` |
| `get` (denied) | `<secret_id>` | `failure` |
| `end` | `__auth__` | `success` |

All events are in the shared append-only log at `rotation/data/audit.log`.
In production: ship to CloudWatch Logs with no-delete policy, or S3 with Object Lock.

---

## Constraints Summary

```
Max session TTL    : 2 hours (hard-coded, cannot be extended)
Approval required  : YES — 2-party, named approver + code
Permissions        : secrets:GetValue, secrets:ListVersions only
Denied explicitly  : secrets:Rotate, secrets:Revoke, secrets:PutVersion
Alert on activate  : YES
Alert on each get  : YES
Values masked      : NO (full value shown; alert compensates)
Post-incident review: MANDATORY within 24h
```
