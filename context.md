# Yuno DevSecOps Challenge — System Context

## Goal
Production-grade secrets lifecycle automation for payment provider credentials.
Priorities: zero-downtime rotation · full auditability (PCI-DSS) · least privilege · secure DX.

---

## Architecture

### Component Map
```
CONTROL PLANE
  rotate.py          — rotation orchestrator (stateful, idempotent)
  store.py           — versioned secrets store (JSON, atomic writes)
  audit.py           — append-only structured event log
  provider.py        — mock external provider API (generate + revoke)
  services.py        — mock consumer services (dynamic fetch, health check)

DATA
  data/secrets.json  — versioned secrets + rotation lock state
  data/audit.log     — one JSON event per line, never modified
```

### Key Design Decisions
- **File-backed store** with atomic temp-file rename (POSIX-safe). Swap for AWS Secrets Manager / Vault without changing orchestrator.
- **Version IDs** are Unix timestamps (`v<epoch>`). Ordering is implicit; no separate index needed.
- **Rotation lock** stored inside `secrets.json` under `__rotation_state__` key — same atomic write guarantees.
- **Audit log** is append-only (`open(path, "a")`). Never co-located with secret values.
- **Failure injection** via `--fail-at` flag threads through provider and services — no test-only code paths in core logic.

---

## Secrets Model

```
secret/{id}
  v0   state=revoked
  v1   state=grace      ← old version, still valid during grace window
  v2   state=active     ← current
  v3   state=pending    ← being rotated in
```

**States:** `pending → active → grace → revoked`

**Valid during rotation:** `active` + `grace` (both accepted simultaneously).
Services always fetch dynamically from the store. No hardcoded values, no static env vars.

---

## Least Privilege Map
```
checkout  → provider_api_key  (read only)
webhooks  → webhook_secret    (read only)
refunds   → refund_token      (read only)
orchestrator → all secrets    (read + write, rotation operations only)
```
No wildcards. No shared credentials between services.

---

## Rotation Workflow (7 Steps)

```
STEP 1  TRIGGER    Idempotency check. Block if in_progress lock exists (--force to override).
                   Set rotation state = in_progress. Assign trace_id.

STEP 2  GENERATE   Call provider.generate_credential() → new credential + metadata.
                   Store as version vN+1 with state=pending.
                   Audit: write/success.

STEP 3  PROPAGATE  Notify each dependent service via notify_new_version(vN+1).
                   Services pre-fetch and cache new version. No traffic switch yet.
                   Audit: propagate/success|failure.

STEP 4  VERIFY     Call service.health_check(vN+1) for each service.
                   Confirms new credential is usable end-to-end before cutover.
                   Failure here → ROLLBACK (step never committed).

STEP 5  ACTIVATE   set vN+1 state=active, vN state=grace.
                   Point of no return. Both versions valid from here.
                   Audit: activate/success.

STEP 6  GRACE      Sleep grace_seconds (default 15s, configurable).
                   In-flight requests using vN drain. No forced cutover.
                   Audit: grace_period_end/success.

STEP 7  REVOKE     Call provider.revoke_credential(vN). Set vN state=revoked.
                   Non-fatal if provider call fails: logged as warning, local state still updated.
                   Audit: revoke/success|failure.
```

### Rollback (triggered by failure in steps 2–5)
1. Delete pending version vN+1 from store
2. If vN was already demoted to grace → restore to active
3. Set rotation state = failed
4. Audit: rotate_failed + rollback_complete

No partial broken states. Previous version always remains valid.

---

## Zero-Downtime Mechanism

Three guarantees that together prevent any auth gap:

1. **Pre-fetch before activate** — services receive vN+1 in STEP 3 before it goes live in STEP 5.
2. **Dual-version validity** — `active` + `grace` both accepted during grace window.
3. **Verified gate** — STEP 5 only executes after STEP 4 health checks pass across all services.

If any service fails health check → rotation aborts before cutover, old version untouched.

---

## Audit Event Schema
```json
{
  "timestamp":  "ISO-8601 UTC",
  "identity":   "system:orchestrator | service:checkout | user:dev@...",
  "secret_id":  "provider_api_key",
  "version":    "v1774923197",
  "action":     "rotate_start|write|propagate|verify|activate|grace_period_end|revoke|rotate_complete|rotate_failed|rollback_complete",
  "status":     "success|failure",
  "trace_id":   "8-char hex",
  "details":    {}
}
```
Secret **values are never logged**. Each rotation correlates all events via `trace_id`.

---

## Security Mechanisms
- **Encryption at rest**: not yet implemented (store is plaintext JSON — plug in KMS envelope encryption at `_read`/`_write` layer)
- **Idempotency lock**: prevents concurrent rotations from creating split-brain version states
- **Atomic writes**: temp-file rename prevents partial reads of the secrets store
- **Append-only audit**: file opened in `"a"` mode only; no update or delete path exists in code
- **No wildcard access**: `SECRET_SERVICE_MAP` enforces exact secret-to-service bindings at runtime
- **Blast radius control**: each service credential is independent; compromise of one doesn't expose others

---

## CLI Reference
```bash
# Bootstrap + rotate (first run)
python3 rotate.py --secret provider_api_key --grace 15 --seed

# Subsequent rotations
python3 rotate.py --secret provider_api_key --grace 15

# Test rollback (inject failure at a step)
python3 rotate.py --secret provider_api_key --fail-at verify --seed
# --fail-at options: generate | propagate | verify | revoke

# Override stuck in-progress lock
python3 rotate.py --secret provider_api_key --force
```

---

## Remaining Deliverables
- [ ] IAM / RBAC access control configs
- [ ] Developer CLI (short-lived token access, TTL ≤ 24h)
- [ ] Break glass runbook + emergency access path
- [ ] Threat model document
- [ ] README (setup + usage)
- [ ] Encryption at rest (KMS hook in store.py)
