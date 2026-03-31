#!/usr/bin/env python3
"""
Secrets Rotation Orchestrator
──────────────────────────────
Rotation steps:
  1. TRIGGER   — idempotency check, acquire lock
  2. GENERATE  — new credential from mock provider → stored as pending
  3. PROPAGATE — services pre-fetch new version (no traffic switch yet)
  4. VERIFY    — health checks confirm new credential is usable
  5. ACTIVATE  — new version → active; old version → grace
  6. GRACE     — both versions valid; in-flight requests drain
  7. REVOKE    — provider invalidates old credential; state → revoked

Rollback: any failure in steps 2–5 deletes the pending version and
          restores the previous version to active.

Usage:
  python rotate.py --secret provider_api_key [--grace 10] [--seed] [--force]
  python rotate.py --secret provider_api_key --fail-at verify   # test rollback
"""

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone

from audit import AuditLog
from provider import MockProviderAPI
from services import MockService
from store import SecretsStore

ORCHESTRATOR_IDENTITY = "system:orchestrator"

# Secrets and the services that are permitted to consume them (least privilege).
SECRET_SERVICE_MAP = {
    "provider_api_key": ["checkout"],
    "webhook_secret": ["webhooks"],
    "refund_token": ["refunds"],
}


# ── Logging helpers ───────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def step(n: int, name: str, msg: str):
    print(f"[{_ts()}] STEP {n} [{name:<10}] {msg}")


def info(msg: str):
    print(f"[{_ts()}] {'':>17} {msg}")


# ── Seed helper ───────────────────────────────────────────────────────────────

def seed_initial_secret(
    secret_id: str, store: SecretsStore, provider: MockProviderAPI, audit: AuditLog
):
    """Bootstrap an active v0 if the secret has never been stored before."""
    if store.get_active_version(secret_id):
        return
    print(f"[seed] No active version for '{secret_id}'. Creating v0...")
    cred = provider.generate_credential(secret_id)
    store.put_version(secret_id, "v0", cred["value"], "active",
                      {"issued_at": cred["issued_at"]},
                      caller_identity=ORCHESTRATOR_IDENTITY)
    audit.log(ORCHESTRATOR_IDENTITY, secret_id, "seed", "success", "v0")
    print(f"[seed] v0 created and active.")


# ── Core rotation ─────────────────────────────────────────────────────────────

def rotate(
    secret_id: str,
    store: SecretsStore,
    audit: AuditLog,
    provider: MockProviderAPI,
    services: list[MockService],
    grace_seconds: int = 15,
    force: bool = False,
) -> bool:

    trace_id = str(uuid.uuid4())[:8]

    def emit(action, status, version=None, details=None):
        audit.log(ORCHESTRATOR_IDENTITY, secret_id, action, status,
                  version, trace_id, details)

    # ── IDEMPOTENCY CHECK ─────────────────────────────────────────────────────
    existing = store.get_rotation_state(secret_id)
    if existing and existing.get("status") == "in_progress":
        if not force:
            print(f"\n[!] Rotation already in progress for '{secret_id}'")
            print(f"    trace={existing['trace_id']}  started={existing.get('started_at')}")
            print(f"    Use --force to override the lock.")
            return False
        # H5: force override must be audited before the lock is cleared
        audit.log(
            ORCHESTRATOR_IDENTITY, secret_id, "rotate_start", "success",
            trace_id=trace_id,
            details={
                "force_override": True,
                "overridden_trace": existing.get("trace_id"),
                "overridden_started_at": existing.get("started_at"),
            },
        )
        print(f"[!] WARNING: forcing override of lock from trace={existing['trace_id']}")

    print(f"\n{'═'*60}")
    print(f"  secret  : {secret_id}")
    print(f"  trace   : {trace_id}")
    print(f"  grace   : {grace_seconds}s")
    print(f"{'═'*60}\n")

    store.set_rotation_state(secret_id, {
        "trace_id": trace_id,
        "status": "in_progress",
        "started_at": time.time(),
    })

    new_version_id: str = None
    notified: list = []      # services that pre-fetched; must be discarded on rollback
    current = store.get_active_version(secret_id)
    old_version_id: str = current["version_id"] if current else None

    # OS-level exclusive lock wraps both the rotation steps AND the rollback.
    # This prevents the TOCTOU race where two processes both read no advisory lock
    # and both proceed.  The lock is held for the full rotation duration including
    # grace period — a second rotation of the same secret must wait or fail fast.
    try:
        lock_ctx = store.rotation_lock(secret_id)
        lock_ctx.__enter__()
    except RuntimeError as lock_err:
        print(f"\n[!] {lock_err}")
        return False

    try:
        # ── STEP 1: TRIGGER ───────────────────────────────────────────────────
        step(1, "TRIGGER", f"Starting rotation for '{secret_id}'")
        emit("rotate_start", "success")

        # ── STEP 2: GENERATE ──────────────────────────────────────────────────
        step(2, "GENERATE", "Requesting new credential from provider...")
        cred = provider.generate_credential(secret_id)

        new_version_id = f"v{uuid.uuid4().hex[:16]}"             # H6: collision-safe ID
        store.put_version(
            secret_id, new_version_id, cred["value"], "pending",
            {"issued_at": cred["issued_at"], "expires_at": cred["expires_at"]},
            caller_identity=ORCHESTRATOR_IDENTITY,               # H3: IAM enforced
        )
        step(2, "GENERATE", f"Stored {new_version_id} (state=pending)")
        emit("write", "success", new_version_id, {"supersedes": old_version_id})

        # ── STEP 3: PROPAGATE ─────────────────────────────────────────────────
        step(3, "PROPAGATE", f"Notifying {len(services)} service(s) to pre-fetch {new_version_id}...")
        for svc in services:
            if not svc.notify_new_version(new_version_id):
                raise RuntimeError(f"Service '{svc.name}' failed to pre-fetch {new_version_id}")
            notified.append(svc)
        step(3, "PROPAGATE", "All services pre-fetched new version.")
        emit("propagate", "success", new_version_id)

        # ── STEP 4: VERIFY ────────────────────────────────────────────────────
        step(4, "VERIFY", "Running auth health checks against new version...")
        for svc in services:
            if not svc.health_check(new_version_id):
                raise RuntimeError(
                    f"Health check FAILED for '{svc.name}' with version {new_version_id}"
                )
        step(4, "VERIFY", "All health checks passed.")
        emit("verify", "success", new_version_id)

        # ── STEP 5: ACTIVATE ──────────────────────────────────────────────────
        step(5, "ACTIVATE", f"Promoting {new_version_id} → active, "
                            f"{old_version_id or 'none'} → grace...")
        store.transition_version_states(                         # H2: single atomic write
            secret_id, new_version_id, old_version_id,
            caller_identity=ORCHESTRATOR_IDENTITY,
        )
        step(5, "ACTIVATE", "New version is live. Old version in grace period.")
        emit("activate", "success", new_version_id, {"grace_version": old_version_id})

        # ── STEP 6: GRACE PERIOD ──────────────────────────────────────────────
        step(6, "GRACE", f"Waiting {grace_seconds}s — both versions valid...")
        for remaining in range(grace_seconds, 0, -1):
            print(f"\r  [{_ts()}] Grace: {remaining:3d}s remaining...", end="", flush=True)
            time.sleep(1)
        print()
        emit("grace_period_end", "success", old_version_id)

        # ── STEP 7: REVOKE ────────────────────────────────────────────────────
        if old_version_id:
            step(7, "REVOKE", f"Revoking {old_version_id} at provider...")
            old_v = store.get_version(secret_id, old_version_id)
            revoked_at_provider = provider.revoke_credential(secret_id, old_v["value"])

            if not revoked_at_provider:
                info("WARNING: provider revocation call failed — marking revoked locally. Manual cleanup needed.")
                emit("revoke", "failure", old_version_id, {"note": "provider API failed"})
            else:
                emit("revoke", "success", old_version_id)

            store.set_version_state(secret_id, old_version_id, "revoked")
            step(7, "REVOKE", f"{old_version_id} is now revoked.")
        else:
            step(7, "REVOKE", "No previous version to revoke.")

        # ── DONE ──────────────────────────────────────────────────────────────
        store.set_rotation_state(secret_id, {
            "trace_id": trace_id,
            "status": "completed",
            "completed_at": time.time(),
            "active_version": new_version_id,
        })
        emit("rotate_complete", "success", new_version_id)

        print(f"\n{'═'*60}")
        print(f"  ROTATION COMPLETE  active={new_version_id}  trace={trace_id}")
        print(f"{'═'*60}\n")
        return True

    except Exception as exc:
        # ── ROLLBACK ──────────────────────────────────────────────────────────
        print(f"\n[{_ts()}] !! ROTATION FAILED: {exc}")
        print(f"[{_ts()}] !! Rolling back to previous state...")
        emit("rotate_failed", "failure", new_version_id, {"error": str(exc)})

        rollback_ok = True
        try:
            # Notify services that already pre-fetched to discard the version.
            # Without this they hold a dangling reference to a deleted version.
            for svc in notified:
                svc.discard_version(new_version_id)

            if new_version_id:
                store.delete_version(
                    secret_id, new_version_id,
                    caller_identity=ORCHESTRATOR_IDENTITY,
                )
                info(f"Rollback: deleted pending version {new_version_id}")

            if old_version_id:
                v = store.get_version(secret_id, old_version_id)
                if v and v["state"] == "grace":
                    store.set_version_state(
                        secret_id, old_version_id, "active",
                        caller_identity=ORCHESTRATOR_IDENTITY,
                    )
                    info(f"Rollback: restored {old_version_id} → active")

            emit("rollback_complete", "success", old_version_id)
            info("Rollback complete. Previous state restored.")
        except Exception as rb_exc:
            rollback_ok = False
            print(f"[{_ts()}] !! ROLLBACK ALSO FAILED: {rb_exc}")
            emit("rollback_failed", "failure", details={"error": str(rb_exc)})

        store.set_rotation_state(secret_id, {
            "trace_id": trace_id,
            "status": "failed",
            "error": str(exc),
            "rollback_ok": rollback_ok,
            "failed_at": time.time(),
        })
        return False

    finally:
        lock_ctx.__exit__(None, None, None)   # always release the OS lock


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Secrets Rotation Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normal rotation (seed first if no existing secret)
  python rotate.py --secret provider_api_key --grace 10 --seed

  # Test rollback by injecting a failure at the verify step
  python rotate.py --secret webhook_secret --fail-at verify --seed

  # Force override a stuck in-progress lock
  python rotate.py --secret refund_token --force --seed
        """,
    )
    parser.add_argument(
        "--secret",
        required=True,
        choices=list(SECRET_SERVICE_MAP.keys()),
        help="Which secret to rotate",
    )
    parser.add_argument(
        "--grace",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Grace period duration in seconds (default: 15)",
    )
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Bootstrap an active v0 if no secret exists yet",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Override an existing in-progress lock",
    )
    parser.add_argument(
        "--fail-at",
        dest="fail_at",
        choices=["generate", "propagate", "verify", "revoke"],
        metavar="STEP",
        help="Inject a failure at STEP to exercise rollback (testing only)",
    )
    args = parser.parse_args()

    store = SecretsStore()
    audit = AuditLog()
    provider = MockProviderAPI(
        inject_failure_at=args.fail_at if args.fail_at in ("generate", "revoke") else None
    )

    # Build service list; inject service-level failures if requested.
    service_failure = args.fail_at if args.fail_at in ("propagate", "verify") else None
    services = [
        MockService(svc_name, args.secret, store, inject_failure_at=service_failure)
        for svc_name in SECRET_SERVICE_MAP[args.secret]
    ]

    if args.seed:
        seed_initial_secret(args.secret, store, provider, audit)

    if not store.get_active_version(args.secret):
        print(f"[!] No active version for '{args.secret}'. Run with --seed first.")
        sys.exit(1)

    ok = rotate(
        secret_id=args.secret,
        store=store,
        audit=audit,
        provider=provider,
        services=services,
        grace_seconds=args.grace,
        force=args.force,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
