#!/usr/bin/env python3
"""
Secrets rotation scheduler.

Iterates the secret registry, checks each secret's last successful rotation
against its configured interval, and triggers rotation for overdue secrets.

Designed to be invoked by cron, a process supervisor, or a CI schedule job.

Usage:
  python scheduler.py             # rotate all overdue secrets
  python scheduler.py --dry-run   # report without rotating
  python scheduler.py --grace 30  # override grace period
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from audit import AuditLog
from provider import MockProviderAPI
from rotate import SECRET_SERVICE_MAP, rotate, seed_initial_secret
from schemas import REGISTRY
from services import MockService
from store import SecretsStore


def _is_overdue(secret_id: str, store: SecretsStore) -> tuple[bool, str]:
    """
    Returns (overdue, display_age).
    A secret is overdue if:
      - it has never been successfully rotated, OR
      - time since last completed rotation >= interval_days.
    """
    policy = REGISTRY[secret_id].rotation_policy
    state = store.get_rotation_state(secret_id)

    if not state or state.get("status") != "completed":
        return True, "never"

    age_seconds = time.time() - state["completed_at"]
    interval_seconds = policy.interval_days * 86400
    age_display = f"{age_seconds / 86400:.1f}d"
    return age_seconds >= interval_seconds, age_display


def run(grace_seconds: int, dry_run: bool) -> bool:
    store = SecretsStore()
    audit = AuditLog()
    all_ok = True

    for secret_id, record in REGISTRY.items():
        policy = record.rotation_policy

        if not policy.auto_rotate:
            print(f"[scheduler] {secret_id}: auto_rotate=False — skip")
            continue

        overdue, age_display = _is_overdue(secret_id, store)
        status = "OVERDUE" if overdue else "ok"
        print(
            f"[scheduler] {secret_id}: age={age_display}"
            f"  interval={policy.interval_days}d  [{status}]"
        )

        if not overdue:
            continue

        if dry_run:
            print(f"[scheduler] DRY RUN — would rotate {secret_id}")
            continue

        # Ensure an active version exists before rotating
        seed_initial_secret(secret_id, store, MockProviderAPI(), audit)

        services = [
            MockService(svc_name, secret_id, store)
            for svc_name in SECRET_SERVICE_MAP[secret_id]
        ]

        ok = rotate(
            secret_id=secret_id,
            store=store,
            audit=audit,
            provider=MockProviderAPI(),
            services=services,
            grace_seconds=grace_seconds,
        )

        if not ok:
            print(f"[scheduler] ERROR: rotation failed for {secret_id}")
            all_ok = False

    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description="Secrets rotation scheduler — rotates overdue secrets"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report overdue secrets without triggering rotation",
    )
    parser.add_argument(
        "--grace",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Grace period for triggered rotations (default: 15)",
    )
    args = parser.parse_args()

    ok = run(grace_seconds=args.grace, dry_run=args.dry_run)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
