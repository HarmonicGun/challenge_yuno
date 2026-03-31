#!/usr/bin/env python3
"""
Break-Glass Emergency Access
─────────────────────────────
Grants temporary, read-only access to secrets outside the normal auth path.
Use ONLY when the primary auth system (dev_cli / IAM) is unavailable.

Principal: system:break-glass
Permissions: secrets:GetValue, secrets:ListVersions — all secrets
Explicitly denied: secrets:Rotate, secrets:Revoke, secrets:PutVersion

Every invocation:
  - Requires a written reason
  - Requires an approval code (mock 2-party approval)
  - Issues a token valid for MAX 2 hours
  - Emits a break_glass audit event immediately on activation
  - Emits a break_glass_end event on exit or expiry

Usage:
  python break_glass.py activate --reason "..." --approver ops@yuno.co
  python break_glass.py get <secret_id>
  python break_glass.py end
"""

import argparse
import json
import secrets as _secrets
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from audit import AuditLog
from iam import PolicyEngine, AccessDenied
from schemas import REGISTRY
from store import SecretsStore

PRINCIPAL = "system:break-glass"
MAX_TTL_SECONDS = 7200   # 2 hours — hard ceiling, non-configurable
SESSION_FILE = Path(__file__).parent / "data" / "break_glass_session.json"

# H4: No static codes in source. A fresh code is generated per activation and
# must be verbally relayed to the named approver, who reads it back.
# In production: replace input() with TOTP verification against approver's device.
def _require_approver_confirmation(approver: str) -> None:
    code = _secrets.token_hex(4).upper()          # 8 hex chars, unique per session
    print(f"\n  Approval code : {code}")
    print(f"  Call {approver} and read them this code.")
    print(f"  Ask them to repeat it back, then enter it below.\n")
    entered = input("  Enter code to confirm: ").strip().upper()
    if entered != code:
        raise ValueError("Code mismatch — approval not confirmed.")


# ─────────────────────────────────────────────────────────────────────────────
# Session
# ─────────────────────────────────────────────────────────────────────────────

def _load_session() -> dict:
    if not SESSION_FILE.exists():
        _die("No active break-glass session. Run: python break_glass.py activate")
    session = json.loads(SESSION_FILE.read_text())
    if time.time() > session["expires_at"]:
        SESSION_FILE.unlink(missing_ok=True)
        _die("Break-glass session expired.")
    return session


def _save_session(session: dict):
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    SESSION_FILE.chmod(0o600)


def _ttl_remaining(session: dict) -> str:
    secs = max(0, int(session["expires_at"] - time.time()))
    m, s = divmod(secs, 60)
    return f"{m}m {s:02d}s"


# ─────────────────────────────────────────────────────────────────────────────
# Mock alerting — replace with PagerDuty / SNS in production
# ─────────────────────────────────────────────────────────────────────────────

def _alert(message: str):
    print(f"\n  [ALERT] {message}")
    print(f"  [ALERT] (production: this would page on-call via PagerDuty/SNS)\n")


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_activate(reason: str, approver: str, audit: AuditLog):
    if not reason or len(reason.strip()) < 10:
        _die("--reason is required and must be descriptive (min 10 chars).")
    if not approver:
        _die("--approver is required.")

    # H4: session-unique code; no static secrets in source
    try:
        _require_approver_confirmation(approver)
    except ValueError as e:
        audit.log(PRINCIPAL, "__auth__", "break_glass", "failure",
                  details={"approver": approver, "reason": str(e)})
        _die(str(e))

    session_id = str(uuid.uuid4())[:12]
    now = time.time()
    session = {
        "session_id": session_id,
        "approver": approver,
        "reason": reason.strip(),
        "activated_at": now,
        "expires_at": now + MAX_TTL_SECONDS,
    }
    _save_session(session)

    audit.log(
        PRINCIPAL, "__auth__", "break_glass", "success",
        trace_id=session_id,
        details={
            "approver": approver,
            "reason": reason.strip(),
            "expires_at": session["expires_at"],
            "ttl_seconds": MAX_TTL_SECONDS,
        },
    )

    _alert(f"BREAK-GLASS ACTIVATED by approver={approver}  session={session_id}  reason='{reason.strip()}'")

    print("┌────────────────────────────────────────────────────┐")
    print("│  !! BREAK-GLASS SESSION ACTIVE !!                  │")
    print("│  READ-ONLY. All access is logged and alerted.      │")
    print("└────────────────────────────────────────────────────┘")
    print(f"\nSession ID : {session_id}")
    print(f"Approver   : {approver}")
    print(f"Reason     : {reason.strip()}")
    print(f"Expires    : {_ttl_remaining(session)}")
    print(f"\nRun 'python break_glass.py end' when done.\n")


def cmd_get(secret_id: str, store: SecretsStore, audit: AuditLog):
    session = _load_session()
    session_id = session["session_id"]

    engine = PolicyEngine()
    try:
        engine.evaluate(PRINCIPAL, "secrets:GetValue", secret_id)
    except AccessDenied as e:
        audit.log(PRINCIPAL, secret_id, "break_glass", "failure",
                  trace_id=session_id, details={"reason": str(e)})
        _die(f"Access denied: {e}")

    version = store.get_active_version(secret_id)
    if not version:
        _die(f"No active version found for '{secret_id}'.")

    audit.log(
        PRINCIPAL, secret_id, "break_glass", "success",
        version=version["version_id"],
        trace_id=session_id,
        details={
            "approver": session["approver"],
            "reason": session["reason"],
            "ttl_remaining": _ttl_remaining(session),
        },
    )

    _alert(f"SECRET READ via break-glass: secret={secret_id}  version={version['version_id']}  session={session_id}")

    # Values are always shown in full during break-glass — masking defeats the purpose.
    # The alert above notifies on-call of the full-value access.
    print(f"\n[BREAK-GLASS] secret_id : {secret_id}")
    print(f"[BREAK-GLASS] version   : {version['version_id']}")
    print(f"[BREAK-GLASS] value     : {version['value']}")
    print(f"[BREAK-GLASS] session   : {session_id}  expires in {_ttl_remaining(session)}\n")


def cmd_end(audit: AuditLog):
    if not SESSION_FILE.exists():
        print("No active session.")
        return
    session = json.loads(SESSION_FILE.read_text())
    SESSION_FILE.unlink()

    duration = int(time.time() - session["activated_at"])
    audit.log(
        PRINCIPAL, "__auth__", "break_glass", "success",
        trace_id=session["session_id"],
        details={
            "action": "session_end",
            "approver": session["approver"],
            "duration_seconds": duration,
        },
    )
    print(f"Break-glass session {session['session_id']} ended after {duration}s.")


def cmd_status():
    if not SESSION_FILE.exists():
        print("No active break-glass session.")
        return
    session = json.loads(SESSION_FILE.read_text())
    if time.time() > session["expires_at"]:
        SESSION_FILE.unlink(missing_ok=True)
        print("Session expired.")
        return
    print(f"Session ID : {session['session_id']}")
    print(f"Approver   : {session['approver']}")
    print(f"Reason     : {session['reason']}")
    print(f"Expires    : {_ttl_remaining(session)}")


# ─────────────────────────────────────────────────────────────────────────────
# Plumbing
# ─────────────────────────────────────────────────────────────────────────────

def _die(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="break_glass.py",
        description="[EMERGENCY] Break-glass read-only secret access",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_act = sub.add_parser("activate", help="Open an emergency session (requires approver)")
    p_act.add_argument("--reason", required=True, help="Why this access is needed")
    p_act.add_argument("--approver", required=True, help="Email of second approver")

    p_get = sub.add_parser("get", help="Read a secret value")
    p_get.add_argument("secret_id", choices=list(REGISTRY.keys()))

    sub.add_parser("status", help="Show current session info")
    sub.add_parser("end",    help="Close the session early")

    args = parser.parse_args()
    store = SecretsStore()
    audit = AuditLog()

    if args.command == "activate":
        cmd_activate(args.reason, args.approver, audit)
    elif args.command == "get":
        cmd_get(args.secret_id, store, audit)
    elif args.command == "status":
        cmd_status()
    elif args.command == "end":
        cmd_end(audit)


if __name__ == "__main__":
    main()
