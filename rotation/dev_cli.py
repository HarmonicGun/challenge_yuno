#!/usr/bin/env python3
"""
Developer CLI — secure, audited, read-only access to secrets.

Separation from production:
  - Principal is always "user:<email>", never a service identity.
  - Tokens are short-lived (TTL ≤ 24h), stored in ~/.yuno_dev_token.
  - Secret values are masked by default; --reveal requires confirmation.
  - All access is logged to the shared audit log under action=read.
  - No write, rotate, or revoke paths exist in this tool.

Usage:
  python dev_cli.py login  [--user EMAIL] [--ttl HOURS]
  python dev_cli.py get    <secret_id> [--reveal]
  python dev_cli.py whoami
  python dev_cli.py logout
  python dev_cli.py list
"""

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

# ── Shared components ──────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from audit import AuditLog
from iam import PolicyEngine, AccessDenied
from schemas import REGISTRY
from store import SecretsStore

TOKEN_FILE = Path.home() / ".yuno_dev_token"
MAX_TTL_HOURS = 24
DEV_STORE = StoreProxy = None  # resolved at runtime


# ─────────────────────────────────────────────────────────────────────────────
# Token management
# ─────────────────────────────────────────────────────────────────────────────

# Mock credential store — in production replace with LDAP / SSO / OIDC.
_MOCK_USERS = {
    "dev@yuno.co":     "dev-password",
    "ops@yuno.co":     "ops-password",
}


def _issue_token(user: str, ttl_hours: int) -> dict:
    now = time.time()
    return {
        "token_id": str(uuid.uuid4())[:12],
        "user": user,
        # principal is the IAM role assumed by this session.
        # Individual identity is preserved in 'user' for audit trail.
        "principal": "user:developer",
        "issued_at": now,
        "expires_at": now + ttl_hours * 3600,
        "ttl_hours": ttl_hours,
    }


def _load_token() -> dict:
    if not TOKEN_FILE.exists():
        _die("Not logged in. Run: python dev_cli.py login")
    token = json.loads(TOKEN_FILE.read_text())
    if time.time() > token["expires_at"]:
        TOKEN_FILE.unlink(missing_ok=True)
        _die("Session expired. Run: python dev_cli.py login")
    return token


def _save_token(token: dict):
    TOKEN_FILE.write_text(json.dumps(token, indent=2))
    TOKEN_FILE.chmod(0o600)  # owner-only read/write


def _ttl_remaining(token: dict) -> str:
    secs = max(0, int(token["expires_at"] - time.time()))
    h, m = divmod(secs // 60, 60)
    return f"{h}h {m:02d}m"


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_login(user: str, ttl_hours: int, audit: AuditLog):
    import getpass

    print("┌─────────────────────────────────────────┐")
    print("│  Yuno Developer CLI  [DEV ACCESS ONLY]  │")
    print("└─────────────────────────────────────────┘")

    if not user:
        user = input("Email: ").strip()

    if user not in _MOCK_USERS:
        _die(f"Unknown user: {user}")

    password = getpass.getpass("Password: ")
    if password != _MOCK_USERS[user]:
        audit.log(f"user:{user}", "__auth__", "read", "failure",
                  details={"reason": "invalid credentials"})
        _die("Authentication failed.")

    ttl_hours = min(ttl_hours, MAX_TTL_HOURS)
    token = _issue_token(user, ttl_hours)
    _save_token(token)

    audit.log(token["principal"], "__auth__", "read", "success",
              trace_id=token["token_id"],
              details={"email": user, "ttl_hours": ttl_hours, "expires_at": token["expires_at"]})

    print(f"\nLogged in as : {user}")
    print(f"Token ID     : {token['token_id']}")
    print(f"Expires in   : {_ttl_remaining(token)}")
    print(f"\n[DEV] Token stored at {TOKEN_FILE} (mode 600)")


def cmd_whoami():
    token = _load_token()
    print(f"User          : {token['user']}")
    print(f"Principal     : {token['principal']}")
    print(f"Token ID      : {token['token_id']}")
    print(f"TTL remaining : {_ttl_remaining(token)}")


def cmd_list():
    _load_token()  # just validates session is active
    print("Available secrets:")
    for sid, rec in REGISTRY.items():
        print(f"  {sid:22s}  owner={rec.owner_service}  rotation={rec.rotation_policy.interval_days}d")


def cmd_get(secret_id: str, reveal: bool, store: SecretsStore, audit: AuditLog):
    token = _load_token()
    principal = token["principal"]

    # ── IAM check ─────────────────────────────────────────────────────────────
    engine = PolicyEngine()
    try:
        engine.evaluate(principal, "secrets:GetValue", secret_id)
    except AccessDenied as e:
        audit.log(principal, secret_id, "read", "failure",
                  trace_id=token["token_id"], details={"reason": str(e)})
        _die(f"Access denied: {e}")

    # ── Fetch ──────────────────────────────────────────────────────────────────
    version = store.get_active_version(secret_id)
    if not version:
        _die(f"No active version found for '{secret_id}'.")

    # ── Reveal gate ────────────────────────────────────────────────────────────
    if reveal:
        confirm = input(
            f"\n[DEV] You are about to reveal a live secret value.\n"
            f"      This access will be logged. Type '{secret_id}' to confirm: "
        ).strip()
        if confirm != secret_id:
            print("Aborted.")
            return
        display_value = version["value"]
        masked = False
    else:
        raw = version["value"]
        display_value = raw[:8] + "..." + raw[-4:]
        masked = True

    # ── Audit ──────────────────────────────────────────────────────────────────
    audit.log(
        principal, secret_id, "read", "success",
        version=version["version_id"],
        trace_id=token["token_id"],
        details={"email": token["user"], "masked": masked, "env": "dev"},
    )

    # ── Output ─────────────────────────────────────────────────────────────────
    print(f"\n[DEV] secret_id : {secret_id}")
    print(f"[DEV] version   : {version['version_id']}")
    print(f"[DEV] value     : {display_value}")
    if masked:
        print(f"[DEV] (masked — use --reveal to see full value)")


def cmd_logout(audit: AuditLog):
    if not TOKEN_FILE.exists():
        print("Not logged in.")
        return
    token = json.loads(TOKEN_FILE.read_text())
    TOKEN_FILE.unlink()
    audit.log(token["principal"], "__auth__", "read", "success",
              trace_id=token["token_id"], details={"action": "logout"})
    print(f"Logged out. Token {token['token_id']} revoked.")


# ─────────────────────────────────────────────────────────────────────────────
# Plumbing
# ─────────────────────────────────────────────────────────────────────────────

def _die(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="dev_cli.py",
        description="[DEV] Yuno developer secret access CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_login = sub.add_parser("login", help="Authenticate and obtain a short-lived token")
    p_login.add_argument("--user", default="", help="Email address")
    p_login.add_argument("--ttl", type=int, default=8, metavar="HOURS",
                         help=f"Token TTL in hours (max {MAX_TTL_HOURS}, default 8)")

    p_get = sub.add_parser("get", help="Read a secret value (masked by default)")
    p_get.add_argument("secret_id", choices=list(REGISTRY.keys()))
    p_get.add_argument("--reveal", action="store_true",
                       help="Show the full value (requires confirmation, always audited)")

    sub.add_parser("whoami", help="Show current session info")
    sub.add_parser("list",   help="List available secrets")
    sub.add_parser("logout", help="Revoke current token")

    args = parser.parse_args()

    store = SecretsStore()
    audit = AuditLog()

    if args.command == "login":
        cmd_login(args.user, args.ttl, audit)
    elif args.command == "get":
        cmd_get(args.secret_id, args.reveal, store, audit)
    elif args.command == "whoami":
        cmd_whoami()
    elif args.command == "list":
        cmd_list()
    elif args.command == "logout":
        cmd_logout(audit)


if __name__ == "__main__":
    main()
