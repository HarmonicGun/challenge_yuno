"""
Append-only audit log.

Each event is one JSON line written to a file that is separate from the secrets store.
The log is never modified or deleted in normal operation — only appended.
Secret values are never logged. Only IDs, version references, actions, and outcomes.

Required fields (all mandatory — missing fields raise at call site, not silently dropped):
  timestamp   ISO-8601 UTC
  identity    who performed the action  (e.g. "service:checkout", "system:orchestrator")
  secret_id   which secret was touched  (never the value)
  action      what operation occurred
  status      success | failure
  trace_id    correlates all events within a single rotation job
  version     which version was involved (None only for job-level events like rotate_start)
  details     structured context (error messages, superseded versions, etc.)
"""

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Optional

AUDIT_PATH = Path(__file__).parent / "data" / "audit.log"

AuditAction = Literal[
    "seed",
    "rotate_start", "rotate_complete", "rotate_failed",
    "write", "propagate", "verify", "activate",
    "grace_period_end", "revoke",
    "rollback_complete", "rollback_failed",
    "read",                          # service runtime access
    "break_glass",                   # emergency access
]

AuditStatus = Literal["success", "failure"]


@dataclass
class AuditEvent:
    identity: str         # "service:checkout" | "system:orchestrator" | "user:dev@..."
    secret_id: str        # never the secret value
    action: AuditAction
    status: AuditStatus
    trace_id: str
    timestamp: str = ""   # filled by AuditLog.log() — do not set manually
    version: Optional[str] = None
    details: dict = None

    def __post_init__(self):
        # Enforce required string fields are non-empty.
        for f in ("identity", "secret_id", "action", "status", "trace_id"):
            if not getattr(self, f):
                raise ValueError(f"AuditEvent: field '{f}' is required and must be non-empty")
        if self.details is None:
            self.details = {}


class AuditLog:
    def __init__(self, path: Path = AUDIT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        identity: str,
        secret_id: str,
        action: AuditAction,
        status: AuditStatus,
        version: str = None,
        trace_id: str = None,
        details: dict = None,
    ) -> AuditEvent:
        event = AuditEvent(
            identity=identity,
            secret_id=secret_id,
            action=action,
            status=status,
            trace_id=trace_id or str(uuid.uuid4()),
            version=version,
            details=details or {},
        )
        event.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # O_APPEND is atomic on Linux for writes < PIPE_BUF. Safe for single-host use.
        # In production: replace with CloudWatch Logs PutLogEvents / S3 Object Lock write.
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(event)) + "\n")

        return event

    def tail(self, n: int = 20) -> list[dict]:
        """Read the last N events. For debugging and forensic queries only."""
        if not self.path.exists():
            return []
        lines = self.path.read_text().splitlines()
        return [json.loads(l) for l in lines[-n:] if l.strip()]
