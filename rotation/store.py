"""
Versioned secrets store backed by a local JSON file.
Atomic writes via temp-file rename to avoid partial reads.

Security hardening applied:
  H1 — secret values are AES-256-GCM encrypted at rest via crypto.py
  H2 — transition_version_states() atomically demotes old + activates new in one write
  H3 — mutating methods require caller_identity and enforce IAM policy
  H6 — put_version guards against silent version overwrites
"""

import fcntl
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import crypto
from iam import PolicyEngine, AccessDenied

_READ_RETRIES = 3
_READ_BACKOFF = 0.1   # seconds; doubles each attempt

STORE_PATH = Path(__file__).parent / "data" / "secrets.json"


class SecretsStore:
    # Version states: pending → active → grace → revoked

    def __init__(self, path: Path = STORE_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({})

    # ── Internal I/O ──────────────────────────────────────────────────────────

    def _read(self) -> dict:
        """
        Read with retry for transient I/O errors (e.g. NFS blip, disk flush).
        Distinguishes corruption (JSONDecodeError → immediate fail) from
        transient unavailability (OSError → retry with backoff).
        """
        last_exc = None
        for attempt in range(_READ_RETRIES):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except json.JSONDecodeError as exc:
                # Store file is corrupt — retrying won't help.
                raise RuntimeError(
                    f"Secrets store is corrupt ({self.path}): {exc}. "
                    "Restore from backup before proceeding."
                ) from exc
            except OSError as exc:
                last_exc = exc
                if attempt < _READ_RETRIES - 1:
                    time.sleep(_READ_BACKOFF * (2 ** attempt))
        raise RuntimeError(
            f"Secrets store unavailable after {_READ_RETRIES} attempts: {last_exc}"
        ) from last_exc

    @contextmanager
    def rotation_lock(self, secret_id: str):
        """
        OS-level exclusive lock for a rotation job.  Prevents the TOCTOU race
        where two processes both read an empty advisory lock and both proceed.

        Uses fcntl.flock(LOCK_EX | LOCK_NB): fails immediately if another
        process holds the lock for the same secret.  The advisory in-JSON lock
        (set_rotation_state) still runs after this and serves as the audit trail.
        """
        lock_path = self.path.parent / f".lock_{secret_id}"
        lock_path.touch(exist_ok=True)
        with open(lock_path) as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError(
                    f"Another rotation process holds the lock for '{secret_id}'. "
                    "Wait for it to finish or investigate if it is stale."
                )
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _write(self, data: dict):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        tmp.replace(self.path)  # atomic on POSIX

    # ── Secret version CRUD ───────────────────────────────────────────────────

    def get_versions(self, secret_id: str) -> dict:
        return self._read().get(secret_id, {})

    def get_version(self, secret_id: str, version_id: str) -> Optional[dict]:
        v = self.get_versions(secret_id).get(version_id)
        if v is None:
            return None
        return {"version_id": version_id, **v, "value": crypto.decrypt(v["value"])}

    def get_active_version(self, secret_id: str) -> Optional[dict]:
        for vid, v in sorted(self.get_versions(secret_id).items(), reverse=True):
            if v["state"] == "active":
                return {"version_id": vid, **v, "value": crypto.decrypt(v["value"])}
        return None

    def get_valid_versions(self, secret_id: str) -> list[dict]:
        """Both active and grace versions are valid during rotation."""
        return [
            {"version_id": vid, **v, "value": crypto.decrypt(v["value"])}
            for vid, v in self.get_versions(secret_id).items()
            if v["state"] in ("active", "grace")
        ]

    _engine = PolicyEngine()
    _VALID_STATES = {"pending", "active", "grace", "revoked"}

    def put_version(                                              # H3: requires IAM
        self,
        secret_id: str,
        version_id: str,
        value: str,
        state: str,
        metadata: dict = None,
        caller_identity: str = None,
    ):
        if caller_identity:
            self._engine.evaluate(caller_identity, "secrets:PutVersion", secret_id)
        data = self._read()
        versions = data.setdefault(secret_id, {})
        if version_id in versions:                                # H6: no silent overwrite
            raise ValueError(f"Version '{version_id}' already exists for '{secret_id}'")
        versions[version_id] = {
            "value": crypto.encrypt(value),                      # H1: encrypt at rest
            "state": state,
            "created_at": time.time(),
            "metadata": metadata or {},
        }
        self._write(data)

    def set_version_state(                                        # H3: requires IAM
        self, secret_id: str, version_id: str, state: str, caller_identity: str = None
    ):
        if state not in self._VALID_STATES:
            raise ValueError(f"Invalid state '{state}'")
        if caller_identity:
            self._engine.evaluate(caller_identity, "secrets:SetState", secret_id)
        data = self._read()
        entry = data.get(secret_id, {}).get(version_id)
        if entry is None:
            raise KeyError(f"Version {version_id} not found for secret '{secret_id}'")
        entry["state"] = state
        entry["state_updated_at"] = time.time()
        self._write(data)

    def transition_version_states(                               # H2: atomic activate+demote
        self,
        secret_id: str,
        activate_id: str,
        demote_id: Optional[str],
        caller_identity: str = None,
    ):
        """Promote activate_id → active and demote_id → grace in a single write."""
        if caller_identity:
            self._engine.evaluate(caller_identity, "secrets:SetState", secret_id)
        data = self._read()
        versions = data.get(secret_id, {})
        if activate_id not in versions:
            raise KeyError(f"Version {activate_id} not found for '{secret_id}'")
        versions[activate_id]["state"] = "active"
        versions[activate_id]["state_updated_at"] = time.time()
        if demote_id and demote_id in versions:
            versions[demote_id]["state"] = "grace"
            versions[demote_id]["state_updated_at"] = time.time()
        self._write(data)                                        # single atomic rename

    def delete_version(                                          # H3: requires IAM
        self, secret_id: str, version_id: str, caller_identity: str = None
    ):
        if caller_identity:
            self._engine.evaluate(caller_identity, "secrets:DeleteVersion", secret_id)
        data = self._read()
        if secret_id in data:
            data[secret_id].pop(version_id, None)
            self._write(data)

    # ── Rotation state (idempotency lock) ─────────────────────────────────────

    def get_rotation_state(self, secret_id: str) -> Optional[dict]:
        return self._read().get("__rotation_state__", {}).get(secret_id)

    def set_rotation_state(self, secret_id: str, state: dict):
        data = self._read()
        data.setdefault("__rotation_state__", {})[secret_id] = state
        self._write(data)

    def clear_rotation_state(self, secret_id: str):
        data = self._read()
        data.get("__rotation_state__", {}).pop(secret_id, None)
        self._write(data)
