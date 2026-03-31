"""
Mock consumer services.
Each service fetches its secret dynamically from the store (no hardcoded values).
During rotation they are notified to pre-fetch the new version before it activates.

Edge-case handling:
  - discard_version(): rollback notification so services don't hold dangling refs
  - cache_ttl_seconds: pre-fetched version expires; stale cache fails health check
"""

import time

from store import SecretsStore

_CACHE_TTL_DEFAULT = 300  # seconds; services must re-fetch after this


class MockService:
    def __init__(
        self,
        name: str,
        secret_id: str,
        store: SecretsStore,
        inject_failure_at: str = None,
        cache_ttl_seconds: int = _CACHE_TTL_DEFAULT,
    ):
        self.name = name
        self.secret_id = secret_id
        self._store = store
        self._inject_failure_at = inject_failure_at
        self._cache_ttl = cache_ttl_seconds
        self._prefetched_version: str = None
        self._prefetched_at: float = None

    def fetch_secret(self) -> dict:
        """Runtime secret fetch — always reads current active version."""
        version = self._store.get_active_version(self.secret_id)
        if not version:
            raise RuntimeError(f"[{self.name}] No active version for '{self.secret_id}'")
        return version

    def notify_new_version(self, version_id: str) -> bool:
        """
        PROPAGATE step: service pre-fetches and caches the new version.
        Records fetch timestamp for TTL enforcement.
        """
        time.sleep(0.03)

        if self._inject_failure_at == "propagate":
            print(f"  [{self.name}] ERROR: failed to pre-fetch {version_id} (injected)")
            return False

        v = self._store.get_version(self.secret_id, version_id)
        if v is None:
            print(f"  [{self.name}] ERROR: version {version_id} not found in store")
            return False

        self._prefetched_version = version_id
        self._prefetched_at = time.time()
        print(f"  [{self.name}] Pre-fetched {version_id} — ready to switch")
        return True

    def discard_version(self, version_id: str):
        """
        ROLLBACK notification: orchestrator tells the service to drop its
        pre-fetched reference.  Prevents the service from holding a dangling
        pointer to a version that has been deleted from the store.
        """
        if self._prefetched_version == version_id:
            self._prefetched_version = None
            self._prefetched_at = None
            print(f"  [{self.name}] Discarded pre-fetched reference to {version_id}")

    def health_check(self, version_id: str) -> bool:
        """
        Auth health probe against a specific version.
        Fails if the pre-fetched cache is stale (older than cache_ttl_seconds).
        """
        time.sleep(0.05)

        if self._inject_failure_at == "verify":
            print(f"  [{self.name}] HEALTH CHECK FAILED with {version_id} (injected)")
            return False

        # Stale cache check: if the service pre-fetched too long ago it must
        # re-fetch before being trusted to use the new version.
        if self._prefetched_at and (time.time() - self._prefetched_at) > self._cache_ttl:
            print(f"  [{self.name}] HEALTH CHECK FAILED: pre-fetched cache expired")
            return False

        v = self._store.get_version(self.secret_id, version_id)
        if not v or v["state"] not in ("pending", "active", "grace"):
            print(f"  [{self.name}] HEALTH CHECK FAILED: {version_id} not in valid state")
            return False

        if self._prefetched_version != version_id:
            print(f"  [{self.name}] HEALTH CHECK FAILED: version mismatch")
            return False

        print(f"  [{self.name}] health check OK with {version_id}")
        return True
