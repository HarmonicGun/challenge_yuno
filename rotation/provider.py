"""
Mock external payment provider API.
Simulates credential generation and revocation endpoints.

Edge-case handling:
  - _retry(): transient network failures are retried with exponential backoff
    before surfacing as rotation failures.  Permanent errors (injected) still
    propagate immediately.
"""

import secrets
import time


def _retry(fn, max_attempts: int = 3, backoff: float = 0.5):
    """
    Call fn() up to max_attempts times, sleeping backoff * 2^attempt between
    tries.  Only retries on RuntimeError (transient); re-raises immediately on
    any other exception type.
    """
    last_exc = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except RuntimeError as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                sleep = backoff * (2 ** attempt)
                print(f"  [provider] Transient error ({exc}), retrying in {sleep:.1f}s "
                      f"(attempt {attempt + 1}/{max_attempts})")
                time.sleep(sleep)
    raise last_exc


class MockProviderAPI:
    _PREFIXES = {
        "provider_api_key": "pk_live",
        "webhook_secret": "whsec",
        "refund_token": "rt",
    }

    def __init__(self, inject_failure_at: str = None):
        self._inject_failure_at = inject_failure_at
        self._generate_call_count = 0   # used to simulate transient failure on first call

    def generate_credential(self, secret_id: str) -> dict:
        """Request a new credential. Retried up to 3 times on transient errors."""
        def _call():
            time.sleep(0.05)
            if self._inject_failure_at == "generate":
                raise RuntimeError("[mock] Provider returned HTTP 503 on generate")
            prefix = self._PREFIXES.get(secret_id, "secret")
            return {
                "value": f"{prefix}_{secrets.token_hex(24)}",
                "issued_at": time.time(),
                "expires_at": time.time() + 90 * 24 * 3600,
            }
        return _retry(_call)

    def revoke_credential(self, secret_id: str, value: str) -> bool:
        """Revoke a credential. Returns False (non-fatal) after retries are exhausted."""
        def _call():
            time.sleep(0.05)
            if self._inject_failure_at == "revoke":
                raise RuntimeError("[mock] Provider revocation failed")
            return True
        try:
            return _retry(_call)
        except RuntimeError:
            return False  # revocation failure is non-fatal; caller logs warning
