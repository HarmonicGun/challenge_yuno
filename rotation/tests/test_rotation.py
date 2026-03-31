"""
Focused rotation system tests.
Run with: python -m pytest rotation/tests/ -v
       or: python -m unittest rotation/tests/test_rotation.py -v
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from audit import AuditLog
from crypto import decrypt, encrypt
from iam import AccessDenied, PolicyEngine
from provider import MockProviderAPI
from rotate import SECRET_SERVICE_MAP, rotate, seed_initial_secret
from services import MockService
from store import SecretsStore


# ── Helpers ───────────────────────────────────────────────────────────────────

def _seeded_store(tmpdir: str, secret_id: str = "provider_api_key"):
    """Return a fresh store and audit log with an active v0 for secret_id."""
    store = SecretsStore(path=Path(tmpdir) / "secrets.json")
    audit = AuditLog(path=Path(tmpdir) / "audit.log")
    seed_initial_secret(secret_id, store, MockProviderAPI(), audit)
    return store, audit


# ── Encryption ────────────────────────────────────────────────────────────────

class TestEncryptDecrypt(unittest.TestCase):

    def test_round_trip(self):
        """Encrypted value must decrypt to the original plaintext."""
        plaintext = "pk_live_test_abc123"
        self.assertEqual(decrypt(encrypt(plaintext)), plaintext)

    def test_unique_nonce_per_call(self):
        """Each encrypt call must produce a distinct ciphertext."""
        plaintext = "same_value"
        self.assertNotEqual(encrypt(plaintext), encrypt(plaintext))

    def test_tampered_ciphertext_raises(self):
        """Modified ciphertext must fail GCM tag verification."""
        ciphertext = encrypt("sensitive_value")
        nonce_b64, ct_b64 = ciphertext.split(".", 1)
        # Flip one character to break the authentication tag
        flipped = ct_b64[:-1] + ("A" if ct_b64[-1] != "A" else "B")
        with self.assertRaises(Exception):   # cryptography.exceptions.InvalidTag
            decrypt(nonce_b64 + "." + flipped)


# ── IAM policy ────────────────────────────────────────────────────────────────

class TestIAMPolicy(unittest.TestCase):

    def setUp(self):
        self.engine = PolicyEngine()

    def test_break_glass_rotate_explicitly_denied(self):
        """system:break-glass must be blocked from rotating secrets."""
        with self.assertRaises(AccessDenied):
            self.engine.evaluate(
                "system:break-glass", "secrets:Rotate", "provider_api_key"
            )

    def test_break_glass_write_explicitly_denied(self):
        """system:break-glass must be blocked from writing new versions."""
        with self.assertRaises(AccessDenied):
            self.engine.evaluate(
                "system:break-glass", "secrets:PutVersion", "provider_api_key"
            )

    def test_service_cross_secret_denied(self):
        """service:checkout must not read secrets it does not own."""
        with self.assertRaises(AccessDenied):
            self.engine.evaluate(
                "service:checkout", "secrets:GetValue", "webhook_secret"
            )

    def test_orchestrator_full_access_allowed(self):
        """system:orchestrator must be permitted for all rotation actions."""
        for secret_id in ["provider_api_key", "webhook_secret", "refund_token"]:
            # Should not raise
            self.assertTrue(
                self.engine.evaluate(
                    "system:orchestrator", "secrets:Rotate", secret_id
                )
            )


# ── Concurrent lock ───────────────────────────────────────────────────────────

class TestRotationLock(unittest.TestCase):

    def test_second_lock_on_same_secret_fails(self):
        """Acquiring the lock twice for the same secret must fail immediately."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SecretsStore(path=Path(tmpdir) / "secrets.json")
            with store.rotation_lock("provider_api_key"):
                with self.assertRaises(RuntimeError) as ctx:
                    with store.rotation_lock("provider_api_key"):
                        pass
            self.assertIn("lock", str(ctx.exception).lower())

    def test_different_secrets_do_not_conflict(self):
        """Locks on distinct secrets must not block each other."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SecretsStore(path=Path(tmpdir) / "secrets.json")
            with store.rotation_lock("provider_api_key"):
                # Must not raise
                with store.rotation_lock("webhook_secret"):
                    pass


# ── Rollback ──────────────────────────────────────────────────────────────────

class TestRollback(unittest.TestCase):

    def _rotate_with_failure(self, tmpdir: str, fail_at: str, secret_id: str = "provider_api_key"):
        store, audit = _seeded_store(tmpdir, secret_id)
        services = [
            MockService(svc, secret_id, store, inject_failure_at=fail_at)
            for svc in SECRET_SERVICE_MAP[secret_id]
        ]
        ok = rotate(
            secret_id=secret_id,
            store=store,
            audit=audit,
            provider=MockProviderAPI(),
            services=services,
            grace_seconds=0,
        )
        return ok, store

    def test_original_version_remains_active_after_rollback(self):
        """After a failed rotation, the pre-rotation active version must still be active."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store, audit = _seeded_store(tmpdir)
            original_vid = store.get_active_version("provider_api_key")["version_id"]

            services = [
                MockService(svc, "provider_api_key", store, inject_failure_at="verify")
                for svc in SECRET_SERVICE_MAP["provider_api_key"]
            ]
            ok = rotate(
                secret_id="provider_api_key",
                store=store,
                audit=audit,
                provider=MockProviderAPI(),
                services=services,
                grace_seconds=0,
            )

            self.assertFalse(ok)
            current = store.get_active_version("provider_api_key")
            self.assertIsNotNone(current)
            self.assertEqual(current["version_id"], original_vid)

    def test_no_pending_version_after_rollback(self):
        """No version must remain in pending state after a failed rotation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, store = self._rotate_with_failure(tmpdir, fail_at="verify")
            self.assertFalse(ok)
            pending = [
                v for v in store.get_versions("provider_api_key").values()
                if v["state"] == "pending"
            ]
            self.assertEqual(pending, [])

    def test_rollback_on_propagate_failure(self):
        """Rollback must also work when failure occurs during propagation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ok, store = self._rotate_with_failure(tmpdir, fail_at="propagate")
            self.assertFalse(ok)
            # Active version must still exist
            self.assertIsNotNone(store.get_active_version("provider_api_key"))


if __name__ == "__main__":
    unittest.main()
