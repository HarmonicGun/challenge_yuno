"""
Encryption for secret values at rest.  (Fixes H1)

Uses AES-256-GCM.  The key is loaded from data/store.key — a stand-in for a KMS
master key.  In production: never write the key to disk; fetch the plaintext data
key from KMS/Vault on startup and keep it only in memory.

Wire format stored in the JSON value field:
    "<base64(12-byte nonce)>.<base64(ciphertext + 16-byte GCM tag)>"
"""

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_PATH = Path(__file__).parent / "data" / "store.key"


def _load_key() -> bytes:
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not KEY_PATH.exists():
        key = AESGCM.generate_key(bit_length=256)
        KEY_PATH.write_bytes(base64.b64encode(key))
        KEY_PATH.chmod(0o600)
        return key
    return base64.b64decode(KEY_PATH.read_bytes())


def encrypt(plaintext: str) -> str:
    key = _load_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce).decode() + "." + base64.b64encode(ct).decode()


def decrypt(blob: str) -> str:
    key = _load_key()
    nonce_b64, ct_b64 = blob.split(".", 1)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    return AESGCM(key).decrypt(nonce, ct, None).decode()
