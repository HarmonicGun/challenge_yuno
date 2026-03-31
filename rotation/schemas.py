"""
Canonical secret structure.
All store reads/writes must conform to these schemas.
"""

from dataclasses import dataclass, field
from typing import Literal

# ── Version ───────────────────────────────────────────────────────────────────

VersionState = Literal["pending", "active", "grace", "revoked"]

@dataclass
class VersionRecord:
    version_id: str
    state: VersionState
    created_at: float          # Unix timestamp
    expires_at: float          # Unix timestamp; enforced at access time, not write time
    created_by: str            # identity that created this version
    # Never contains the secret value — values live only in the store's encrypted layer.


# ── Rotation policy ───────────────────────────────────────────────────────────

@dataclass
class RotationPolicy:
    interval_days: int = 90    # how often automatic rotation is triggered
    grace_seconds: int = 900   # overlap window where old + new are both valid
    auto_rotate: bool = True


# ── Secret record ─────────────────────────────────────────────────────────────

@dataclass
class SecretRecord:
    secret_id: str
    owner_service: str         # single authoritative owner; used for policy lookup
    rotation_policy: RotationPolicy = field(default_factory=RotationPolicy)
    tags: dict = field(default_factory=dict)  # e.g. {"env": "prod", "pci_scope": "true"}

    # Valid transitions: pending → active → grace → revoked
    # Only one version may be in state=active at any time.
    # At most one version may be in state=pending at any time.


# ── Canonical secret registry ─────────────────────────────────────────────────
# Defines every managed secret and its owning service.
# New secrets must be registered here before they can be rotated or accessed.

REGISTRY: dict[str, SecretRecord] = {
    "provider_api_key": SecretRecord(
        secret_id="provider_api_key",
        owner_service="checkout",
        rotation_policy=RotationPolicy(interval_days=90, grace_seconds=900),
        tags={"pci_scope": "true"},
    ),
    "webhook_secret": SecretRecord(
        secret_id="webhook_secret",
        owner_service="webhooks",
        rotation_policy=RotationPolicy(interval_days=30, grace_seconds=300),
    ),
    "refund_token": SecretRecord(
        secret_id="refund_token",
        owner_service="refunds",
        rotation_policy=RotationPolicy(interval_days=60, grace_seconds=600),
    ),
}
