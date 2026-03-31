"""
IAM / RBAC access control engine.

Policy format is AWS IAM-compatible (Principal / Action / Resource / Effect).
Default posture: DENY. An explicit Allow is required for every operation.
An explicit Deny always wins over any Allow.

Actions
-------
  secrets:GetValue      — read the current secret value (services, developer CLI)
  secrets:ListVersions  — list version metadata, never values
  secrets:PutVersion    — write a new version (orchestrator only)
  secrets:SetState      — transition a version's state (orchestrator only)
  secrets:Rotate        — trigger a rotation job (orchestrator + break-glass)
  secrets:Revoke        — revoke a version at the provider (orchestrator only)
  secrets:Seed          — create the initial v0 for a secret (orchestrator only)

Principals
----------
  service:<name>        — machine identity for a running service
  system:orchestrator   — rotation automation
  user:<email>          — human developer (short-lived token, TTL ≤ 24h)
  system:break-glass    — emergency access (requires 2-party approval upstream)
"""

from dataclasses import dataclass, field
from typing import Literal

# ── Types ──────────────────────────────────────────────────────────────────────

Action = Literal[
    "secrets:GetValue",
    "secrets:ListVersions",
    "secrets:PutVersion",
    "secrets:SetState",
    "secrets:DeleteVersion",            # H3: added for rollback delete path
    "secrets:Rotate",
    "secrets:Revoke",
    "secrets:Seed",
]

Effect = Literal["Allow", "Deny"]


@dataclass
class Statement:
    sid: str
    effect: Effect
    principals: list[str]          # exact match; no wildcards
    actions: list[Action]          # exact match; no wildcards
    resources: list[str]           # "secret:<id>" or "secret:*" is FORBIDDEN


@dataclass
class Policy:
    version: str = "2012-10-17"
    statements: list[Statement] = field(default_factory=list)


# ── Policy definitions ─────────────────────────────────────────────────────────
# One Allow statement per service-secret pair.
# No principal may access a secret not explicitly listed here.

POLICY = Policy(statements=[

    # ── Service: checkout ──────────────────────────────────────────────────────
    Statement(
        sid="CheckoutReadProviderKey",
        effect="Allow",
        principals=["service:checkout"],
        actions=["secrets:GetValue", "secrets:ListVersions"],
        resources=["secret:provider_api_key"],
    ),

    # ── Service: webhooks ──────────────────────────────────────────────────────
    Statement(
        sid="WebhooksReadWebhookSecret",
        effect="Allow",
        principals=["service:webhooks"],
        actions=["secrets:GetValue", "secrets:ListVersions"],
        resources=["secret:webhook_secret"],
    ),

    # ── Service: refunds ───────────────────────────────────────────────────────
    Statement(
        sid="RefundsReadRefundToken",
        effect="Allow",
        principals=["service:refunds"],
        actions=["secrets:GetValue", "secrets:ListVersions"],
        resources=["secret:refund_token"],
    ),

    # ── Orchestrator ───────────────────────────────────────────────────────────
    Statement(
        sid="OrchestratorFullRotationAccess",
        effect="Allow",
        principals=["system:orchestrator"],
        actions=[
            "secrets:GetValue",
            "secrets:ListVersions",
            "secrets:PutVersion",
            "secrets:SetState",
            "secrets:DeleteVersion",
            "secrets:Rotate",
            "secrets:Revoke",
            "secrets:Seed",
        ],
        resources=[
            "secret:provider_api_key",
            "secret:webhook_secret",
            "secret:refund_token",
        ],
    ),

    # ── Developer CLI ──────────────────────────────────────────────────────────
    # Read-only. All access must use short-lived tokens (enforced at token issuance,
    # not here). Values returned must be masked in UI output.
    Statement(
        sid="DeveloperReadAll",
        effect="Allow",
        principals=["user:developer"],
        actions=["secrets:GetValue", "secrets:ListVersions"],
        resources=[
            "secret:provider_api_key",
            "secret:webhook_secret",
            "secret:refund_token",
        ],
    ),

    # ── Break glass ────────────────────────────────────────────────────────────
    # Emergency read-only access. Rotation is NOT permitted via break-glass path
    # to prevent accidental state changes under incident pressure.
    Statement(
        sid="BreakGlassEmergencyRead",
        effect="Allow",
        principals=["system:break-glass"],
        actions=["secrets:GetValue", "secrets:ListVersions"],
        resources=[
            "secret:provider_api_key",
            "secret:webhook_secret",
            "secret:refund_token",
        ],
    ),

    # ── Explicit deny: break-glass cannot rotate ───────────────────────────────
    Statement(
        sid="DenyBreakGlassRotate",
        effect="Deny",
        principals=["system:break-glass"],
        actions=["secrets:Rotate", "secrets:Revoke", "secrets:PutVersion", "secrets:SetState"],
        resources=[
            "secret:provider_api_key",
            "secret:webhook_secret",
            "secret:refund_token",
        ],
    ),
])


# ── Policy engine ──────────────────────────────────────────────────────────────

class AccessDenied(Exception):
    """Raised when a request is denied. Message includes principal, action, resource."""


class PolicyEngine:
    def __init__(self, policy: Policy = POLICY):
        self._policy = policy

    def evaluate(self, principal: str, action: Action, secret_id: str) -> bool:
        """
        Returns True if the request is allowed.
        Raises AccessDenied if denied (default posture).

        Evaluation order (mirrors AWS IAM):
          1. Explicit Deny — immediate reject.
          2. Explicit Allow — permit.
          3. No match — implicit deny.
        """
        resource = f"secret:{secret_id}"
        allow_matched = False

        for stmt in self._policy.statements:
            if principal not in stmt.principals:
                continue
            if action not in stmt.actions:
                continue
            if resource not in stmt.resources:
                continue

            if stmt.effect == "Deny":
                raise AccessDenied(
                    f"DENIED  principal={principal}  action={action}  resource={resource}"
                    f"  (sid={stmt.sid})"
                )
            if stmt.effect == "Allow":
                allow_matched = True

        if not allow_matched:
            raise AccessDenied(
                f"DENIED  principal={principal}  action={action}  resource={resource}"
                f"  (no matching allow statement)"
            )
        return True
