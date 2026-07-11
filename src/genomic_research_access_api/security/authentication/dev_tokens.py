"""Development-only JWT issuance for local testing.

This module uses synthetic keys and predefined identities. It is not a production
identity provider.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

from genomic_research_access_api.config import get_settings
from genomic_research_access_api.domain.enums import ActorRole

DEV_PRIVATE_KEY_PATH = Path("tests/fixtures/keys/dev_private_key.pem")

DEMO_IDENTITIES: dict[str, tuple[str, tuple[ActorRole, ...]]] = {
    "researcher-001": ("Researcher One", (ActorRole.RESEARCHER,)),
    "researcher-002": ("Researcher Two", (ActorRole.RESEARCHER,)),
    "approver-001": ("Approver One", (ActorRole.APPROVER,)),
    "custodian-001": ("Data Custodian One", (ActorRole.DATA_CUSTODIAN,)),
    "auditor-001": ("Security Auditor One", (ActorRole.SECURITY_AUDITOR,)),
    "admin-001": ("Application Admin One", (ActorRole.APPLICATION_ADMIN,)),
    "multi-role-001": ("Multi Role One", (ActorRole.RESEARCHER, ActorRole.APPROVER)),
}


def issue_dev_token(
    *,
    subject: str,
    expires_in_seconds: int = 300,
    issued_at: datetime | None = None,
    not_before: datetime | None = None,
    token_id: str | None = None,
    roles: tuple[ActorRole, ...] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    private_key_path: Path = DEV_PRIVATE_KEY_PATH,
) -> str:
    if subject not in DEMO_IDENTITIES:
        raise ValueError("subject is not a predefined local development identity")
    display_name, default_roles = DEMO_IDENTITIES[subject]
    now = issued_at or datetime.now(UTC)
    settings = get_settings()
    claims: dict[str, object] = {
        "iss": issuer or settings.jwt_issuer,
        "aud": audience or settings.jwt_audience,
        "sub": subject,
        "name": display_name,
        "roles": [role.value for role in (roles or default_roles)],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in_seconds)).timestamp()),
        "jti": token_id or f"dev-token-{subject}",
    }
    if not_before is not None:
        claims["nbf"] = int(not_before.timestamp())
    return jwt.encode(
        claims,
        private_key_path.read_text(encoding="utf-8"),
        algorithm=settings.jwt_algorithm,
    )
