"""Authenticated principal model."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from genomic_research_access_api.domain.enums import ActorRole


class AuthenticatedPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    display_name: str
    roles: tuple[ActorRole, ...]
    token_id: str
    issuer: str
    audience: str
    issued_at: datetime
    expires_at: datetime

    @property
    def primary_role(self) -> ActorRole:
        return self.roles[0]
