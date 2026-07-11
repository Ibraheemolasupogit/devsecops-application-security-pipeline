"""JWT validation for local RS256 portfolio authentication."""

from datetime import UTC, datetime
from typing import Any

import jwt

from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.exceptions.app import (
    AccessTokenExpiredError,
    InvalidAccessTokenError,
    InvalidTokenAudienceError,
    InvalidTokenIssuerError,
)
from genomic_research_access_api.security.authentication.principal import (
    AuthenticatedPrincipal,
)


class JwtValidator:
    def __init__(
        self,
        *,
        public_key: str,
        issuer: str,
        audience: str,
        algorithm: str,
        leeway_seconds: int,
        maximum_lifetime_seconds: int,
    ) -> None:
        self._public_key = public_key
        self._issuer = issuer
        self._audience = audience
        self._algorithm = algorithm
        self._leeway_seconds = leeway_seconds
        self._maximum_lifetime_seconds = maximum_lifetime_seconds

    def validate(self, token: str) -> AuthenticatedPrincipal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidAccessTokenError() from exc
        if header.get("alg") != self._algorithm:
            raise InvalidAccessTokenError()
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                leeway=self._leeway_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AccessTokenExpiredError() from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidTokenIssuerError() from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidTokenAudienceError() from exc
        except jwt.PyJWTError as exc:
            raise InvalidAccessTokenError() from exc
        return self._principal_from_claims(claims)

    def _principal_from_claims(self, claims: dict[str, Any]) -> AuthenticatedPrincipal:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 120:
            raise InvalidAccessTokenError()
        roles_claim = claims.get("roles")
        if not isinstance(roles_claim, list) or not roles_claim:
            raise InvalidAccessTokenError()
        try:
            roles = tuple(ActorRole(role) for role in roles_claim)
        except ValueError as exc:
            raise InvalidAccessTokenError() from exc
        issued_at = self._numeric_date(claims.get("iat"))
        expires_at = self._numeric_date(claims.get("exp"))
        if (expires_at - issued_at).total_seconds() > self._maximum_lifetime_seconds:
            raise InvalidAccessTokenError()
        token_id = claims.get("jti")
        if not isinstance(token_id, str) or not token_id:
            raise InvalidAccessTokenError()
        display_name = claims.get("name")
        if not isinstance(display_name, str) or not display_name:
            display_name = subject
        return AuthenticatedPrincipal(
            subject=subject,
            display_name=display_name[:120],
            roles=roles,
            token_id=token_id,
            issuer=self._issuer,
            audience=self._audience,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _numeric_date(value: object) -> datetime:
        if not isinstance(value, int):
            raise InvalidAccessTokenError()
        return datetime.fromtimestamp(value, tz=UTC)
