"""FastAPI authentication and authorisation dependencies."""

from collections.abc import Callable
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.config import get_settings
from genomic_research_access_api.domain.enums import ActorRole, AuditEventType, AuditOutcome
from genomic_research_access_api.exceptions.app import (
    AuthenticationRequiredError,
    InsufficientPermissionError,
    InvalidAccessTokenError,
)
from genomic_research_access_api.security.authentication.jwt_validator import JwtValidator
from genomic_research_access_api.security.authentication.principal import (
    AuthenticatedPrincipal,
)
from genomic_research_access_api.security.authorisation import Permission, has_permission

bearer_scheme = HTTPBearer(auto_error=False)


def _audit_service(request: Request) -> AuditService:
    return cast(AuditService, request.app.state.audit_service)


def _correlation_id(request: Request) -> str:
    return str(request.state.correlation_id)


def _record_security_event(
    request: Request,
    *,
    event_type: AuditEventType,
    actor_id: str,
    actor_role: ActorRole,
    outcome: AuditOutcome,
    reason_code: str,
    resource_type: str = "authentication",
    resource_id: str = "access_token",
) -> None:
    _audit_service(request).record(
        event_type=event_type,
        actor_id=actor_id,
        actor_role=actor_role,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        correlation_id=_correlation_id(request),
        details={"reason_code": reason_code},
    )


def get_jwt_validator() -> JwtValidator:
    settings = get_settings()
    return JwtValidator(
        public_key=settings.load_jwt_public_key(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        algorithm=settings.jwt_algorithm,
        leeway_seconds=settings.jwt_clock_skew_seconds,
        maximum_lifetime_seconds=settings.jwt_maximum_lifetime_seconds,
    )


def get_current_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    validator: Annotated[JwtValidator, Depends(get_jwt_validator)],
) -> AuthenticatedPrincipal:
    if credentials is None:
        _record_security_event(
            request,
            event_type=AuditEventType.AUTHENTICATION_FAILED,
            actor_id="anonymous",
            actor_role=ActorRole.RESEARCHER,
            outcome=AuditOutcome.FAILURE,
            reason_code="missing_bearer_token",
        )
        raise AuthenticationRequiredError()
    try:
        principal = validator.validate(credentials.credentials)
    except InvalidAccessTokenError:
        _record_security_event(
            request,
            event_type=AuditEventType.AUTHENTICATION_FAILED,
            actor_id="anonymous",
            actor_role=ActorRole.RESEARCHER,
            outcome=AuditOutcome.FAILURE,
            reason_code="invalid_bearer_token",
        )
        raise
    _record_security_event(
        request,
        event_type=AuditEventType.AUTHENTICATION_SUCCEEDED,
        actor_id=principal.subject,
        actor_role=principal.primary_role,
        outcome=AuditOutcome.SUCCESS,
        reason_code="token_validated",
    )
    return principal


def require_any_permission(
    *permissions: Permission,
) -> Callable[[Request, AuthenticatedPrincipal], AuthenticatedPrincipal]:
    def dependency(
        request: Request,
        principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    ) -> AuthenticatedPrincipal:
        if not any(has_permission(principal, permission) for permission in permissions):
            _record_security_event(
                request,
                event_type=AuditEventType.AUTHORISATION_DENIED,
                actor_id=principal.subject,
                actor_role=principal.primary_role,
                outcome=AuditOutcome.FAILURE,
                reason_code="missing_permission:" + ",".join(permissions),
                resource_type="permission",
                resource_id=",".join(permissions),
            )
            raise InsufficientPermissionError()
        return principal

    return dependency


def require_permission(
    permission: Permission,
) -> Callable[[Request, AuthenticatedPrincipal], AuthenticatedPrincipal]:
    return require_any_permission(permission)
