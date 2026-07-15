"""Access request workflow routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Path, status

from genomic_research_access_api.api.dependencies import (
    get_access_request_service,
    get_correlation_id,
)
from genomic_research_access_api.api.responses import (
    AUTHENTICATION_ERROR_RESPONSES,
    NOT_FOUND_RESPONSE,
)
from genomic_research_access_api.schemas.access_requests import (
    AccessRequestCreate,
    AccessRequestResponse,
    ApprovalDecisionRequest,
    RejectionDecisionRequest,
)
from genomic_research_access_api.security.authentication.dependencies import (
    require_any_permission,
    require_permission,
)
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal
from genomic_research_access_api.security.authorisation import Permission
from genomic_research_access_api.services.access_requests import AccessRequestService

router = APIRouter(prefix="/api/v1/access-requests", tags=["access requests"])


@router.post("", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
def create_access_request(
    payload: AccessRequestCreate,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_permission(Permission.ACCESS_REQUEST_CREATE))
    ],
) -> AccessRequestResponse:
    access_request = service.create(
        payload=payload,
        principal=principal,
        correlation_id=correlation_id,
    )
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.get(
    "",
    response_model=list[AccessRequestResponse],
    responses=AUTHENTICATION_ERROR_RESPONSES,
)
def list_access_requests(
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ACCESS_REQUEST_LIST_OWN,
                Permission.ACCESS_REQUEST_LIST_ALL,
            )
        ),
    ],
) -> list[AccessRequestResponse]:
    return [
        AccessRequestResponse.model_validate(access_request, from_attributes=True)
        for access_request in service.list_requests(principal)
    ]


@router.get(
    "/{request_id}",
    response_model=AccessRequestResponse,
    responses=AUTHENTICATION_ERROR_RESPONSES | NOT_FOUND_RESPONSE,
)
def get_access_request(
    request_id: Annotated[
        str,
        Path(
            min_length=1,
            max_length=120,
            pattern=r"^[A-Za-z0-9_.:-]+$",
            examples=["schemathesis-access-request-001"],
        ),
    ],
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(
            require_any_permission(
                Permission.ACCESS_REQUEST_READ_OWN,
                Permission.ACCESS_REQUEST_READ_ALL,
            )
        ),
    ],
) -> AccessRequestResponse:
    access_request = service.get_request_for_principal(request_id, principal, correlation_id)
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.post("/{request_id}/approve", response_model=AccessRequestResponse)
def approve_access_request(
    request_id: str,
    payload: ApprovalDecisionRequest,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_permission(Permission.ACCESS_REQUEST_APPROVE))
    ],
) -> AccessRequestResponse:
    access_request = service.approve(
        request_id=request_id,
        decision_reason=payload.decision_reason,
        principal=principal,
        correlation_id=correlation_id,
    )
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.post("/{request_id}/reject", response_model=AccessRequestResponse)
def reject_access_request(
    request_id: str,
    payload: RejectionDecisionRequest,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_permission(Permission.ACCESS_REQUEST_REJECT))
    ],
) -> AccessRequestResponse:
    access_request = service.reject(
        request_id=request_id,
        decision_reason=payload.decision_reason,
        principal=principal,
        correlation_id=correlation_id,
    )
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)
