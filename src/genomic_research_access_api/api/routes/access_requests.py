"""Access request workflow routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, status

from genomic_research_access_api.api.dependencies import (
    get_access_request_service,
    get_correlation_id,
    get_simulated_reviewer,
)
from genomic_research_access_api.domain.models import ActorContext
from genomic_research_access_api.schemas.access_requests import (
    AccessRequestCreate,
    AccessRequestResponse,
    DecisionRequest,
)
from genomic_research_access_api.services.access_requests import AccessRequestService

router = APIRouter(prefix="/api/v1/access-requests", tags=["access requests"])


@router.post("", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
def create_access_request(
    payload: AccessRequestCreate,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> AccessRequestResponse:
    access_request = service.create(payload=payload, correlation_id=correlation_id)
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.get("", response_model=list[AccessRequestResponse])
def list_access_requests(
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
) -> list[AccessRequestResponse]:
    return [
        AccessRequestResponse.model_validate(access_request, from_attributes=True)
        for access_request in service.list_requests()
    ]


@router.get("/{request_id}", response_model=AccessRequestResponse)
def get_access_request(
    request_id: str,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
) -> AccessRequestResponse:
    access_request = service.get_request(request_id)
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.post("/{request_id}/approve", response_model=AccessRequestResponse)
def approve_access_request(
    request_id: str,
    payload: DecisionRequest,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    actor: Annotated[ActorContext, Depends(get_simulated_reviewer)],
) -> AccessRequestResponse:
    access_request = service.approve(
        request_id=request_id,
        decision_reason=payload.decision_reason,
        actor=actor,
        correlation_id=correlation_id,
    )
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)


@router.post("/{request_id}/reject", response_model=AccessRequestResponse)
def reject_access_request(
    request_id: str,
    payload: DecisionRequest,
    service: Annotated[AccessRequestService, Depends(get_access_request_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
    actor: Annotated[ActorContext, Depends(get_simulated_reviewer)],
) -> AccessRequestResponse:
    access_request = service.reject(
        request_id=request_id,
        decision_reason=payload.decision_reason,
        actor=actor,
        correlation_id=correlation_id,
    )
    return AccessRequestResponse.model_validate(access_request, from_attributes=True)
