"""Access request workflow service."""

from collections.abc import Callable

from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.domain.clock import Clock
from genomic_research_access_api.domain.enums import (
    AccessRequestStatus,
    ActorRole,
    AuditEventType,
    AuditOutcome,
)
from genomic_research_access_api.domain.models import AccessRequest, ActorContext
from genomic_research_access_api.exceptions.app import (
    AccessRequestNotFoundError,
    DatasetNotFoundError,
    InvalidAccessRequestTransitionError,
)
from genomic_research_access_api.repositories.access_requests import AccessRequestRepository
from genomic_research_access_api.repositories.datasets import DatasetRepository
from genomic_research_access_api.schemas.access_requests import AccessRequestCreate


class AccessRequestService:
    def __init__(
        self,
        access_request_repository: AccessRequestRepository,
        dataset_repository: DatasetRepository,
        audit_service: AuditService,
        clock: Clock,
        id_factory: Callable[[], str],
    ) -> None:
        self._access_request_repository = access_request_repository
        self._dataset_repository = dataset_repository
        self._audit_service = audit_service
        self._clock = clock
        self._id_factory = id_factory

    def create(self, payload: AccessRequestCreate, correlation_id: str) -> AccessRequest:
        if self._dataset_repository.get(payload.dataset_id) is None:
            raise DatasetNotFoundError()
        access_request = AccessRequest(
            request_id=self._id_factory(),
            dataset_id=payload.dataset_id,
            requester_id=payload.requester_id,
            research_purpose=payload.research_purpose,
            requested_access_level=payload.requested_access_level,
            status=AccessRequestStatus.PENDING,
            submitted_at=self._clock(),
        )
        self._access_request_repository.add(access_request)
        self._audit_service.record(
            event_type=AuditEventType.ACCESS_REQUEST_SUBMITTED,
            actor_id=payload.requester_id,
            actor_role=ActorRole.RESEARCHER,
            resource_type="access_request",
            resource_id=access_request.request_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={"dataset_id": payload.dataset_id},
        )
        return access_request

    def list_requests(self) -> list[AccessRequest]:
        return self._access_request_repository.list()

    def get_request(self, request_id: str) -> AccessRequest:
        access_request = self._access_request_repository.get(request_id)
        if access_request is None:
            raise AccessRequestNotFoundError()
        return access_request

    def approve(
        self,
        request_id: str,
        decision_reason: str,
        actor: ActorContext,
        correlation_id: str,
    ) -> AccessRequest:
        return self._decide(
            request_id=request_id,
            status=AccessRequestStatus.APPROVED,
            decision_reason=decision_reason,
            actor=actor,
            correlation_id=correlation_id,
        )

    def reject(
        self,
        request_id: str,
        decision_reason: str,
        actor: ActorContext,
        correlation_id: str,
    ) -> AccessRequest:
        return self._decide(
            request_id=request_id,
            status=AccessRequestStatus.REJECTED,
            decision_reason=decision_reason,
            actor=actor,
            correlation_id=correlation_id,
        )

    def _decide(
        self,
        *,
        request_id: str,
        status: AccessRequestStatus,
        decision_reason: str,
        actor: ActorContext,
        correlation_id: str,
    ) -> AccessRequest:
        access_request = self.get_request(request_id)
        if access_request.status is not AccessRequestStatus.PENDING:
            self._audit_service.record(
                event_type=AuditEventType.INVALID_WORKFLOW_TRANSITION_ATTEMPTED,
                actor_id=actor.actor_id,
                actor_role=actor.actor_role,
                resource_type="access_request",
                resource_id=request_id,
                outcome=AuditOutcome.FAILURE,
                correlation_id=correlation_id,
                details={"current_status": access_request.status, "requested_status": status},
            )
            raise InvalidAccessRequestTransitionError()
        access_request.status = status
        access_request.reviewed_at = self._clock()
        access_request.reviewed_by = actor.actor_id
        access_request.decision_reason = decision_reason
        self._access_request_repository.update(access_request)
        self._audit_service.record(
            event_type=(
                AuditEventType.ACCESS_REQUEST_APPROVED
                if status is AccessRequestStatus.APPROVED
                else AuditEventType.ACCESS_REQUEST_REJECTED
            ),
            actor_id=actor.actor_id,
            actor_role=actor.actor_role,
            resource_type="access_request",
            resource_id=request_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={"dataset_id": access_request.dataset_id},
        )
        return access_request
