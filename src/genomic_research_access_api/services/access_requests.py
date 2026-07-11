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
from genomic_research_access_api.domain.models import AccessRequest
from genomic_research_access_api.exceptions.app import (
    AccessRequestNotFoundError,
    DatasetNotFoundError,
    InvalidAccessRequestTransitionError,
    ObjectAccessDeniedError,
    SeparationOfDutiesViolationError,
)
from genomic_research_access_api.repositories.access_requests import AccessRequestRepository
from genomic_research_access_api.repositories.datasets import DatasetRepository
from genomic_research_access_api.schemas.access_requests import AccessRequestCreate
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal
from genomic_research_access_api.security.authorisation import Permission, has_permission


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

    def create(
        self,
        payload: AccessRequestCreate,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> AccessRequest:
        if self._dataset_repository.get(payload.dataset_id) is None:
            raise DatasetNotFoundError()
        access_request = AccessRequest(
            request_id=self._id_factory(),
            dataset_id=payload.dataset_id,
            requester_id=principal.subject,
            research_purpose=payload.research_purpose,
            requested_access_level=payload.requested_access_level,
            status=AccessRequestStatus.PENDING,
            submitted_at=self._clock(),
        )
        self._access_request_repository.add(access_request)
        self._audit_service.record(
            event_type=AuditEventType.ACCESS_REQUEST_SUBMITTED,
            actor_id=principal.subject,
            actor_role=principal.primary_role,
            resource_type="access_request",
            resource_id=access_request.request_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={
                "dataset_id": payload.dataset_id,
                "reason_code": "access_request_submitted",
            },
        )
        return access_request

    def list_requests(self, principal: AuthenticatedPrincipal) -> list[AccessRequest]:
        requests = self._access_request_repository.list()
        if has_permission(principal, Permission.ACCESS_REQUEST_LIST_ALL):
            if principal.primary_role is ActorRole.APPROVER:
                return [
                    request for request in requests if request.requester_id != principal.subject
                ]
            return requests
        if has_permission(principal, Permission.ACCESS_REQUEST_LIST_OWN):
            return [request for request in requests if request.requester_id == principal.subject]
        return []

    def get_request(self, request_id: str) -> AccessRequest:
        access_request = self._access_request_repository.get(request_id)
        if access_request is None:
            raise AccessRequestNotFoundError()
        return access_request

    def get_request_for_principal(
        self,
        request_id: str,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> AccessRequest:
        access_request = self.get_request(request_id)
        if self._can_read(access_request, principal):
            self._audit_service.record(
                event_type=AuditEventType.ACCESS_REQUEST_VIEWED,
                actor_id=principal.subject,
                actor_role=principal.primary_role,
                resource_type="access_request",
                resource_id=request_id,
                outcome=AuditOutcome.SUCCESS,
                correlation_id=correlation_id,
                details={"reason_code": "object_access_granted"},
            )
            return access_request
        self._audit_service.record(
            event_type=AuditEventType.AUTHORISATION_DENIED,
            actor_id=principal.subject,
            actor_role=principal.primary_role,
            resource_type="access_request",
            resource_id=request_id,
            outcome=AuditOutcome.FAILURE,
            correlation_id=correlation_id,
            details={"reason_code": "object_access_denied"},
        )
        raise ObjectAccessDeniedError()

    def approve(
        self,
        request_id: str,
        decision_reason: str,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> AccessRequest:
        return self._decide(
            request_id=request_id,
            status=AccessRequestStatus.APPROVED,
            decision_reason=decision_reason,
            principal=principal,
            correlation_id=correlation_id,
        )

    def reject(
        self,
        request_id: str,
        decision_reason: str,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> AccessRequest:
        return self._decide(
            request_id=request_id,
            status=AccessRequestStatus.REJECTED,
            decision_reason=decision_reason,
            principal=principal,
            correlation_id=correlation_id,
        )

    def _decide(
        self,
        *,
        request_id: str,
        status: AccessRequestStatus,
        decision_reason: str,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> AccessRequest:
        access_request = self.get_request(request_id)
        if access_request.requester_id == principal.subject:
            self._audit_service.record(
                event_type=AuditEventType.SELF_APPROVAL_DENIED,
                actor_id=principal.subject,
                actor_role=principal.primary_role,
                resource_type="access_request",
                resource_id=request_id,
                outcome=AuditOutcome.FAILURE,
                correlation_id=correlation_id,
                details={"reason_code": "requester_reviewer_match"},
            )
            raise SeparationOfDutiesViolationError()
        if access_request.status is not AccessRequestStatus.PENDING:
            self._audit_service.record(
                event_type=AuditEventType.INVALID_WORKFLOW_TRANSITION_ATTEMPTED,
                actor_id=principal.subject,
                actor_role=principal.primary_role,
                resource_type="access_request",
                resource_id=request_id,
                outcome=AuditOutcome.FAILURE,
                correlation_id=correlation_id,
                details={
                    "current_status": access_request.status,
                    "reason_code": "invalid_workflow_transition",
                    "requested_status": status,
                },
            )
            raise InvalidAccessRequestTransitionError()
        access_request.status = status
        access_request.reviewed_at = self._clock()
        access_request.reviewed_by = principal.subject
        access_request.decision_reason = decision_reason
        self._access_request_repository.update(access_request)
        self._audit_service.record(
            event_type=(
                AuditEventType.ACCESS_REQUEST_APPROVED
                if status is AccessRequestStatus.APPROVED
                else AuditEventType.ACCESS_REQUEST_REJECTED
            ),
            actor_id=principal.subject,
            actor_role=principal.primary_role,
            resource_type="access_request",
            resource_id=request_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={
                "dataset_id": access_request.dataset_id,
                "reason_code": (
                    "access_request_approved"
                    if status is AccessRequestStatus.APPROVED
                    else "access_request_rejected"
                ),
            },
        )
        return access_request

    def has_approved_access(self, subject: str, dataset_id: str) -> bool:
        return any(
            request.requester_id == subject
            and request.dataset_id == dataset_id
            and request.status is AccessRequestStatus.APPROVED
            for request in self._access_request_repository.list()
        )

    @staticmethod
    def _can_read(access_request: AccessRequest, principal: AuthenticatedPrincipal) -> bool:
        if access_request.requester_id == principal.subject and has_permission(
            principal, Permission.ACCESS_REQUEST_READ_OWN
        ):
            return True
        if not has_permission(principal, Permission.ACCESS_REQUEST_READ_ALL):
            return False
        if principal.primary_role is ActorRole.APPROVER:
            return access_request.requester_id != principal.subject
        return True
