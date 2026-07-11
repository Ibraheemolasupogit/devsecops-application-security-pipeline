"""Dataset catalogue service."""

from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.domain.enums import (
    AccessRequestStatus,
    AuditEventType,
    AuditOutcome,
    SensitivityClassification,
)
from genomic_research_access_api.domain.models import Dataset
from genomic_research_access_api.exceptions.app import DatasetNotFoundError, ObjectAccessDeniedError
from genomic_research_access_api.repositories.access_requests import AccessRequestRepository
from genomic_research_access_api.repositories.datasets import DatasetRepository
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal
from genomic_research_access_api.security.authorisation import Permission, has_permission


class DatasetService:
    def __init__(
        self,
        repository: DatasetRepository,
        access_request_repository: AccessRequestRepository,
        audit_service: AuditService,
    ) -> None:
        self._repository = repository
        self._access_request_repository = access_request_repository
        self._audit_service = audit_service

    def list_datasets(self) -> list[Dataset]:
        return self._repository.list()

    def get_dataset(
        self,
        dataset_id: str,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> Dataset:
        dataset = self._repository.get(dataset_id)
        if dataset is None:
            raise DatasetNotFoundError()
        if self._is_restricted(dataset) and not self._can_read_restricted(dataset, principal):
            self._audit_service.record(
                event_type=AuditEventType.AUTHORISATION_DENIED,
                actor_id=principal.subject,
                actor_role=principal.primary_role,
                resource_type="dataset",
                resource_id=dataset_id,
                outcome=AuditOutcome.FAILURE,
                correlation_id=correlation_id,
                details={"reason_code": "restricted_dataset_without_entitlement"},
            )
            raise ObjectAccessDeniedError()
        self._audit_service.record(
            event_type=AuditEventType.DATASET_VIEWED,
            actor_id=principal.subject,
            actor_role=principal.primary_role,
            resource_type="dataset",
            resource_id=dataset_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={
                "capability": "catalogue_lookup",
                "reason_code": "dataset_access_granted",
            },
        )
        return dataset

    @staticmethod
    def _is_restricted(dataset: Dataset) -> bool:
        return dataset.sensitivity_classification is SensitivityClassification.SYNTHETIC_RESTRICTED

    def _can_read_restricted(self, dataset: Dataset, principal: AuthenticatedPrincipal) -> bool:
        if has_permission(principal, Permission.DATASET_READ_RESTRICTED):
            return True
        return any(
            request.dataset_id == dataset.dataset_id
            and request.requester_id == principal.subject
            and request.status is AccessRequestStatus.APPROVED
            for request in self._access_request_repository.list()
        )
