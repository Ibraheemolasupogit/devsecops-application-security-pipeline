"""Dataset catalogue service."""

from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.domain.enums import ActorRole, AuditEventType, AuditOutcome
from genomic_research_access_api.domain.models import Dataset
from genomic_research_access_api.exceptions.app import DatasetNotFoundError
from genomic_research_access_api.repositories.datasets import DatasetRepository


class DatasetService:
    def __init__(self, repository: DatasetRepository, audit_service: AuditService) -> None:
        self._repository = repository
        self._audit_service = audit_service

    def list_datasets(self) -> list[Dataset]:
        return self._repository.list()

    def get_dataset(self, dataset_id: str, correlation_id: str) -> Dataset:
        dataset = self._repository.get(dataset_id)
        if dataset is None:
            raise DatasetNotFoundError()
        self._audit_service.record(
            event_type=AuditEventType.DATASET_VIEWED,
            actor_id="local-demo-viewer",
            actor_role=ActorRole.RESEARCHER,
            resource_type="dataset",
            resource_id=dataset_id,
            outcome=AuditOutcome.SUCCESS,
            correlation_id=correlation_id,
            details={"capability": "catalogue_lookup"},
        )
        return dataset
