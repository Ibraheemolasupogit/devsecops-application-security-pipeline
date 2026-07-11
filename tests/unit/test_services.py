from datetime import UTC, datetime

import pytest

from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.data.seed import synthetic_datasets
from genomic_research_access_api.domain.enums import AccessLevel, ActorRole
from genomic_research_access_api.exceptions.app import InvalidAccessRequestTransitionError
from genomic_research_access_api.repositories.access_requests import AccessRequestRepository
from genomic_research_access_api.repositories.audit_events import AuditEventRepository
from genomic_research_access_api.repositories.datasets import DatasetRepository
from genomic_research_access_api.schemas.access_requests import AccessRequestCreate
from genomic_research_access_api.security.authentication.principal import AuthenticatedPrincipal
from genomic_research_access_api.services.access_requests import AccessRequestService


def test_service_rejects_invalid_transition() -> None:
    def clock() -> datetime:
        return datetime(2026, 1, 2, 10, 0, tzinfo=UTC)

    ids = iter(["request-1", "event-1", "event-2", "event-3"])
    audit_service = AuditService(AuditEventRepository(), clock, lambda: next(ids))
    service = AccessRequestService(
        AccessRequestRepository(),
        DatasetRepository(synthetic_datasets()),
        audit_service,
        clock,
        lambda: next(ids),
    )
    researcher = AuthenticatedPrincipal(
        subject="researcher-001",
        display_name="Researcher One",
        roles=(ActorRole.RESEARCHER,),
        token_id="token-researcher",
        issuer="issuer",
        audience="audience",
        issued_at=clock(),
        expires_at=clock(),
    )
    approver = AuthenticatedPrincipal(
        subject="approver-001",
        display_name="Approver One",
        roles=(ActorRole.APPROVER,),
        token_id="token-approver",
        issuer="issuer",
        audience="audience",
        issued_at=clock(),
        expires_at=clock(),
    )
    created = service.create(
        AccessRequestCreate(
            dataset_id="syn-rare-disease-001",
            research_purpose="A valid synthetic research purpose.",
            requested_access_level=AccessLevel.AGGREGATE_ANALYSIS,
        ),
        principal=researcher,
        correlation_id="corr-service",
    )
    service.approve(created.request_id, "Approved.", approver, "corr-service")

    with pytest.raises(InvalidAccessRequestTransitionError):
        service.reject(created.request_id, "Too late.", approver, "corr-service")
