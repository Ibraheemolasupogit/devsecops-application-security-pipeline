"""FastAPI dependency helpers."""

from typing import cast

from fastapi import Request

from genomic_research_access_api.config import get_settings
from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.domain.models import ActorContext
from genomic_research_access_api.services.access_requests import AccessRequestService
from genomic_research_access_api.services.datasets import DatasetService


def get_correlation_id(request: Request) -> str:
    return str(request.state.correlation_id)


def get_dataset_service(request: Request) -> DatasetService:
    return cast(DatasetService, request.app.state.dataset_service)


def get_access_request_service(request: Request) -> AccessRequestService:
    return cast(AccessRequestService, request.app.state.access_request_service)


def get_simulated_reviewer() -> ActorContext:
    settings = get_settings()
    return ActorContext(
        actor_id=settings.simulated_reviewer_id,
        actor_role=ActorRole(settings.simulated_reviewer_role),
    )
