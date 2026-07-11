"""Health endpoint."""

from fastapi import APIRouter

from genomic_research_access_api.config import get_settings
from genomic_research_access_api.schemas.health import HealthResponse
from genomic_research_access_api.version import __version__

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(status="healthy", service=settings.service_name, version=__version__)
