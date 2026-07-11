"""Health response schema."""

from genomic_research_access_api.schemas.common import ApiModel


class HealthResponse(ApiModel):
    status: str
    service: str
    version: str
