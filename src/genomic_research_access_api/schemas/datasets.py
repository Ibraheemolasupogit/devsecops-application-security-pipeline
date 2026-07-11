"""Dataset response schemas."""

from datetime import datetime

from genomic_research_access_api.domain.enums import (
    AccessLevel,
    DatasetStatus,
    SensitivityClassification,
)
from genomic_research_access_api.schemas.common import ApiModel


class DatasetResponse(ApiModel):
    dataset_id: str
    name: str
    description: str
    research_domain: str
    sensitivity_classification: SensitivityClassification
    access_level: AccessLevel
    status: DatasetStatus
    created_at: datetime
    updated_at: datetime
