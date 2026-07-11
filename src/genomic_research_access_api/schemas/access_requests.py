"""Access request API schemas."""

from datetime import datetime
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator

from genomic_research_access_api.domain.enums import AccessLevel, AccessRequestStatus
from genomic_research_access_api.schemas.common import ApiModel

BoundedText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]
BoundedIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:-]+$"
    ),
]


class AccessRequestCreate(ApiModel):
    dataset_id: BoundedIdentifier
    requester_id: BoundedIdentifier
    research_purpose: BoundedText
    requested_access_level: AccessLevel

    @field_validator("research_purpose")
    @classmethod
    def purpose_must_have_words(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Research purpose must not be empty.")
        return value


class AccessRequestResponse(ApiModel):
    request_id: str
    dataset_id: str
    requester_id: str
    research_purpose: str
    requested_access_level: AccessLevel
    status: AccessRequestStatus
    submitted_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None
    decision_reason: str | None


class DecisionRequest(ApiModel):
    decision_reason: BoundedText = Field(
        description="Reason recorded by the simulated local reviewer context."
    )
