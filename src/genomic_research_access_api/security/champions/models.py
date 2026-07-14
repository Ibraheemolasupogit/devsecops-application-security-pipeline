"""Typed records for Security Champions configuration."""

from pydantic import BaseModel, ConfigDict, Field


class ChampionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    champion_id: str
    squad_id: str
    role: str
    status: str
    onboarding_status: str
    start_date: str
    review_date: str
    workshops_completed: list[str] = Field(default_factory=list)
    backup_champion: str | None = None
    synthetic_record: bool = True


class SquadModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    squad_id: str
    name: str
    engineering_area: str
    champion_required: bool
    threat_ids: list[str] = Field(default_factory=list)
    security_requirement_ids: list[str] = Field(default_factory=list)


class MetricDefinitionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    metric_id: str
    name: str
    description: str
    calculation: str
    evidence_sources: list[str]
    anti_gaming_guardrail: str
