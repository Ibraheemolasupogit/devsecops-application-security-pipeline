"""Threat-model validation rules."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from genomic_research_access_api.security.threat_model.io import SOURCE_FILES, load_json_yaml
from genomic_research_access_api.security.threat_model.models import (
    Actor,
    Asset,
    DataFlow,
    EntryPoint,
    ResidualRisk,
    SecurityRequirement,
    Threat,
    TraceabilityLink,
    TrustBoundary,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


class ThreatModelValidationError(Exception):
    """Raised when threat-model validation fails."""


@dataclass(frozen=True)
class ThreatModel:
    assets: list[Asset]
    actors: list[Actor]
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    data_flows: list[DataFlow]
    threats: list[Threat]
    requirements: list[SecurityRequirement]
    traceability: list[TraceabilityLink]
    residual_risks: list[ResidualRisk]


def _parse_records(path: Path, model: type[ModelT]) -> list[ModelT]:
    payload = load_json_yaml(path)
    if not isinstance(payload, list):
        raise ThreatModelValidationError(f"{path} must contain a list")
    try:
        return [model.model_validate(item) for item in payload]
    except ValidationError as exc:
        raise ThreatModelValidationError(f"{path} failed schema validation: {exc}") from exc


def _ensure_unique(records: Sequence[BaseModel], id_field: str, errors: list[str]) -> None:
    values = [str(getattr(record, id_field)) for record in records]
    duplicates = sorted(value for value, count in Counter(values).items() if count > 1)
    if duplicates:
        errors.append(f"Duplicate {id_field} values: {', '.join(duplicates)}")
    if values != sorted(values):
        errors.append(f"{id_field} values must be in stable sorted order")


def _ensure_references(
    *,
    source_id: str,
    referenced_ids: list[str],
    valid_ids: set[str],
    label: str,
    errors: list[str],
) -> None:
    missing = sorted(set(referenced_ids) - valid_ids)
    if missing:
        errors.append(f"{source_id} references unknown {label}: {', '.join(missing)}")


def _ensure_iso_date(value: str, source_id: str, field_name: str, errors: list[str]) -> None:
    try:
        date.fromisoformat(value)
    except ValueError:
        errors.append(f"{source_id}.{field_name} must be an ISO date")


def load_threat_model() -> ThreatModel:
    return ThreatModel(
        assets=_parse_records(SOURCE_FILES["assets"], Asset),
        actors=_parse_records(SOURCE_FILES["actors"], Actor),
        entry_points=_parse_records(SOURCE_FILES["entry_points"], EntryPoint),
        trust_boundaries=_parse_records(SOURCE_FILES["trust_boundaries"], TrustBoundary),
        data_flows=_parse_records(SOURCE_FILES["data_flows"], DataFlow),
        threats=_parse_records(SOURCE_FILES["threats"], Threat),
        requirements=_parse_records(SOURCE_FILES["requirements"], SecurityRequirement),
        traceability=_parse_records(SOURCE_FILES["traceability"], TraceabilityLink),
        residual_risks=_parse_records(SOURCE_FILES["residual_risks"], ResidualRisk),
    )


def validate_threat_model() -> ThreatModel:
    model = load_threat_model()
    errors: list[str] = []

    _ensure_unique(model.assets, "asset_id", errors)
    _ensure_unique(model.actors, "actor_id", errors)
    _ensure_unique(model.entry_points, "entry_point_id", errors)
    _ensure_unique(model.trust_boundaries, "boundary_id", errors)
    _ensure_unique(model.data_flows, "data_flow_id", errors)
    _ensure_unique(model.threats, "threat_id", errors)
    _ensure_unique(model.requirements, "requirement_id", errors)
    _ensure_unique(model.traceability, "traceability_id", errors)
    _ensure_unique(model.residual_risks, "risk_id", errors)

    asset_ids = {asset.asset_id for asset in model.assets}
    actor_ids = {actor.actor_id for actor in model.actors}
    entry_point_ids = {entry.entry_point_id for entry in model.entry_points}
    boundary_ids = {boundary.boundary_id for boundary in model.trust_boundaries}
    data_flow_ids = {flow.data_flow_id for flow in model.data_flows}
    threat_ids = {threat.threat_id for threat in model.threats}
    requirement_ids = {requirement.requirement_id for requirement in model.requirements}
    residual_risk_ids = {risk.risk_id for risk in model.residual_risks}

    for entry in model.entry_points:
        _ensure_references(
            source_id=entry.entry_point_id,
            referenced_ids=entry.trust_boundary_ids,
            valid_ids=boundary_ids,
            label="trust boundaries",
            errors=errors,
        )

    for flow in model.data_flows:
        _ensure_references(
            source_id=flow.data_flow_id,
            referenced_ids=flow.trust_boundary_ids,
            valid_ids=boundary_ids,
            label="trust boundaries",
            errors=errors,
        )

    requirement_threat_links: dict[str, set[str]] = {threat_id: set() for threat_id in threat_ids}
    for requirement in model.requirements:
        if not requirement.source_threat_ids and not requirement.policy_source:
            errors.append(f"{requirement.requirement_id} has no source threat or policy source")
        _ensure_references(
            source_id=requirement.requirement_id,
            referenced_ids=requirement.source_threat_ids,
            valid_ids=threat_ids,
            label="threats",
            errors=errors,
        )
        for threat_id in requirement.source_threat_ids:
            requirement_threat_links.setdefault(threat_id, set()).add(requirement.requirement_id)
        if (
            requirement.implementation_status == "implemented"
            and not requirement.implementation_reference
        ):
            errors.append(f"{requirement.requirement_id} implemented control lacks reference")
        if (
            requirement.implementation_status in {"planned", "not_started"}
            and not requirement.planned_milestone
        ):
            errors.append(f"{requirement.requirement_id} planned control lacks future milestone")

    for threat in model.threats:
        _ensure_references(
            source_id=threat.threat_id,
            referenced_ids=threat.asset_ids,
            valid_ids=asset_ids,
            label="assets",
            errors=errors,
        )
        _ensure_references(
            source_id=threat.threat_id,
            referenced_ids=threat.actor_ids,
            valid_ids=actor_ids,
            label="actors",
            errors=errors,
        )
        _ensure_references(
            source_id=threat.threat_id,
            referenced_ids=threat.entry_point_ids,
            valid_ids=entry_point_ids,
            label="entry points",
            errors=errors,
        )
        _ensure_references(
            source_id=threat.threat_id,
            referenced_ids=threat.data_flow_ids,
            valid_ids=data_flow_ids,
            label="data flows",
            errors=errors,
        )
        _ensure_references(
            source_id=threat.threat_id,
            referenced_ids=threat.trust_boundary_ids,
            valid_ids=boundary_ids,
            label="trust boundaries",
            errors=errors,
        )
        _ensure_iso_date(threat.review_date, threat.threat_id, "review_date", errors)
        if not requirement_threat_links.get(threat.threat_id):
            errors.append(f"{threat.threat_id} has no mapped security requirement")

    for risk in model.residual_risks:
        _ensure_references(
            source_id=risk.risk_id,
            referenced_ids=risk.related_threat_ids,
            valid_ids=threat_ids,
            label="threats",
            errors=errors,
        )
        _ensure_iso_date(risk.review_date, risk.risk_id, "review_date", errors)

    traceability_threats: set[str] = set()
    for link in model.traceability:
        _ensure_references(
            source_id=link.traceability_id,
            referenced_ids=[link.threat_id],
            valid_ids=threat_ids,
            label="threats",
            errors=errors,
        )
        _ensure_references(
            source_id=link.traceability_id,
            referenced_ids=link.requirement_ids,
            valid_ids=requirement_ids,
            label="requirements",
            errors=errors,
        )
        _ensure_references(
            source_id=link.traceability_id,
            referenced_ids=[link.residual_risk_id],
            valid_ids=residual_risk_ids,
            label="residual risks",
            errors=errors,
        )
        traceability_threats.add(link.threat_id)

    missing_traceability = sorted(threat_ids - traceability_threats)
    if missing_traceability:
        errors.append(f"Threats missing traceability links: {', '.join(missing_traceability)}")

    if errors:
        raise ThreatModelValidationError("\n".join(errors))
    return model
