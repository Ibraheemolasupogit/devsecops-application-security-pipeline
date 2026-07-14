"""Security Champions config validation and inventories."""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from genomic_research_access_api.security.champions.config import (
    DOC_DIR,
    SCHEMA_VERSION,
    load_configs,
)
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT

STATUSES = {"active", "onboarding", "inactive", "vacant"}
ONBOARDING = {"complete", "in_progress", "not_started", "not_applicable"}
LEVELS = {"level_0", "level_1", "level_2", "level_3", "level_4"}
ESCALATION_LEVELS = {
    "squad_handling",
    "champion_escalation",
    "engineering_lead_escalation",
    "product_security_escalation",
    "risk_owner_escalation",
}
SECRET_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|@[A-Za-z0-9.-]+"
)


def _iso(value: str, field: str, errors: list[str]) -> None:
    try:
        date.fromisoformat(value)
    except ValueError:
        errors.append(f"{field} must be an ISO date")


def _ids(records: list[dict[str, Any]], key: str) -> list[str]:
    return [str(record[key]) for record in records]


def validate_programme() -> dict[str, Any]:
    configs = load_configs()
    errors: list[str] = []
    squads = configs["squads"].get("squads", [])
    roster = configs["roster"].get("champions", [])
    workshops = configs["workshops"].get("workshops", [])
    metrics = configs["metrics"].get("metrics", [])
    maturity_areas = configs["maturity"].get("areas", [])
    escalation = configs["escalation"].get("criteria", [])

    squad_ids = set(_ids(squads, "squad_id"))
    champion_ids = _ids(roster, "champion_id")
    workshop_ids = set(_ids(workshops, "workshop_id"))

    for label, values in {
        "squad_id": _ids(squads, "squad_id"),
        "champion_id": champion_ids,
        "workshop_id": _ids(workshops, "workshop_id"),
        "metric_id": _ids(metrics, "metric_id"),
        "maturity_area_id": _ids(maturity_areas, "area_id"),
        "escalation_id": _ids(escalation, "criterion_id"),
    }.items():
        if values != sorted(values):
            errors.append(f"{label} values must be in stable sorted order")
        duplicates = sorted({value for value in values if values.count(value) > 1})
        if duplicates:
            errors.append(f"duplicate {label}: {', '.join(duplicates)}")

    for squad in squads:
        if str(squad.get("name", "")).count("@"):
            errors.append(f"squad contains personal data: {squad['squad_id']}")
        for req in squad.get("security_requirement_ids", []):
            _requirement_exists(str(req), errors)
        for threat in squad.get("threat_ids", []):
            _threat_exists(str(threat), errors)

    for champion in roster:
        cid = champion["champion_id"]
        if champion["squad_id"] not in squad_ids:
            errors.append(f"{cid} references unknown squad {champion['squad_id']}")
        if champion["status"] not in STATUSES:
            errors.append(f"{cid} has invalid status {champion['status']}")
        if champion["onboarding_status"] not in ONBOARDING:
            errors.append(f"{cid} has invalid onboarding status {champion['onboarding_status']}")
        if champion.get("backup_champion") and champion["backup_champion"] not in champion_ids:
            errors.append(f"{cid} references unknown backup champion {champion['backup_champion']}")
        _iso(champion["start_date"], f"{cid}.start_date", errors)
        _iso(champion["review_date"], f"{cid}.review_date", errors)
        for workshop_id in champion.get("workshops_completed", []):
            if workshop_id not in workshop_ids:
                errors.append(f"{cid} references unknown workshop {workshop_id}")
        for value in champion.values():
            if isinstance(value, str) and SECRET_PATTERN.search(value):
                errors.append(f"{cid} contains personal or secret-like data")

    for metric in metrics:
        if metric.get("anti_gaming_guardrail") in {"", None}:
            errors.append(f"{metric['metric_id']} lacks anti-gaming guardrail")
        for source in metric.get("evidence_sources", []):
            if not (ROOT / source).exists():
                errors.append(f"{metric['metric_id']} references missing evidence source {source}")

    for area in maturity_areas:
        for level in area.get("levels", []):
            if level.get("level") not in LEVELS:
                errors.append(f"{area['area_id']} has invalid maturity level {level.get('level')}")

    for criterion in escalation:
        if criterion.get("default_level") not in ESCALATION_LEVELS:
            errors.append(f"{criterion['criterion_id']} has invalid escalation level")
        if not criterion.get("required_evidence"):
            errors.append(f"{criterion['criterion_id']} lacks required evidence")

    _validate_documentation(errors)
    sorted_errors = sorted(set(errors))
    result: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "valid": not errors,
        "errors": sorted_errors,
    }
    if errors:
        raise ValueError("\n".join(sorted_errors))
    return result


def _requirement_exists(requirement_id: str, errors: list[str]) -> None:
    requirements = {
        item["requirement_id"]
        for item in read_json(ROOT / "docs/threat-model/security-requirements.yaml")
    }
    if requirement_id not in requirements:
        errors.append(f"unknown security requirement {requirement_id}")


def _threat_exists(threat_id: str, errors: list[str]) -> None:
    threats = {
        item["threat_id"] for item in read_json(ROOT / "docs/threat-model/threat-register.yaml")
    }
    if threat_id not in threats:
        errors.append(f"unknown threat {threat_id}")


def _validate_documentation(errors: list[str]) -> None:
    required = [
        "README.md",
        "programme-charter.md",
        "champion-role.md",
        "operating-model.md",
        "onboarding-guide.md",
        "onboarding-checklist.md",
        "90-day-plan.md",
        "monthly-session-plan.md",
        "champion-checklist.md",
        "escalation-guide.md",
        "communication-guide.md",
        "metrics.md",
        "maturity-model.md",
        "succession-and-continuity.md",
        "recognition-model.md",
        "limitations.md",
        "workshops/threat-modelling-workshop.md",
        "workshops/secure-code-review-workshop.md",
        "workshops/vulnerability-triage-workshop.md",
        "workshops/authentication-and-authorisation-workshop.md",
        "workshops/cloud-and-terraform-security-workshop.md",
        "workshops/incident-learning-workshop.md",
        "exercises/threat-model-exercise.md",
        "exercises/code-review-exercise.md",
        "exercises/finding-triage-exercise.md",
        "exercises/exception-review-exercise.md",
        "exercises/release-gate-exercise.md",
        "templates/monthly-update-template.md",
        "templates/risk-escalation-template.md",
        "templates/threat-model-review-template.md",
        "templates/secure-design-review-template.md",
        "templates/workshop-feedback-template.md",
        "templates/champion-handover-template.md",
    ]
    for item in required:
        path = DOC_DIR / item
        if not path.exists():
            errors.append(f"missing champions document {item}")
            continue
        text = path.read_text(encoding="utf-8")
        if len(text.split()) < 80:
            errors.append(f"champions document is not substantive: {item}")
        if "/Users/" in text or "/private/" in text or SECRET_PATTERN.search(text):
            errors.append(f"champions document contains prohibited content: {item}")
