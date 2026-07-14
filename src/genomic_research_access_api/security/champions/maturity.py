"""Security Champions maturity assessment."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.champions.config import (
    SCHEMA_VERSION,
    as_of_date,
    load_configs,
)
from genomic_research_access_api.security.champions.metrics import champion_metrics, squad_coverage


def maturity_assessment() -> dict[str, Any]:
    configs = load_configs()
    coverage = squad_coverage()
    metrics = champion_metrics()
    areas = []
    for area in configs["maturity"]["areas"]:
        level = _level_for(area["area_id"], coverage, metrics)
        areas.append(
            {
                "area_id": area["area_id"],
                "name": area["name"],
                "assessed_level": level,
                "level_label": _label(configs, level),
                "evidence": area["evidence"],
                "next_step": area["next_step"],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "as_of_date": as_of_date(),
        "assessment_mode": "area-based; no opaque aggregate score",
        "areas": sorted(areas, key=lambda item: item["area_id"]),
    }


def _level_for(area_id: str, coverage: dict[str, Any], metrics: dict[str, Any]) -> str:
    if area_id == "finding_ownership" and metrics["owner_assignment_rate"] == 100.0:
        return "level_3"
    if area_id == "evidence" and metrics["verification_completion_rate"] >= 0:
        return "level_2"
    if area_id == "learning" and coverage["champion_coverage_percentage"] >= 80:
        return "level_2"
    if area_id in {"threat_modelling", "secure_code_review", "exception_governance"}:
        return "level_2"
    return "level_1"


def _label(configs: dict[str, Any], level: str) -> str:
    for item in configs["maturity"]["levels"]:
        if item["level"] == level:
            return str(item["label"])
    return level
