"""Security Champions metric calculations."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from genomic_research_access_api.security.champions.config import (
    SCHEMA_VERSION,
    as_of_date,
    load_configs,
)
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT


def squad_coverage() -> dict[str, Any]:
    configs = load_configs()
    squads = configs["squads"]["squads"]
    champions = configs["roster"]["champions"]
    champion_by_squad: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for champion in champions:
        champion_by_squad[champion["squad_id"]].append(champion)
    rows = []
    for squad in squads:
        squad_champions = champion_by_squad.get(squad["squad_id"], [])
        active = [item for item in squad_champions if item["status"] in {"active", "onboarding"}]
        rows.append(
            {
                "squad_id": squad["squad_id"],
                "squad": squad["name"],
                "required": squad["champion_required"],
                "champion_count": len(squad_champions),
                "active_champion_count": len(active),
                "coverage_status": "covered"
                if active
                else ("not_required" if not squad["champion_required"] else "vacant"),
            }
        )
    required = [row for row in rows if row["required"]]
    covered = [row for row in required if row["coverage_status"] == "covered"]
    return {
        "schema_version": SCHEMA_VERSION,
        "as_of_date": as_of_date(),
        "squad_count": len(rows),
        "required_squad_count": len(required),
        "covered_squad_count": len(covered),
        "squads_without_champion": [
            row["squad"] for row in rows if row["coverage_status"] == "vacant"
        ],
        "champion_coverage_percentage": round((len(covered) / len(required)) * 100, 2)
        if required
        else 100.0,
        "squads": rows,
    }


def workshop_inventory() -> dict[str, Any]:
    workshops = load_configs()["workshops"]["workshops"]
    return {
        "schema_version": SCHEMA_VERSION,
        "workshop_count": len(workshops),
        "workshops": sorted(workshops, key=lambda item: item["workshop_id"]),
    }


def workshop_completion() -> dict[str, Any]:
    configs = load_configs()
    workshops = {item["workshop_id"] for item in configs["workshops"]["workshops"]}
    champions = configs["roster"]["champions"]
    rows = []
    for champion in champions:
        completed = sorted(set(champion.get("workshops_completed", [])) & workshops)
        rows.append(
            {
                "champion_id": champion["champion_id"],
                "squad_id": champion["squad_id"],
                "status": champion["status"],
                "completed_workshop_count": len(completed),
                "total_workshop_count": len(workshops),
                "completion_percentage": round((len(completed) / len(workshops)) * 100, 2)
                if workshops
                else 100.0,
                "demonstration_data": True,
            }
        )
    complete = [row for row in rows if row["completion_percentage"] == 100.0]
    return {
        "schema_version": SCHEMA_VERSION,
        "champion_count": len(rows),
        "fully_completed_count": len(complete),
        "records": rows,
        "limitations": [
            "Workshop completion is synthetic demonstration data, not attendance history.",
            "No real training attendance system is implemented.",
        ],
    }


def champion_metrics() -> dict[str, Any]:
    findings = read_json(ROOT / "outputs/security/findings/deduplicated-findings.json")["findings"]
    lifecycle = read_json(ROOT / "outputs/security/lifecycle/vulnerability-register.json")[
        "vulnerabilities"
    ]
    exceptions = read_json(ROOT / "outputs/security/lifecycle/security-exceptions.json")[
        "exceptions"
    ]
    coverage = squad_coverage()
    by_squad = _count_by(findings, "squad")
    overdue = _count_where(lifecycle, "squad", lambda item: bool(item.get("overdue")))
    high_critical = _count_where(
        findings,
        "squad",
        lambda item: str(item.get("normalised_severity", "")).lower() in {"high", "critical"},
    )
    repeated_categories = Counter(str(item.get("security_domain", "unknown")) for item in findings)
    assigned = [
        item for item in findings if item.get("technical_owner") or item.get("remediation_owner")
    ]
    verified = [item for item in lifecycle if item.get("verification_status") == "verified"]
    active_or_expiring_exceptions = [
        item for item in exceptions if item.get("status") in {"active", "expiring", "expired"}
    ]
    reviewed_exceptions = [
        item for item in active_or_expiring_exceptions if item.get("review_date")
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "as_of_date": as_of_date(),
        "demonstration_data": True,
        "champion_coverage_percentage": coverage["champion_coverage_percentage"],
        "squads_with_active_champion": coverage["covered_squad_count"],
        "squads_without_champion": coverage["squads_without_champion"],
        "findings_by_squad": dict(sorted(by_squad.items())),
        "critical_high_findings_by_squad": dict(sorted(high_critical.items())),
        "overdue_findings_by_squad": dict(sorted(overdue.items())),
        "owner_assignment_rate": round((len(assigned) / len(findings)) * 100, 2)
        if findings
        else 100.0,
        "verification_completion_rate": round((len(verified) / len(lifecycle)) * 100, 2)
        if lifecycle
        else 100.0,
        "exception_review_completion_rate": round(
            (len(reviewed_exceptions) / len(active_or_expiring_exceptions)) * 100, 2
        )
        if active_or_expiring_exceptions
        else 100.0,
        "repeated_vulnerability_categories": {
            key: value for key, value in sorted(repeated_categories.items()) if value > 1
        },
        "workshop_completion": workshop_completion(),
        "anti_gaming_note": (
            "Metrics are used to reveal risk and support learning, not to hide findings."
        ),
    }


def _count_by(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        label = str(record.get(key) or "Unassigned")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _count_where(records: list[dict[str, Any]], key: str, predicate: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        if predicate(record):
            label = str(record.get(key) or "Unassigned")
            counts[label] = counts.get(label, 0) + 1
    return counts
