"""Security Champions evidence generation and verification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.champions.config import (
    OUTPUT_DIR,
    SCHEMA_VERSION,
    as_of_date,
    evidence_timestamp,
    load_configs,
)
from genomic_research_access_api.security.champions.inventory import validate_programme
from genomic_research_access_api.security.champions.maturity import maturity_assessment
from genomic_research_access_api.security.champions.metrics import (
    champion_metrics,
    squad_coverage,
    workshop_completion,
    workshop_inventory,
)
from genomic_research_access_api.security.findings.utils import read_json, write_json
from genomic_research_access_api.security.threat_model.io import sha256_file


def programme_summary() -> dict[str, Any]:
    configs = load_configs()
    coverage = squad_coverage()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": evidence_timestamp(),
        "as_of_date": as_of_date(),
        "programme_name": configs["policy"]["programme"]["name"],
        "squad_count": coverage["squad_count"],
        "champion_count": len(configs["roster"]["champions"]),
        "workshop_count": len(configs["workshops"]["workshops"]),
        "local_only": True,
        "deployment_status": "not_deployed",
        "demonstration_data": True,
        "milestone_boundary": (
            "Milestone 12 only; Repository 5 integration, dashboards and "
            "Milestone 13 are not implemented."
        ),
    }


def champion_roster() -> dict[str, Any]:
    champions = load_configs()["roster"]["champions"]
    return {
        "schema_version": SCHEMA_VERSION,
        "champion_count": len(champions),
        "synthetic_records": True,
        "champions": sorted(champions, key=lambda item: item["champion_id"]),
    }


def escalation_summary() -> dict[str, Any]:
    criteria = load_configs()["escalation"]["criteria"]
    return {
        "schema_version": SCHEMA_VERSION,
        "criterion_count": len(criteria),
        "criteria": sorted(criteria, key=lambda item: item["criterion_id"]),
    }


def developer_control_alignment() -> dict[str, Any]:
    mappings = [
        {
            "alignment_id": "SCA-001",
            "champions_requirement_ids": ["SR-CHAMP-001", "SR-CHAMP-002"],
            "developer_enablement_requirement_ids": ["SR-DEV-001", "SR-DEV-002"],
            "evidence": [
                "outputs/security/developer-enablement/enablement-summary.json",
                "outputs/security/champions/programme-summary.json",
            ],
        },
        {
            "alignment_id": "SCA-002",
            "champions_requirement_ids": ["SR-CHAMP-003", "SR-CHAMP-004"],
            "developer_enablement_requirement_ids": ["SR-DEV-003", "SR-DEV-004"],
            "evidence": [
                "outputs/security/champions/champion-metrics.json",
                "outputs/security/findings/deduplicated-findings.json",
            ],
        },
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "alignment_count": len(mappings),
        "mappings": mappings,
    }


def generate(output_dir: Path = OUTPUT_DIR) -> list[Path]:
    validate_programme()
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "programme-summary.json": programme_summary(),
        "champion-roster.json": champion_roster(),
        "squad-coverage.json": squad_coverage(),
        "champion-metrics.json": champion_metrics(),
        "maturity-assessment.json": maturity_assessment(),
        "workshop-inventory.json": workshop_inventory(),
        "workshop-completion-summary.json": workshop_completion(),
        "escalation-summary.json": escalation_summary(),
        "developer-control-alignment.json": developer_control_alignment(),
    }
    written = []
    for name, payload in outputs.items():
        path = output_dir / name
        write_json(path, payload)
        written.append(path)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "controlled_timestamp": evidence_timestamp(),
        "as_of_date": as_of_date(),
        "repository": "devsecops-application-security-pipeline",
        "deployment_status": "not_deployed",
        "synthetic_programme_data": True,
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
    }
    manifest_path = output_dir / "evidence-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ValueError("Security Champions evidence manifest missing")
    manifest = read_json(manifest_path)
    errors = []
    for name, details in manifest["output_files"].items():
        path = output_dir / str(details["path"])
        if not path.exists():
            errors.append(f"missing output: {name}")
        elif sha256_file(path) != details["sha256"]:
            errors.append(f"checksum mismatch: {name}")
    summary = read_json(output_dir / "programme-summary.json")
    if not summary.get("demonstration_data"):
        errors.append("programme summary must label demonstration data")
    roster = read_json(output_dir / "champion-roster.json")
    if not roster.get("synthetic_records"):
        errors.append("champion roster must label synthetic records")
    if errors:
        raise ValueError("\n".join(sorted(errors)))
