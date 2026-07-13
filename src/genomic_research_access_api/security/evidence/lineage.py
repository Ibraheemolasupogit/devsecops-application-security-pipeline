"""Evidence lineage generation."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT


def generate_lineage() -> dict[str, Any]:
    traceability = read_json(
        ROOT / "outputs/security/threat-model/validated-control-traceability.json"
    )
    edges: list[dict[str, Any]] = []
    relationships = [
        ("threat_model", "security_requirements", "defines"),
        ("security_requirements", "implementation_references", "maps_to"),
        ("implementation_references", "tests", "verified_by"),
        ("tests", "scanner_outputs", "augmented_by"),
        ("scanner_outputs", "canonical_findings", "normalised_into"),
        ("canonical_findings", "release_decision", "evaluated_by"),
        ("release_decision", "lifecycle_records", "feeds"),
        ("lifecycle_records", "consolidated_report", "summarised_by"),
    ]
    for index, (source, target, relationship) in enumerate(relationships, start=1):
        linked = traceability[(index - 1) % len(traceability)] if traceability else {}
        edges.append(
            {
                "source_id": source,
                "target_id": target,
                "relationship": relationship,
                "source_reference": _reference(source),
                "target_reference": _reference(target),
                "control_ids": linked.get("requirement_ids", []),
                "threat_ids": [linked.get("threat_id")] if linked.get("threat_id") else [],
                "security_requirement_ids": linked.get("requirement_ids", []),
            }
        )
    return {"schema_version": "1.0", "edges": edges}


def _reference(node: str) -> str:
    references = {
        "threat_model": "outputs/security/threat-model/validated-threat-register.json",
        "security_requirements": (
            "outputs/security/threat-model/validated-security-requirements.json"
        ),
        "implementation_references": "docs/threat-model/control-traceability.yaml",
        "tests": "tests/",
        "scanner_outputs": "outputs/security/appsec/raw/",
        "canonical_findings": "outputs/security/findings/deduplicated-findings.json",
        "release_decision": "outputs/security/release/release-gate-decision.json",
        "lifecycle_records": "outputs/security/lifecycle/vulnerability-register.json",
        "consolidated_report": "reports/security/security-evidence-report.md",
    }
    return references[node]
