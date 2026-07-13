"""Control coverage aggregation."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.evidence.config import load_config
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT


def aggregate_control_coverage() -> dict[str, Any]:
    requirements = read_json(
        ROOT / "outputs/security/threat-model/validated-security-requirements.json"
    )
    mapping = load_config("control-mapping.yaml")["domains"]
    controls: list[dict[str, Any]] = []
    for req in requirements:
        status = _status(req)
        domain = _domain(str(req.get("category")), mapping)
        controls.append(
            {
                "control_id": req["requirement_id"],
                "security_requirement_ids": [req["requirement_id"]],
                "threat_ids": req.get("source_threat_ids", []),
                "domain": domain,
                "implementation_status": status,
                "verification_status": _verification_status(status),
                "evidence_references": [req.get("evidence_reference", "")],
                "owner": req.get("owner", "unknown"),
                "deployment_dependency": _deployment_dependency(req),
                "residual_risk": req.get("residual_risk", "unknown"),
            }
        )
    by_status: dict[str, int] = {}
    for control in controls:
        by_status[control["implementation_status"]] = (
            by_status.get(control["implementation_status"], 0) + 1
        )
    covered = sum(
        1 for item in controls if item["verification_status"] in {"verified", "validated_locally"}
    )
    percentage = round((covered / len(controls)) * 100, 2) if controls else 0.0
    return {
        "schema_version": "1.0",
        "controls": controls,
        "control_count": len(controls),
        "coverage_percentage": percentage,
        "coverage_by_status": dict(sorted(by_status.items())),
    }


def _status(requirement: dict[str, Any]) -> str:
    raw = str(requirement.get("implementation_status"))
    reference = str(requirement.get("implementation_reference", ""))
    if raw == "planned":
        return "planned"
    if "infrastructure/" in reference or "Terraform" in reference:
        return "implemented_as_code"
    if raw == "implemented":
        return "validated_locally"
    return "partially_implemented"


def _verification_status(status: str) -> str:
    if status == "planned":
        return "planned"
    if status == "implemented_as_code":
        return "validated_locally"
    if status == "validated_locally":
        return "verified"
    return "partially_implemented"


def _domain(category: str, mapping: dict[str, list[str]]) -> str:
    for domain, categories in mapping.items():
        if category in categories:
            return domain
    return "threat_model"


def _deployment_dependency(requirement: dict[str, Any]) -> str:
    text = " ".join(
        str(requirement.get(key, ""))
        for key in ("description", "implementation_reference", "verification_method")
    ).lower()
    return "future_deployment" if "future" in text or "terraform" in text else "none"
