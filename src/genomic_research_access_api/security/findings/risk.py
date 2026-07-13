"""Transparent contextual risk scoring."""

from __future__ import annotations

from genomic_research_access_api.security.findings.config import load_config
from genomic_research_access_api.security.findings.enums import Priority
from genomic_research_access_api.security.findings.models import Finding


def score_finding(finding: Finding) -> tuple[float, Priority, dict[str, float]]:
    config = load_config("risk-scoring.yaml")
    weights = config["weights"]
    scores = config["factor_scores"]
    factors = {
        "technical_severity": scores["technical_severity"].get(
            finding.normalised_severity, scores["technical_severity"]["unknown"]
        ),
        "exploitability": scores["exploitability"].get(
            finding.exploitability, scores["exploitability"]["unknown"]
        ),
        "internet_exposure": scores["internet_exposure"].get(
            finding.internet_exposure, scores["internet_exposure"]["unknown"]
        ),
        "asset_criticality": scores["asset_criticality"].get(
            finding.asset_criticality, scores["asset_criticality"]["unknown"]
        ),
        "data_sensitivity": scores["data_sensitivity"].get(
            finding.data_sensitivity, scores["data_sensitivity"]["unknown"]
        ),
        "privilege_required": scores["privilege_required"].get(
            finding.privilege_required, scores["privilege_required"]["unknown"]
        ),
        "age_or_recurrence": scores["age_or_recurrence"]["first_seen"],
    }
    score = round(sum(factors[name] * weights[name] for name in weights), 2)
    thresholds = config["priority_thresholds"]
    if score >= thresholds["P1"]:
        priority = Priority.P1
    elif score >= thresholds["P2"]:
        priority = Priority.P2
    elif score >= thresholds["P3"]:
        priority = Priority.P3
    elif score >= thresholds["P4"]:
        priority = Priority.P4
    else:
        priority = Priority.P5
    return score, priority, factors


def apply_risk(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        score, priority, factors = score_finding(finding)
        finding.risk_score = score
        finding.priority = priority
        finding.metadata["risk_factors"] = factors
    return findings
