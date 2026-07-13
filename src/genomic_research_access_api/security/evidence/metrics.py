"""Consolidated metrics."""

from __future__ import annotations

from typing import Any


def build_metrics(
    *,
    threat_summary: dict[str, Any],
    requirements: list[dict[str, Any]],
    findings: dict[str, Any],
    release: dict[str, Any],
    lifecycle: dict[str, Any],
    appsec: dict[str, Any],
    source_status: dict[str, Any],
    controls: dict[str, Any],
) -> dict[str, Any]:
    implemented = sum(
        1 for item in requirements if item.get("implementation_status") == "implemented"
    )
    planned = sum(1 for item in requirements if item.get("implementation_status") == "planned")
    partial = len(requirements) - implemented - planned
    return {
        "schema_version": "1.0",
        "metrics": {
            "total_threats": threat_summary["total_threats"],
            "high_critical_threats": (
                threat_summary.get("threats_by_inherent_risk", {}).get("critical", 0)
                + threat_summary.get("threats_by_inherent_risk", {}).get("high", 0)
            ),
            "security_requirements": len(requirements),
            "implemented_requirements": implemented,
            "partially_implemented_requirements": partial,
            "planned_requirements": planned,
            "scanner_tools_executed": appsec.get("scanner_count", 0),
            "scanner_findings_by_source": findings.get("findings_by_source_tool", {}),
            "canonical_findings": findings.get("total_canonical_findings", 0),
            "findings_by_severity": findings.get("findings_by_severity", {}),
            "findings_by_priority": findings.get("findings_by_priority", {}),
            "suppressed_findings": findings.get("suppressed_findings", 0),
            "expired_suppressions": findings.get("expired_suppressions", 0),
            "unowned_findings": findings.get("unowned_findings", 0),
            "release_decision": release.get("decision"),
            "conditional_findings": len(release.get("conditional_findings", [])),
            "blocking_findings": len(release.get("blocking_findings", [])),
            "warning_findings": len(release.get("warning_findings", [])),
            "vulnerability_records": lifecycle.get("total_vulnerabilities", 0),
            "vulnerabilities_by_lifecycle_status": lifecycle.get("vulnerabilities_by_status", {}),
            "overdue_findings": lifecycle.get("overdue_findings", 0),
            "due_soon_findings": lifecycle.get("due_soon_findings", 0),
            "false_positives": lifecycle.get("false_positives", 0),
            "risk_accepted_findings": lifecycle.get("risk_accepted", 0),
            "active_exceptions": lifecycle.get("active_exceptions", 0),
            "expired_exceptions": lifecycle.get("expired_exceptions", 0),
            "expiring_exceptions": lifecycle.get("expiring_exceptions", 0),
            "verification_records": lifecycle.get("verification_record_count", 0),
            "closed_findings": lifecycle.get("closed_findings", 0),
            "resolved_but_unverified_findings": lifecycle.get("resolved_but_unverified", 0),
            "control_coverage_percentage": controls.get("coverage_percentage", 0.0),
            "verified_evidence_domains": source_status.get("verified_domains", 0),
            "failed_evidence_domains": source_status.get("failed_domains", 0),
        },
    }
