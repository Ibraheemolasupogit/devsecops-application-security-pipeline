"""Consolidated evidence report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.evidence.config import OUTPUT_DIR, REPORT_DIR, load_config
from genomic_research_access_api.security.evidence.verification import scan_sensitive_content
from genomic_research_access_api.security.findings.utils import read_json


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    evidence = read_json(output_dir / "consolidated-evidence.json")
    metrics = read_json(output_dir / "security-metrics.json")["metrics"]
    integrity = read_json(output_dir / "evidence-integrity-summary.json")
    controls = read_json(output_dir / "control-coverage.json")
    lineage = read_json(output_dir / "evidence-lineage.json")
    policy = load_config("report-policy.yaml")
    reports = {
        "executive-security-summary.md": _executive(evidence, metrics, integrity),
        "product-security-report.md": _product_security(evidence, metrics),
        "security-evidence-report.md": _evidence(evidence),
        "control-coverage-report.md": _controls(controls),
        "threat-and-requirements-report.md": _threats(metrics),
        "application-security-report.md": _domain(evidence, "api_security", metrics),
        "cloud-infrastructure-security-report.md": _domain(evidence, "infrastructure", metrics),
        "dynamic-security-report.md": _domain(evidence, "dynamic_security", metrics),
        "findings-and-risk-report.md": _findings(metrics),
        "release-assurance-report.md": _release(metrics),
        "vulnerability-remediation-report.md": _lifecycle(metrics),
        "security-exception-report.md": _exceptions(metrics),
        "evidence-integrity-report.md": _integrity(integrity),
        "portfolio-assurance-report.md": _portfolio(evidence, metrics, lineage),
    }
    written: list[Path] = []
    for name in policy["report_order"]:
        path = report_dir / name
        path.write_text(reports[name], encoding="utf-8", newline="\n")
        written.append(path)
    _validate_report_metrics(written, metrics)
    sensitive_errors = scan_sensitive_content(written)
    if sensitive_errors:
        raise ValueError("\n".join(sensitive_errors))
    return written


def _executive(evidence: dict[str, Any], metrics: dict[str, Any], integrity: dict[str, Any]) -> str:
    critical_high = metrics["findings_by_severity"].get("critical", 0) + metrics[
        "findings_by_severity"
    ].get("high", 0)
    exception_line = (
        f"Security exceptions: active {metrics['active_exceptions']}, "
        f"expired {metrics['expired_exceptions']}, "
        f"expiring {metrics['expiring_exceptions']}"
    )
    lifecycle_line = (
        f"Lifecycle summary: {metrics['vulnerability_records']} vulnerabilities; "
        f"{metrics['overdue_findings']} overdue."
    )
    integrity_line = (
        f"Evidence integrity: {evidence['verified_domain_count']} verified domains, "
        f"{evidence['failed_domain_count']} failed domains."
    )
    return f"""# Executive Security Summary

Project: {evidence["project_name"]}

Milestone status: Milestone 10 consolidated evidence implemented.

Deployment status: {evidence["deployment_status"]}

Overall assurance posture: {integrity["overall_integrity_decision"]}

Release decision: {metrics["release_decision"]}

Control coverage: {metrics["control_coverage_percentage"]}%

Critical/high findings: {critical_high}

{exception_line}

{lifecycle_line}

{integrity_line}

Known limitations: local portfolio evidence only; not regulatory certification.

Next milestone boundary: Milestone 11 developer enablement is not implemented.
"""


def _product_security(evidence: dict[str, Any], metrics: dict[str, Any]) -> str:
    bundle = evidence["evidence_bundle_id"]
    return f"""# Product Security Report

Architecture, threat model, application controls, authentication, authorisation, AppSec,
dynamic testing, findings, release gates, lifecycle and exception governance are represented
in bundle `{bundle}`.

Canonical findings: {metrics["canonical_findings"]}

Release decision: {metrics["release_decision"]}

Vulnerability records: {metrics["vulnerability_records"]}
"""


def _evidence(evidence: dict[str, Any]) -> str:
    domains = "\n".join(
        f"- {item['domain_id']}: {item['verification_status']}" for item in evidence["domains"]
    )
    return f"# Security Evidence Report\n\nBundle: {evidence['evidence_bundle_id']}\n\n{domains}\n"


def _controls(controls: dict[str, Any]) -> str:
    return f"""# Control Coverage Report

Controls: {controls["control_count"]}

Coverage: {controls["coverage_percentage"]}%

By status:
{_mapping(controls["coverage_by_status"])}
"""


def _threats(metrics: dict[str, Any]) -> str:
    return f"""# Threat and Requirements Report

Threats: {metrics["total_threats"]}

High/critical threats: {metrics["high_critical_threats"]}

Security requirements: {metrics["security_requirements"]}
"""


def _domain(evidence: dict[str, Any], domain: str, metrics: dict[str, Any]) -> str:
    item = next(entry for entry in evidence["domains"] if entry["domain_id"] == domain)
    return (
        f"# {item['name']}\n\n"
        f"Verification status: {item['verification_status']}\n\n"
        f"Source manifest: {item['source_manifest']}\n\n"
        f"Release decision: {metrics['release_decision']}\n"
    )


def _findings(metrics: dict[str, Any]) -> str:
    return f"""# Findings and Risk Report

Canonical findings: {metrics["canonical_findings"]}

Suppressed findings: {metrics["suppressed_findings"]}

Unowned findings: {metrics["unowned_findings"]}

By severity:
{_mapping(metrics["findings_by_severity"])}
"""


def _release(metrics: dict[str, Any]) -> str:
    return f"""# Release Assurance Report

Release decision: {metrics["release_decision"]}

Blocking findings: {metrics["blocking_findings"]}

Conditional findings: {metrics["conditional_findings"]}

Warning findings: {metrics["warning_findings"]}
"""


def _lifecycle(metrics: dict[str, Any]) -> str:
    return f"""# Vulnerability Remediation Report

Vulnerability records: {metrics["vulnerability_records"]}

Overdue findings: {metrics["overdue_findings"]}

Resolved but unverified findings: {metrics["resolved_but_unverified_findings"]}

By status:
{_mapping(metrics["vulnerabilities_by_lifecycle_status"])}
"""


def _exceptions(metrics: dict[str, Any]) -> str:
    return f"""# Security Exception Report

Active exceptions: {metrics["active_exceptions"]}

Expired exceptions: {metrics["expired_exceptions"]}

Expiring exceptions: {metrics["expiring_exceptions"]}

Risk accepted findings: {metrics["risk_accepted_findings"]}
"""


def _integrity(integrity: dict[str, Any]) -> str:
    return f"""# Evidence Integrity Report

Verified manifests: {integrity["verified_manifests"]}

Checksum failures: {integrity["checksum_failures"]}

Missing outputs: {integrity["missing_outputs"]}

Local-path findings: {integrity["local_path_findings"]}

Secret-pattern findings: {integrity["secret_pattern_findings"]}

Timestamp consistency: {integrity["timestamp_consistency"]}

Deployment-status consistency: {integrity["deployment_status_consistency"]}

Overall integrity decision: {integrity["overall_integrity_decision"]}
"""


def _portfolio(evidence: dict[str, Any], metrics: dict[str, Any], lineage: dict[str, Any]) -> str:
    return f"""# Portfolio Assurance Report

Bundle: {evidence["evidence_bundle_id"]}

Evidence domains: {evidence["domain_count"]}

Verified domains: {evidence["verified_domain_count"]}

Lineage edges: {len(lineage["edges"])}

Control coverage: {metrics["control_coverage_percentage"]}%

Deployment status: {evidence["deployment_status"]}
"""


def _mapping(mapping: dict[str, int]) -> str:
    return "\n".join(f"- {key}: {value}" for key, value in sorted(mapping.items())) or "- none"


def _validate_report_metrics(paths: list[Path], metrics: dict[str, Any]) -> None:
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    for value in (
        str(metrics["canonical_findings"]),
        str(metrics["vulnerability_records"]),
        str(metrics["release_decision"]),
    ):
        if value not in combined:
            raise ValueError(f"report metric missing from generated reports: {value}")
