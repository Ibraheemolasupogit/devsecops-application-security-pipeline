"""Markdown reports for lifecycle evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.lifecycle.config import OUTPUT_DIR, REPORT_DIR


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(output_dir / "lifecycle-summary.json")
    register = read_json(output_dir / "vulnerability-register.json")
    exceptions = read_json(output_dir / "security-exceptions.json")
    history = read_json(output_dir / "lifecycle-history.json")
    reports = {
        "vulnerability-lifecycle-report.md": _lifecycle(summary),
        "remediation-register-report.md": _remediation(register),
        "security-exception-report.md": _exceptions(exceptions, summary),
        "verification-report.md": _verification(summary),
        "overdue-findings-report.md": _overdue(summary),
        "lifecycle-audit-report.md": _audit(history),
    }
    written: list[Path] = []
    for name, body in reports.items():
        path = report_dir / name
        path.write_text(body, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _lifecycle(summary: dict[str, Any]) -> str:
    return f"""# Vulnerability Lifecycle Report

Total vulnerabilities: {summary["total_vulnerabilities"]}

By status:
{_mapping(summary["vulnerabilities_by_status"])}

By severity:
{_mapping(summary["vulnerabilities_by_severity"])}
"""


def _remediation(register: dict[str, Any]) -> str:
    rows = register["vulnerabilities"]
    return (
        "# Remediation Register Report\n\n"
        + "\n".join(
            f"- {item['vulnerability_id']}: {item['status']} - {item['remediation_plan']}"
            for item in rows[:20]
        )
        + "\n"
    )


def _exceptions(exceptions: dict[str, Any], summary: dict[str, Any]) -> str:
    return (
        f"""# Security Exception Report

Security exceptions: {summary["security_exception_count"]}

Active exceptions: {summary["active_exceptions"]}

Expired exceptions: {summary["expired_exceptions"]}

Expiring exceptions: {summary["expiring_exceptions"]}

"""
        + "\n".join(
            f"- {item['exception_id']}: {item['status']} expires {item['expiry_date']}"
            for item in exceptions["exceptions"]
        )
        + "\n"
    )


def _verification(summary: dict[str, Any]) -> str:
    return f"""# Verification Report

Verification records: {summary["verification_record_count"]}

Resolved but unverified: {summary["resolved_but_unverified"]}

Verified but not closed: {summary["verified_but_not_closed"]}

Closed findings: {summary["closed_findings"]}
"""


def _overdue(summary: dict[str, Any]) -> str:
    return f"""# Overdue Findings Report

Overdue findings: {summary["overdue_findings"]}

Due soon findings: {summary["due_soon_findings"]}

Unowned findings: {summary["unowned_findings"]}
"""


def _audit(history: dict[str, Any]) -> str:
    def _line(item: dict[str, Any]) -> str:
        transition = f"{item.get('from_status')} -> {item.get('to_status')}"
        return f"- {item['event_id']}: {item['event_type']} {transition}"

    return (
        "# Lifecycle Audit Report\n\n"
        + "\n".join(_line(item) for item in history["history"][:40])
        + "\n"
    )


def _mapping(mapping: dict[str, int]) -> str:
    return "\n".join(f"- {key}: {value}" for key, value in sorted(mapping.items())) or "- none"
