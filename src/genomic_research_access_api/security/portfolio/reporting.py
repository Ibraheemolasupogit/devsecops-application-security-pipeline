"""Portfolio report generation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.portfolio.config import OUTPUT_DIR, REPORT_DIR

REPORT_NAMES = {
    "final-project-report.md": "Final Project Report",
    "final-security-assurance-report.md": "Final Security Assurance Report",
    "final-architecture-report.md": "Final Architecture Report",
    "final-testing-report.md": "Final Testing Report",
    "final-evidence-report.md": "Final Evidence Report",
    "final-limitations-report.md": "Final Limitations Report",
    "final-portfolio-readiness-report.md": "Final Portfolio Readiness Report",
}


def generate_reports() -> list[Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    summary = read_json(OUTPUT_DIR / "portfolio-summary.json")
    metrics = read_json(OUTPUT_DIR / "portfolio-metrics.json")["metrics"]
    readiness = read_json(OUTPUT_DIR / "portfolio-readiness.json")
    written = []
    for filename, title in REPORT_NAMES.items():
        path = REPORT_DIR / filename
        path.write_text(
            render_report(title, summary, metrics, readiness), encoding="utf-8", newline="\n"
        )
        written.append(path)
    return written


def render_report(
    title: str, summary: dict[str, Any], metrics: dict[str, Any], readiness: dict[str, Any]
) -> str:
    limitations = "\n".join(f"- {item}" for item in readiness["limitations"])
    failures = "\n".join(f"- {item}" for item in readiness["failures"]) or "- None"
    return (
        f"# {title}\n\n"
        f"Portfolio ID: `{summary['portfolio_id']}`\n\n"
        f"Readiness status: `{summary['readiness_status']}`\n\n"
        f"Release decision: `{summary['release_decision']}`\n\n"
        "## Key Metrics\n\n"
        f"- Canonical findings: {metrics['canonical_findings']}\n"
        f"- Source findings: {metrics['source_findings']}\n"
        f"- Evidence domains: {metrics['evidence_domains']}\n"
        f"- Control coverage: {metrics['control_coverage_percentage']}%\n"
        f"- Integration export records: {metrics['integration_export_records']}\n"
        f"- Repository integration lineage edges: {metrics['integration_lineage_edges']}\n\n"
        "## Readiness Failures\n\n"
        f"{failures}\n\n"
        "## Limitations\n\n"
        f"{limitations}\n"
    )
