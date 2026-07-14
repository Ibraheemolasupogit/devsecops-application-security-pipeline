"""Markdown reports for the Repository 5 integration contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.integration.config import OUTPUT_DIR, REPORT_DIR


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(output_dir / "integration-summary.json")
    metrics = read_json(output_dir / "security-metrics.json")
    manifest = read_json(output_dir / "integration-manifest.json")
    data_quality = read_json(output_dir / "data-quality-summary.json")
    compatibility = read_json(output_dir / "compatibility-summary.json")
    lineage = read_json(output_dir / "finding-source-lineage.json")
    reports = {
        "repository-5-integration-report.md": _contract_report(summary, manifest),
        "product-security-export-report.md": _export_report(summary, metrics),
        "integration-data-quality-report.md": _data_quality_report(data_quality),
        "integration-lineage-report.md": _lineage_report(lineage),
        "integration-compatibility-report.md": _compatibility_report(compatibility),
    }
    written: list[Path] = []
    for name, content in reports.items():
        path = report_dir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _contract_report(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Repository 5 Integration Contract",
            "",
            f"Contract: `{summary['contract_name']}` version `{summary['contract_version']}`.",
            "",
            "A consumer control plane can validate and ingest the bundle by verifying the "
            "manifest, checksums, schemas, record counts and data-handling constraints.",
            "",
            f"Producer repository: `{manifest['producer_repository']}`.",
            f"Deployment status: `{manifest['deployment_status']}`.",
            "No Repository 5 files are modified and no external transfer is performed.",
            "",
        ]
    )


def _export_report(summary: dict[str, Any], metrics: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Product Security Export",
            "",
            f"Exported findings: {summary['export_record_count']}",
            f"Source findings represented: {summary['source_finding_count']}",
            f"Release decision: `{summary['release_decision']}`",
            f"Suppressed findings: {metrics['suppressed_findings']}",
            f"Risk-accepted findings: {metrics['risk_accepted_findings']}",
            f"Active exceptions: {metrics['active_exceptions']}",
            f"Expired exceptions: {metrics['expired_exceptions']}",
            "",
        ]
    )


def _data_quality_report(summary: dict[str, Any]) -> str:
    lines = ["# Integration Data Quality", "", f"Valid: `{summary['valid']}`", ""]
    for name, passed in sorted(summary["checks"].items()):
        lines.append(f"- `{name}`: `{passed}`")
    lines.append("")
    return "\n".join(lines)


def _lineage_report(lineage: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Integration Lineage",
            "",
            f"Lineage edges: {len(lineage['lineage_edges'])}",
            "",
            "Lineage preserves raw-source, canonical-finding, lifecycle, release and export "
            "relationships without hiding suppressed or risk-accepted findings.",
            "",
        ]
    )


def _compatibility_report(summary: dict[str, Any]) -> str:
    lines = [
        "# Integration Compatibility",
        "",
        f"Compatibility status: `{summary['compatibility_status']}`",
        f"Contract version: `{summary['contract_version']}`",
        f"Minimum consumer version: `{summary['minimum_consumer_version']}`",
        "",
    ]
    for warning in summary["warnings"]:
        lines.append(f"- {warning}")
    lines.append("")
    return "\n".join(lines)
