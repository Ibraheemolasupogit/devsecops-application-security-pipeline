"""Markdown reports derived from canonical findings outputs."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.config import OUTPUT_DIR, REPORT_DIR
from genomic_research_access_api.security.findings.utils import read_json


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(output_dir / "findings-summary.json")
    risk = read_json(output_dir / "risk-summary.json")
    ownership = read_json(output_dir / "ownership-summary.json")
    sla = read_json(output_dir / "sla-summary.json")
    dedupe = read_json(output_dir / "deduplication-summary.json")
    outputs = {
        "findings-normalisation-report.md": _normalisation(summary),
        "risk-enrichment-report.md": _risk(risk),
        "ownership-report.md": _ownership(ownership),
        "remediation-sla-report.md": _sla(sla),
        "deduplication-report.md": _dedupe(dedupe),
    }
    written = []
    for name, content in outputs.items():
        path = report_dir / name
        path.write_text(content, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _table(mapping: dict[str, Any]) -> str:
    lines = ["| Name | Count |", "| --- | ---: |"]
    lines.extend(f"| {key} | {value} |" for key, value in mapping.items())
    return "\n".join(lines)


def _normalisation(summary: dict[str, Any]) -> str:
    return f"""# Findings Normalisation Report

Canonical schema version: 1.0

Total source findings: {summary["total_source_findings"]}

Total canonical findings: {summary["total_canonical_findings"]}

Deduplicated count: {summary["deduplicated_count"]}

## Source Tools

{_table(summary["findings_by_source_tool"])}

## Severity

{_table(summary["findings_by_severity"])}
"""


def _risk(risk: dict[str, Any]) -> str:
    highest = "\n".join(
        f"- {item['finding_id']}: {item['priority']} score {item['risk_score']} - {item['title']}"
        for item in risk["highest_risk"]
    )
    return f"""# Risk Enrichment Report

Formula: {risk["formula"]}

## Priority

{_table(risk["by_priority"])}

## Highest Risk

{highest}
"""


def _ownership(ownership: dict[str, Any]) -> str:
    return f"""# Ownership Report

Unowned findings: {ownership["unowned_findings"]}

## Owners

{_table(ownership["owners"])}
"""


def _sla(sla: dict[str, Any]) -> str:
    return f"""# Remediation SLA Report

{sla["portfolio_notice"]}

## Due Dates

{_table(sla["by_due_date"])}

Expired suppressions: {len(sla["overdue_or_expired_suppressions"])}
"""


def _dedupe(dedupe: dict[str, Any]) -> str:
    groups = "\n".join(
        f"- {group['primary_finding_id']}: {group['rationale']}" for group in dedupe["groups"]
    )
    return f"""# Deduplication Report

Deduplicated count: {dedupe["deduplicated_count"]}

## Groups

{groups}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    generate_reports()


if __name__ == "__main__":
    main()
