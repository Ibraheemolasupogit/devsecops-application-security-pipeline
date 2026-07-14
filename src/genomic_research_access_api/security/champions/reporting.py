"""Markdown reports for Security Champions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.champions.config import OUTPUT_DIR, REPORT_DIR
from genomic_research_access_api.security.findings.utils import read_json


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = read_json(output_dir / "programme-summary.json")
    coverage = read_json(output_dir / "squad-coverage.json")
    metrics = read_json(output_dir / "champion-metrics.json")
    maturity = read_json(output_dir / "maturity-assessment.json")
    workshops = read_json(output_dir / "workshop-inventory.json")
    completion = read_json(output_dir / "workshop-completion-summary.json")
    escalation = read_json(output_dir / "escalation-summary.json")
    reports = {
        "security-champions-report.md": _programme(summary, metrics),
        "champion-coverage-report.md": _coverage(coverage),
        "champion-maturity-report.md": _maturity(maturity),
        "champion-workshop-report.md": _workshops(workshops, completion),
        "champion-escalation-report.md": _escalation(escalation),
    }
    written = []
    for name, text in reports.items():
        path = report_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _programme(summary: dict[str, Any], metrics: dict[str, Any]) -> str:
    return f"""# Security Champions Report

Generated: {summary["generated_at"]}

The Security Champions programme is a local, evidence-backed operating model for distributing
product security ownership across engineering squads while Product Security retains accountability
for policy, release risk and formal acceptance.

| Measure | Value |
| --- | ---: |
| Squads | {summary["squad_count"]} |
| Champions | {summary["champion_count"]} |
| Workshops | {summary["workshop_count"]} |
| Coverage | {metrics["champion_coverage_percentage"]}% |
| Owner assignment | {metrics["owner_assignment_rate"]}% |
| Verification completion | {metrics["verification_completion_rate"]}% |

All programme records are synthetic demonstration data. No deployment, external messaging,
ticketing or Repository 5 integration is implemented.
"""


def _coverage(coverage: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {item['squad']} | {item['coverage_status']} | {item['active_champion_count']} |"
        for item in coverage["squads"]
    )
    return f"""# Champion Coverage Report

Coverage is calculated from the synthetic champion roster and role-based squad inventory.

| Squad | Status | Active champions |
| --- | --- | ---: |
{rows}

Required squad coverage: {coverage["champion_coverage_percentage"]}%.
Vacant required squads: {", ".join(coverage["squads_without_champion"]) or "none"}.
"""


def _maturity(maturity: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {item['name']} | {item['level_label']} | {item['next_step']} |"
        for item in maturity["areas"]
    )
    return f"""# Champion Maturity Report

The assessment is area-based and intentionally avoids a single opaque score.

| Area | Level | Next step |
| --- | --- | --- |
{rows}
"""


def _workshops(workshops: dict[str, Any], completion: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {item['title']} | {item['duration']} | {item['primary_evidence']} |"
        for item in workshops["workshops"]
    )
    return f"""# Champion Workshop Report

Workshop completion records are synthetic demonstration records and do not claim real attendance.

| Workshop | Duration | Evidence |
| --- | --- | --- |
{rows}

Fully completed champion records: {completion["fully_completed_count"]} of
{completion["champion_count"]}.
"""


def _escalation(escalation: dict[str, Any]) -> str:
    rows = "\n".join(
        f"| {item['trigger']} | {item['default_level']} | {', '.join(item['required_evidence'])} |"
        for item in escalation["criteria"]
    )
    return f"""# Champion Escalation Report

Escalation keeps squad handling close to the work while preserving Product Security and Risk
Owner decision rights.

| Trigger | Level | Required evidence |
| --- | --- | --- |
{rows}
"""
