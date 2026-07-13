"""Markdown reports for Milestone 6 dynamic API security."""

from __future__ import annotations

import argparse
import json
from typing import Any, cast

from genomic_research_access_api.security.dynamic.config import OUTPUT_DIR, REPORT_DIR

REPORTS = {
    "dynamic-security-report.md": "dynamic-security-summary.json",
    "schemathesis-report.md": "schemathesis-summary.json",
    "zap-report.md": "zap-summary.json",
    "authentication-boundary-report.md": "authentication-boundary-summary.json",
    "authorisation-boundary-report.md": "authorisation-boundary-summary.json",
    "object-access-report.md": "object-access-summary.json",
    "resource-consumption-report.md": "resource-consumption-summary.json",
}


def read_summary(filename: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((OUTPUT_DIR / filename).read_text(encoding="utf-8")))


def render_report(title: str, payload: dict[str, Any]) -> str:
    lines = [
        f"# {title}",
        "",
        "Scope: local-only dynamic validation for the Genomic Research Access API.",
        "",
        f"Execution status: `{payload.get('execution_status', 'unknown')}`",
        f"Policy decision: `{payload.get('policy_decision', 'not-applicable')}`",
    ]
    if "test_count" in payload:
        lines.append(f"Test count: `{payload['test_count']}`")
        lines.append(f"Failed count: `{payload.get('failed_count', 0)}`")
    if "alerts_by_risk" in payload:
        lines.append(f"Alerts by risk: `{payload['alerts_by_risk']}`")
    if "tool_versions" in payload:
        lines.append(f"Tool versions: `{payload['tool_versions']}`")
    if "cases" in payload:
        lines.append("")
        lines.append("Cases:")
        for case in payload["cases"]:
            lines.append(f"- `{case['name']}`: `{case['outcome']}`")
    lines.append("")
    lines.append(
        "Limitations: local synthetic validation only; this is not penetration-test coverage."
    )
    lines.append("")
    return "\n".join(lines)


def generate_reports() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    for report_name, summary_name in REPORTS.items():
        title = report_name.removesuffix(".md").replace("-", " ").title()
        (REPORT_DIR / report_name).write_text(
            render_report(title, read_summary(summary_name)),
            encoding="utf-8",
            newline="\n",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    generate_reports()


if __name__ == "__main__":
    main()
