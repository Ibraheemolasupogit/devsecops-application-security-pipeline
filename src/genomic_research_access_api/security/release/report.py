"""Markdown reports for release-assurance evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.release.config import OUTPUT_DIR, REPORT_DIR


def generate_reports(output_dir: Path = OUTPUT_DIR, report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    decision = read_json(output_dir / "release-gate-decision.json")
    evaluations = read_json(output_dir / "finding-evaluations.json")
    matched = read_json(output_dir / "matched-rules.json")
    actions = read_json(output_dir / "release-actions.json")
    approvals = read_json(output_dir / "required-approvals.json")
    risk = read_json(output_dir / "release-risk-summary.json")

    reports = {
        "release-assurance-report.md": _assurance_report(decision, approvals),
        "release-gate-report.md": _gate_report(decision, matched, evaluations),
        "release-risk-report.md": _risk_report(decision, risk),
        "release-actions-report.md": _actions_report(decision, actions, approvals),
    }
    written: list[Path] = []
    for name, body in reports.items():
        path = report_dir / name
        path.write_text(body, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _assurance_report(decision: dict[str, Any], approvals: dict[str, Any]) -> str:
    return f"""# Release Assurance Report

Decision ID: {decision["decision_id"]}

Decision: {decision["decision"]}

Policy version: {decision["policy_version"]}

Environment: {decision["environment"]}

Deployment status: {decision["deployment_status"]}

Evaluated findings: {decision["evaluated_finding_count"]}

Required approvals: {", ".join(decision["required_approvals"]) or "none"}

Missing approvals: {", ".join(approvals["missing_approvals"]) or "none"}

Rationale: {decision["rationale"]}

Limitations:
{_bullets(decision["limitations"])}
"""


def _gate_report(
    decision: dict[str, Any], matched: dict[str, Any], evaluations: dict[str, Any]
) -> str:
    return f"""# Release Gate Report

Decision: {decision["decision"]}

Matched rules: {", ".join(decision["rules_matched"]) or "none"}

Rules not matched: {", ".join(decision["rules_not_matched"]) or "none"}

Blocking findings: {", ".join(decision["blocking_finding_ids"]) or "none"}

Conditional findings: {", ".join(decision["conditional_finding_ids"]) or "none"}

Warning findings: {", ".join(decision["warning_finding_ids"]) or "none"}

Matched rule evaluations:
{_matched_rule_lines(matched["matched_rules"])}

Finding evaluations:
{_evaluation_lines(evaluations["evaluations"])}
"""


def _risk_report(decision: dict[str, Any], risk: dict[str, Any]) -> str:
    return f"""# Release Risk Report

Decision ID: {decision["decision_id"]}

Findings by severity:
{_mapping_lines(risk["by_severity"])}

Findings by priority:
{_mapping_lines(risk["by_priority"])}

Findings by decision contribution:
{_mapping_lines(risk["by_decision"])}

Highest risk findings:
{_top_risk_lines(risk["top_risk_findings"])}
"""


def _actions_report(
    decision: dict[str, Any], actions: dict[str, Any], approvals: dict[str, Any]
) -> str:
    return f"""# Release Actions Report

Decision: {decision["decision"]}

Required actions:
{_action_lines(actions["actions"])}

Required approvals:
{_approval_lines(approvals["required_approvals"])}
"""


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) or "- none"


def _mapping_lines(mapping: dict[str, int]) -> str:
    return "\n".join(f"- {key}: {value}" for key, value in sorted(mapping.items())) or "- none"


def _matched_rule_lines(items: list[dict[str, Any]]) -> str:
    return (
        "\n".join(
            f"- {item['rule_id']} on {item['finding_id']}: {item['decision']} ({item['outcome']})"
            for item in items
        )
        or "- none"
    )


def _evaluation_lines(items: list[dict[str, Any]]) -> str:
    return (
        "\n".join(
            (
                f"- {item['finding_id']}: {item['decision_contribution']} via "
                f"{', '.join(item['matched_rule_ids']) or 'no matched rules'}"
            )
            for item in items
        )
        or "- none"
    )


def _top_risk_lines(items: list[dict[str, Any]]) -> str:
    return (
        "\n".join(
            (
                f"- {item['finding_id']}: {item['priority']} "
                f"score {item['risk_score']} - {item['title']}"
            )
            for item in items
        )
        or "- none"
    )


def _action_lines(items: list[dict[str, Any]]) -> str:
    return (
        "\n".join(f"- {item['action']} ({', '.join(item['finding_ids'])})" for item in items)
        or "- none"
    )


def _approval_lines(items: list[dict[str, Any]]) -> str:
    return (
        "\n".join(
            f"- {item['role']}: {item['status']} ({', '.join(item['finding_ids'])})"
            for item in items
        )
        or "- none"
    )
