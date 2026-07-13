"""Release gate rule validation and matching."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.release.config import (
    DEFAULT_AS_OF_DATE,
    load_config,
    read_json_yaml,
)
from genomic_research_access_api.security.release.enums import ReleaseDecision
from genomic_research_access_api.security.release.models import GateRule

ALLOWED_OPERATORS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "is_null",
    "is_not_null",
    "greater_than_or_equal",
    "less_than_or_equal",
    "days_overdue_greater_than",
    "days_until_less_than_or_equal",
}

ALLOWED_FIELDS = {
    "finding_id",
    "source_tool",
    "source_type",
    "finding_type",
    "security_domain",
    "normalised_severity",
    "severity",
    "confidence",
    "exploitability",
    "internet_exposure",
    "asset_criticality",
    "data_sensitivity",
    "environment",
    "repository",
    "application",
    "risk_score",
    "priority",
    "fixed_version",
    "fix_status",
    "technical_owner",
    "risk_owner",
    "remediation_owner",
    "owner_status",
    "due_date",
    "due_status",
    "suppression_status",
    "suppression_expiry",
    "compensating_control",
    "verification_status",
}

DECISION_PRECEDENCE = {
    ReleaseDecision.BLOCK: 4,
    ReleaseDecision.CONDITIONAL_PASS: 3,
    ReleaseDecision.WARN: 2,
    ReleaseDecision.PASS: 1,
}


def load_rules() -> list[GateRule]:
    payload = load_config("gate-rules.yaml")
    rules = [GateRule.model_validate(item) for item in payload.get("rules", [])]
    return sorted(rules, key=lambda item: (item.priority, item.rule_id))


def validate_policy_config() -> dict[str, Any]:
    release_policy = load_config("release-policy.yaml")
    environment_policy = load_config("environment-policy.yaml")
    approval_policy = load_config("approval-policy.yaml")
    severity_overrides = load_config("severity-overrides.yaml")
    rules = load_rules()

    environments = set(str(name) for name in environment_policy["environments"])
    roles = set(str(role) for role in approval_policy["allowed_roles"])
    rule_ids: set[str] = set()
    errors: list[str] = []
    warnings: list[str] = []

    precedence = release_policy.get("precedence")
    if precedence != ["block", "conditional_pass", "warn", "pass"]:
        errors.append(
            "release-policy decision_precedence must be block > conditional_pass > warn > pass"
        )

    for rule in rules:
        if rule.rule_id in rule_ids:
            errors.append(f"duplicate release rule id: {rule.rule_id}")
        rule_ids.add(rule.rule_id)
        if not set(rule.environments).issubset(environments):
            errors.append(f"{rule.rule_id} references an unknown release environment")
        if not set(rule.required_approvals).issubset(roles):
            errors.append(f"{rule.rule_id} references an unknown approval role")
        for condition in rule.conditions:
            field = str(condition.get("field", ""))
            operator = str(condition.get("operator", ""))
            if field not in ALLOWED_FIELDS:
                errors.append(f"{rule.rule_id} uses unsupported condition field: {field}")
            if operator not in ALLOWED_OPERATORS:
                errors.append(f"{rule.rule_id} uses unsupported operator: {operator}")

    for override in severity_overrides.get("overrides", []):
        if not override.get("name") or not override.get("effect"):
            errors.append("severity override entries require name and effect")

    if not rules:
        errors.append("release policy has no gate rules")
    if not warnings:
        warnings.append("No policy validation warnings.")

    return {
        "schema_version": "1.0",
        "policy_version": release_policy["policy_version"],
        "valid": not errors,
        "rule_count": len(rules),
        "environment_count": len(environments),
        "approval_role_count": len(roles),
        "errors": errors,
        "warnings": warnings,
    }


def approved_roles(path: str | None = None) -> set[str]:
    if not path:
        return set()
    payload = read_json_yaml(Path(path))
    roles = payload.get("approved_roles", []) if isinstance(payload, dict) else []
    return {str(role) for role in roles}


def finding_context(
    finding: dict[str, Any],
    *,
    as_of_date: str = DEFAULT_AS_OF_DATE,
    release_environment: str = "dev",
) -> dict[str, Any]:
    context = dict(finding)
    context["environment"] = _effective_environment(finding, release_environment)
    context["owner_status"] = _owner_status(finding)
    context["fix_status"] = _fix_status(finding)
    context["due_status"] = _due_status(finding.get("due_date"), as_of_date)
    context["suppression_expiry_status"] = _due_status(
        finding.get("suppression_expiry"), as_of_date, missing="none"
    )
    return context


def matches_condition(context: dict[str, Any], condition: dict[str, Any], as_of_date: str) -> bool:
    field = str(condition["field"])
    operator = str(condition["operator"])
    expected = condition.get("value")
    actual = context.get(field)

    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "not_in":
        return isinstance(expected, list) and actual not in expected
    if operator == "is_null":
        return actual in (None, "")
    if operator == "is_not_null":
        return actual not in (None, "")
    if operator == "greater_than_or_equal":
        return float(actual or 0) >= float(expected or 0)
    if operator == "less_than_or_equal":
        return float(actual or 0) <= float(expected or 0)
    if operator == "days_overdue_greater_than":
        days = _days_delta(actual, as_of_date)
        return days is not None and days < -int(expected or 0)
    if operator == "days_until_less_than_or_equal":
        days = _days_delta(actual, as_of_date)
        return days is not None and 0 <= days <= int(expected or 0)
    raise ValueError(f"unsupported release condition operator: {operator}")


def matches_rule(
    context: dict[str, Any],
    rule: GateRule,
    *,
    release_environment: str,
    as_of_date: str,
) -> bool:
    return (
        rule.enabled
        and release_environment in rule.environments
        and all(matches_condition(context, condition, as_of_date) for condition in rule.conditions)
    )


def most_severe(decisions: list[ReleaseDecision]) -> ReleaseDecision:
    if not decisions:
        return ReleaseDecision.PASS
    return max(decisions, key=lambda item: DECISION_PRECEDENCE[item])


def enforcement_exit_code(decision: ReleaseDecision, missing_approvals: list[str]) -> int:
    if decision == ReleaseDecision.BLOCK:
        return 2
    if decision == ReleaseDecision.CONDITIONAL_PASS and missing_approvals:
        return 1
    return 0


def _owner_status(finding: dict[str, Any]) -> str:
    owners = [
        finding.get("technical_owner"),
        finding.get("risk_owner"),
        finding.get("remediation_owner"),
    ]
    return "owned" if any(owner and owner != "unowned" for owner in owners) else "unowned"


def _fix_status(finding: dict[str, Any]) -> str:
    return "fix_available" if finding.get("fixed_version") else "no_fix_available"


def _effective_environment(finding: dict[str, Any], release_environment: str) -> str:
    configured = load_config("environment-policy.yaml")
    deployment_status = configured["environments"][release_environment]["deployment_status"]
    if str(finding.get("environment")) == "not_deployed":
        return "not_deployed"
    return str(finding.get("environment") or deployment_status)


def _due_status(value: Any, as_of_date: str, *, missing: str = "no_due_date") -> str:
    if not value:
        return missing
    days = _days_delta(value, as_of_date)
    if days is None:
        return missing
    if days < 0:
        return "overdue"
    due_soon_days = int(load_config("release-policy.yaml").get("due_soon_days", 7))
    return "due_soon" if days <= due_soon_days else "within_sla"


def _days_delta(value: Any, as_of_date: str) -> int | None:
    if not value:
        return None
    return (date.fromisoformat(str(value)) - date.fromisoformat(as_of_date)).days
