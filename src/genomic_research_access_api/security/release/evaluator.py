"""Risk-based release gate evaluation over canonical findings."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import canonical_json, read_json
from genomic_research_access_api.security.release.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_ENVIRONMENT,
    DEFAULT_TIMESTAMP,
    FINDINGS_PATH,
    load_config,
    policy_version,
)
from genomic_research_access_api.security.release.enums import ReleaseDecision, RuleOutcome
from genomic_research_access_api.security.release.models import (
    FindingEvaluation,
    ReleaseDecisionRecord,
    RuleEvaluation,
)
from genomic_research_access_api.security.release.rules import (
    enforcement_exit_code,
    finding_context,
    load_rules,
    matches_rule,
    most_severe,
)


def load_findings(path: Path = FINDINGS_PATH) -> list[dict[str, Any]]:
    payload = read_json(path)
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("deduplicated findings document must contain a findings list")
    return findings


def evaluate(
    *,
    findings_path: Path = FINDINGS_PATH,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
    environment: str = DEFAULT_ENVIRONMENT,
    approval_roles: set[str] | None = None,
) -> dict[str, Any]:
    findings = load_findings(findings_path)
    rules = load_rules()
    approvals = approval_roles or set()
    rule_evaluations: list[RuleEvaluation] = []
    finding_evaluations: list[FindingEvaluation] = []
    matched_rule_records: list[dict[str, Any]] = []
    required_approval_map: dict[str, set[str]] = {}
    required_action_map: dict[str, set[str]] = {}

    for finding in findings:
        context = finding_context(finding, as_of_date=as_of_date, release_environment=environment)
        matched_rules = []
        for rule in rules:
            if not rule.enabled or environment not in rule.environments:
                outcome = RuleOutcome.NOT_APPLICABLE
                rationale = f"{rule.rule_id} is not applicable to {environment}."
            elif matches_rule(
                context, rule, release_environment=environment, as_of_date=as_of_date
            ):
                outcome = _outcome_for_match(context, rule.decision)
                rationale = rule.rationale_template.format(finding_id=finding["finding_id"])
                matched_rules.append(rule)
                matched_rule_records.append(
                    {
                        "rule_id": rule.rule_id,
                        "finding_id": finding["finding_id"],
                        "decision": rule.decision.value,
                        "outcome": outcome.value,
                        "priority": rule.priority,
                        "required_approvals": sorted(rule.required_approvals),
                        "required_actions": sorted(rule.required_actions),
                        "rationale": rationale,
                    }
                )
                for role in rule.required_approvals:
                    required_approval_map.setdefault(role, set()).add(str(finding["finding_id"]))
                for action in rule.required_actions:
                    required_action_map.setdefault(action, set()).add(str(finding["finding_id"]))
            else:
                outcome = RuleOutcome.NOT_MATCHED
                rationale = f"{rule.rule_id} did not match {finding['finding_id']}."
            rule_evaluations.append(
                RuleEvaluation(
                    rule_id=rule.rule_id,
                    finding_id=finding["finding_id"],
                    outcome=outcome,
                    decision=rule.decision
                    if outcome
                    in {RuleOutcome.MATCHED, RuleOutcome.SUPPRESSED, RuleOutcome.DEFERRED}
                    else None,
                    rationale=rationale,
                )
            )

        matched_decisions = [rule.decision for rule in matched_rules]
        decision = most_severe(matched_decisions)
        matched_ids = [rule.rule_id for rule in matched_rules]
        finding_evaluations.append(
            FindingEvaluation(
                finding_id=finding["finding_id"],
                matched_rule_ids=matched_ids,
                decision_contribution=decision,
                effective_severity=str(context.get("normalised_severity", "unknown")),
                risk_score=context.get("risk_score"),
                priority=context.get("priority"),
                owner_status=str(context["owner_status"]),
                suppression_status=context.get("suppression_status"),
                due_status=str(context["due_status"]),
                fix_status=str(context["fix_status"]),
                environment=str(context["environment"]),
                rationale=_finding_rationale(finding["finding_id"], decision, matched_ids),
                required_actions=sorted(
                    {action for rule in matched_rules for action in rule.required_actions}
                ),
                required_approvals=sorted(
                    {role for rule in matched_rules for role in rule.required_approvals}
                ),
            )
        )

    contributions = [item.decision_contribution for item in finding_evaluations]
    release_decision = most_severe(contributions)
    required_approvals = sorted(required_approval_map)
    missing_approvals = sorted(set(required_approvals) - approvals)
    decision_record = _decision_record(
        findings=findings,
        finding_evaluations=finding_evaluations,
        matched_rule_records=matched_rule_records,
        required_approvals=required_approvals,
        required_action_map=required_action_map,
        findings_path=findings_path,
        timestamp=timestamp,
        as_of_date=as_of_date,
        environment=environment,
        decision=release_decision,
    )
    approvals_document = {
        "schema_version": "1.0",
        "decision_id": decision_record.decision_id,
        "required_approvals": [
            {
                "role": role,
                "status": "approved" if role in approvals else "missing",
                "finding_ids": sorted(required_approval_map[role]),
            }
            for role in required_approvals
        ],
        "provided_approvals": sorted(approvals),
        "missing_approvals": missing_approvals,
        "enforcement_exit_code": enforcement_exit_code(release_decision, missing_approvals),
    }
    return {
        "decision": decision_record.model_dump(mode="json"),
        "finding_evaluations": {
            "schema_version": "1.0",
            "evaluations": [item.model_dump(mode="json") for item in finding_evaluations],
        },
        "rule_evaluations": [item.model_dump(mode="json") for item in rule_evaluations],
        "matched_rules": {
            "schema_version": "1.0",
            "matched_rules": sorted(
                matched_rule_records, key=lambda item: (item["rule_id"], item["finding_id"])
            ),
        },
        "release_actions": _actions_document(decision_record.decision_id, required_action_map),
        "required_approvals": approvals_document,
        "risk_summary": _risk_summary(decision_record.decision_id, findings, finding_evaluations),
    }


def _decision_record(
    *,
    findings: list[dict[str, Any]],
    finding_evaluations: list[FindingEvaluation],
    matched_rule_records: list[dict[str, Any]],
    required_approvals: list[str],
    required_action_map: dict[str, set[str]],
    findings_path: Path,
    timestamp: str,
    as_of_date: str,
    environment: str,
    decision: ReleaseDecision,
) -> ReleaseDecisionRecord:
    checksum = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    policy = load_config("release-policy.yaml")
    env_policy = load_config("environment-policy.yaml")
    decision_basis = {
        "as_of_date": as_of_date,
        "environment": environment,
        "findings_input_checksum": checksum,
        "policy_version": policy_version(),
    }
    decision_id = (
        "REL-" + hashlib.sha256(canonical_json(decision_basis).encode("utf-8")).hexdigest()[:16]
    )
    by_decision = _finding_ids_by_decision(finding_evaluations)
    matched_ids = sorted({item["rule_id"] for item in matched_rule_records})
    not_matched_ids = sorted({rule.rule_id for rule in load_rules()} - set(matched_ids))
    return ReleaseDecisionRecord(
        decision_id=decision_id,
        decision=decision,
        decision_timestamp=timestamp,
        as_of_date=as_of_date,
        environment=environment,
        application="genomic-research-access-api",
        repository="devsecops-application-security-pipeline",
        policy_version=policy_version(),
        findings_input_checksum=checksum,
        evaluated_finding_count=len(findings),
        blocking_finding_ids=by_decision["block"],
        conditional_finding_ids=by_decision["conditional_pass"],
        warning_finding_ids=by_decision["warn"],
        informational_finding_ids=by_decision["pass"],
        unowned_finding_ids=sorted(
            item.finding_id for item in finding_evaluations if item.owner_status == "unowned"
        ),
        expired_suppression_finding_ids=sorted(
            str(item["finding_id"])
            for item in findings
            if item.get("suppression_status") == "active"
            and item.get("suppression_expiry")
            and str(item["suppression_expiry"]) < as_of_date
        ),
        overdue_finding_ids=sorted(
            item.finding_id for item in finding_evaluations if item.due_status == "overdue"
        ),
        rules_evaluated=len(load_rules()) * len(findings),
        rules_matched=matched_ids,
        rules_not_matched=not_matched_ids,
        required_approvals=required_approvals,
        required_actions=sorted(required_action_map),
        rationale=_release_rationale(decision, by_decision),
        limitations=list(policy.get("limitations", [])),
        deployment_status=str(env_policy["environments"][environment]["deployment_status"]),
        evidence_references=[
            "outputs/security/findings/deduplicated-findings.json",
            "outputs/security/release/finding-evaluations.json",
            "outputs/security/release/matched-rules.json",
        ],
    )


def _outcome_for_match(context: dict[str, Any], decision: ReleaseDecision) -> RuleOutcome:
    if context.get("suppression_status") == "active" and decision != ReleaseDecision.BLOCK:
        return RuleOutcome.SUPPRESSED
    if decision == ReleaseDecision.CONDITIONAL_PASS:
        return RuleOutcome.DEFERRED
    return RuleOutcome.MATCHED


def _finding_rationale(finding_id: str, decision: ReleaseDecision, matched_ids: list[str]) -> str:
    if not matched_ids:
        return f"{finding_id} did not match an active release gate rule."
    return f"{finding_id} contributes {decision.value} through {', '.join(matched_ids)}."


def _release_rationale(decision: ReleaseDecision, by_decision: dict[str, list[str]]) -> str:
    if decision == ReleaseDecision.BLOCK:
        return f"Release is blocked by {len(by_decision['block'])} blocking finding(s)."
    if decision == ReleaseDecision.CONDITIONAL_PASS:
        return (
            "Release is conditionally passable with required approvals for "
            f"{len(by_decision['conditional_pass'])} finding(s)."
        )
    if decision == ReleaseDecision.WARN:
        return f"Release passes with warnings for {len(by_decision['warn'])} finding(s)."
    return "Release passes because no blocking, conditional or warning rules matched."


def _finding_ids_by_decision(evaluations: list[FindingEvaluation]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {decision.value: [] for decision in ReleaseDecision}
    for item in evaluations:
        grouped[str(item.decision_contribution)].append(item.finding_id)
    return {key: sorted(value) for key, value in grouped.items()}


def _actions_document(decision_id: str, required_action_map: dict[str, set[str]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "decision_id": decision_id,
        "actions": [
            {"action": action, "finding_ids": sorted(finding_ids)}
            for action, finding_ids in sorted(required_action_map.items())
        ],
    }


def _risk_summary(
    decision_id: str,
    findings: list[dict[str, Any]],
    evaluations: list[FindingEvaluation],
) -> dict[str, Any]:
    by_severity = Counter(str(item.get("normalised_severity", "unknown")) for item in findings)
    by_priority = Counter(str(item.get("priority", "unknown")) for item in findings)
    by_decision = Counter(str(item.decision_contribution) for item in evaluations)
    top_risk = sorted(
        [
            {
                "finding_id": item["finding_id"],
                "risk_score": item.get("risk_score"),
                "priority": item.get("priority"),
                "normalised_severity": item.get("normalised_severity"),
                "title": item.get("title"),
            }
            for item in findings
        ],
        key=lambda item: (-float(item["risk_score"] or 0), str(item["finding_id"])),
    )[:10]
    return {
        "schema_version": "1.0",
        "decision_id": decision_id,
        "finding_count": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_priority": dict(sorted(by_priority.items())),
        "by_decision": dict(sorted(by_decision.items())),
        "top_risk_findings": top_risk,
    }


def canonical_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
