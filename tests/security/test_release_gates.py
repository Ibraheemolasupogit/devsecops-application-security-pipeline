from pathlib import Path

import pytest

from genomic_research_access_api.security.findings.utils import read_json, write_json
from genomic_research_access_api.security.release import __main__ as release_main
from genomic_research_access_api.security.release.config import (
    CONFIG_DIR,
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
)
from genomic_research_access_api.security.release.enums import ReleaseDecision
from genomic_research_access_api.security.release.evaluator import evaluate
from genomic_research_access_api.security.release.evidence import generate, verify
from genomic_research_access_api.security.release.report import generate_reports
from genomic_research_access_api.security.release.rules import (
    enforcement_exit_code,
    matches_condition,
    validate_policy_config,
)


def finding(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "finding_id": "FIND-001",
        "source_tool": "trivy",
        "source_type": "container_scan",
        "finding_type": "Container",
        "security_domain": "supply-chain",
        "title": "demo finding",
        "normalised_severity": "high",
        "confidence": "high",
        "exploitability": "medium",
        "internet_exposure": "internal",
        "asset_criticality": "medium",
        "data_sensitivity": "low",
        "environment": "not_deployed",
        "repository": "devsecops-application-security-pipeline",
        "application": "genomic-research-access-api",
        "risk_score": 70.0,
        "priority": "P2",
        "fixed_version": None,
        "technical_owner": "Platform Engineering",
        "risk_owner": "Product Security",
        "remediation_owner": "Platform Engineering",
        "due_date": "2026-02-01",
        "suppression_status": None,
        "suppression_expiry": None,
        "compensating_control": None,
        "verification_status": "source-observed",
    }
    payload.update(overrides)
    return payload


def write_findings(tmp_path: Path, rows: list[dict[str, object]]) -> Path:
    path = tmp_path / "deduplicated-findings.json"
    write_json(path, {"schema_version": "1.0", "findings": rows})
    return path


def decisions(result: dict[str, object]) -> dict[str, str]:
    evaluations = result["finding_evaluations"]["evaluations"]  # type: ignore[index]
    return {item["finding_id"]: item["decision_contribution"] for item in evaluations}


def test_release_policy_validation_accepts_documented_rules() -> None:
    summary = validate_policy_config()
    assert summary["valid"] is True
    assert summary["rule_count"] >= 12
    assert summary["approval_role_count"] >= 4


def test_release_rule_operators() -> None:
    context = {"severity": "high", "risk_score": 72, "due_date": "2025-12-31", "owner": None}
    assert matches_condition(
        context, {"field": "severity", "operator": "equals", "value": "high"}, DEFAULT_AS_OF_DATE
    )
    assert matches_condition(
        context, {"field": "severity", "operator": "in", "value": ["high"]}, DEFAULT_AS_OF_DATE
    )
    assert matches_condition(context, {"field": "owner", "operator": "is_null"}, DEFAULT_AS_OF_DATE)
    assert matches_condition(
        context,
        {"field": "risk_score", "operator": "greater_than_or_equal", "value": 70},
        DEFAULT_AS_OF_DATE,
    )
    assert matches_condition(
        context,
        {"field": "due_date", "operator": "days_overdue_greater_than", "value": 0},
        DEFAULT_AS_OF_DATE,
    )


def test_no_fix_container_is_conditional_in_dev(tmp_path: Path) -> None:
    result = evaluate(findings_path=write_findings(tmp_path, [finding()]))
    assert result["decision"]["decision"] == "conditional_pass"
    assert decisions(result)["FIND-001"] == "conditional_pass"
    assert "Technical Owner" in result["required_approvals"]["missing_approvals"]


def test_prod_high_internet_fix_available_blocks(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(
                finding_id="FIND-PROD",
                normalised_severity="critical",
                internet_exposure="internet_facing",
                fixed_version="2.0.0",
                environment="prod",
            )
        ],
    )
    result = evaluate(findings_path=path, environment="prod")
    assert result["decision"]["decision"] == "block"
    assert result["decision"]["blocking_finding_ids"] == ["FIND-PROD"]


def test_precedence_block_over_conditional_and_warn(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(finding_id="FIND-COND"),
            finding(
                finding_id="FIND-BLOCK",
                finding_type="Secret",
                normalised_severity="critical",
                fixed_version="1.0.0",
            ),
            finding(finding_id="FIND-WARN", normalised_severity="medium", finding_type="DAST"),
        ],
    )
    result = evaluate(findings_path=path)
    assert result["decision"]["decision"] == "block"
    assert decisions(result)["FIND-COND"] == "conditional_pass"
    assert decisions(result)["FIND-WARN"] == "warn"


def test_stable_decision_id_for_same_inputs(tmp_path: Path) -> None:
    path = write_findings(tmp_path, [finding()])
    first = evaluate(findings_path=path)
    second = evaluate(findings_path=path)
    assert first["decision"]["decision_id"] == second["decision"]["decision_id"]


def test_fix_availability_changes_decision_by_environment(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(
                finding_id="FIND-FIX", fixed_version="3.1.4", internet_exposure="internet_facing"
            )
        ],
    )
    assert evaluate(findings_path=path, environment="dev")["decision"]["decision"] == "pass"
    assert evaluate(findings_path=path, environment="prod")["decision"]["decision"] == "block"


def test_expired_suppression_blocks(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(
                finding_id="FIND-EXP",
                suppression_status="active",
                suppression_expiry="2025-12-31",
                compensating_control="Runtime monitoring",
            )
        ],
    )
    result = evaluate(findings_path=path)
    assert result["decision"]["decision"] == "block"
    assert "FIND-EXP" in result["decision"]["expired_suppression_finding_ids"]


def test_approaching_suppression_expiry_is_warn_or_conditional(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(
                finding_id="FIND-SUP",
                normalised_severity="medium",
                suppression_status="active",
                suppression_expiry="2026-01-10",
                compensating_control="Runtime monitoring",
            )
        ],
    )
    result = evaluate(findings_path=path)
    matched_ids = result["finding_evaluations"]["evaluations"][0]["matched_rule_ids"]
    assert "RG-WARN-003" in matched_ids
    assert result["decision"]["decision"] == "conditional_pass"


def test_unowned_and_overdue_p1_block(tmp_path: Path) -> None:
    path = write_findings(
        tmp_path,
        [
            finding(
                finding_id="FIND-UNOWNED",
                technical_owner="unowned",
                risk_owner=None,
                remediation_owner=None,
            ),
            finding(finding_id="FIND-P1", priority="P1", due_date="2025-12-31"),
        ],
    )
    result = evaluate(findings_path=path)
    assert result["decision"]["decision"] == "block"
    assert result["decision"]["blocking_finding_ids"] == ["FIND-P1", "FIND-UNOWNED"]


def test_approval_aggregation_and_enforcement(tmp_path: Path) -> None:
    result = evaluate(findings_path=write_findings(tmp_path, [finding()]))
    missing = result["required_approvals"]["missing_approvals"]
    assert set(missing) == {"Product Security", "Technical Owner"}
    assert enforcement_exit_code(ReleaseDecision.CONDITIONAL_PASS, missing) == 1
    complete = evaluate(
        findings_path=write_findings(tmp_path, [finding(finding_id="FIND-COMPLETE")]),
        approval_roles={"Product Security", "Technical Owner"},
    )
    assert complete["required_approvals"]["missing_approvals"] == []
    assert complete["required_approvals"]["enforcement_exit_code"] == 0


def test_release_rationale_mentions_decision_basis(tmp_path: Path) -> None:
    result = evaluate(findings_path=write_findings(tmp_path, [finding()]))
    assert "conditionally passable" in result["decision"]["rationale"]
    assert "RG-COND-001" in result["finding_evaluations"]["evaluations"][0]["rationale"]


def test_evidence_is_deterministic_and_tamper_detects(tmp_path: Path) -> None:
    generate(tmp_path)
    verify(tmp_path)
    decision = read_json(tmp_path / "release-gate-decision.json")
    assert decision["decision_id"].startswith("REL-")
    payload = read_json(tmp_path / "release-risk-summary.json")
    payload["tampered"] = True
    write_json(tmp_path / "release-risk-summary.json", payload)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify(tmp_path)


def test_report_generation(tmp_path: Path) -> None:
    generate(tmp_path)
    report_dir = tmp_path / "reports"
    written = generate_reports(tmp_path, report_dir)
    assert {item.name for item in written} == {
        "release-actions-report.md",
        "release-assurance-report.md",
        "release-gate-report.md",
        "release-risk-report.md",
    }


def test_current_canonical_findings_evaluate_to_conditional_pass() -> None:
    result = evaluate(timestamp=DEFAULT_TIMESTAMP)
    assert result["decision"]["decision"] == "conditional_pass"
    assert result["decision"]["evaluated_finding_count"] >= 40
    assert "RG-COND-001" in result["decision"]["rules_matched"]


@pytest.mark.parametrize(
    "command, expected",
    [
        ("validate", "validated"),
        ("evaluate", "evaluated release gate decision"),
        ("evidence", "generated release evidence"),
        ("verify", "verified release evidence"),
        ("report", "generated release reports"),
        ("full", "completed release full workflow"),
    ],
)
def test_release_cli_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str, expected: str
) -> None:
    monkeypatch.setattr("sys.argv", ["release", command])
    release_main.main()
    assert expected in capsys.readouterr().out


def test_enforcement_fixtures(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    no_approval = CONFIG_DIR / "fixtures" / "no-approvals.yaml"
    complete = CONFIG_DIR / "fixtures" / "complete-approvals.yaml"
    monkeypatch.setattr("sys.argv", ["release", "enforce", "--approvals-file", str(no_approval)])
    with pytest.raises(SystemExit) as missing:
        release_main.main()
    assert missing.value.code == 1
    assert "missing approvals" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["release", "enforce", "--approvals-file", str(complete)])
    with pytest.raises(SystemExit) as approved:
        release_main.main()
    assert approved.value.code == 0
