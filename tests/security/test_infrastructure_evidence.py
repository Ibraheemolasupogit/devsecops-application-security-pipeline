import json
from pathlib import Path

from genomic_research_access_api.security.infrastructure.evidence import (
    architecture_inventory,
    build_summary,
    encryption_control_summary,
    generate_evidence,
    iam_policy_summary,
    iam_role_inventory,
    logging_and_audit_summary,
    network_security_summary,
    provider_constraints,
    terraform_validation_summary,
    verify_evidence,
)
from genomic_research_access_api.security.infrastructure.report import generate_reports


def test_ci_infrastructure_test_target_uses_active_python_pytest() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    assert "PYTEST := $(PYTHON) -m pytest" in makefile
    assert "infrastructure-test:\n\tPYTHONPATH=src $(PYTEST) infrastructure/tests -q" in makefile


def test_infrastructure_evidence_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    generate_evidence(first, timestamp="2026-01-01T00:00:00Z")
    generate_evidence(second, timestamp="2026-01-01T00:00:00Z")

    first_manifest = json.loads((first / "evidence-manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((second / "evidence-manifest.json").read_text(encoding="utf-8"))

    assert first_manifest["deployment_status"] == "not deployed"
    assert first_manifest["output_files"] == second_manifest["output_files"]
    verify_evidence(first)


def test_infrastructure_summaries_reflect_required_controls() -> None:
    assert architecture_inventory()["compute"] == "AWS ECS Fargate"
    assert iam_role_inventory()["separation"] == "configured"
    assert iam_policy_summary()["wildcard_actions"] is False
    assert network_security_summary()["ecs_assign_public_ip"] == "false"
    assert encryption_control_summary()["secret_values_in_terraform"] == "not configured"
    assert logging_and_audit_summary()["cloudtrail_multi_region"] is True
    assert terraform_validation_summary()["deployment_commands_run"] is False
    assert build_summary()["aws_resources_created"] is False
    assert provider_constraints()["aws"] == "~> 5.70"


def test_infrastructure_reports_are_generated(tmp_path: Path) -> None:
    reports = generate_reports(tmp_path)
    report_names = {path.name for path in reports}

    assert "aws-architecture-report.md" in report_names
    assert "terraform-security-report.md" in report_names
    assert "iam-security-report.md" in report_names
    assert "infrastructure-validation-report.md" in report_names
    assert "not deployed" in (tmp_path / "aws-architecture-report.md").read_text(encoding="utf-8")
