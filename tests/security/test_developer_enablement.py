from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from genomic_research_access_api.security.enablement import evidence
from genomic_research_access_api.security.enablement.catalog import (
    COMMANDS,
    CONTROL_MAPPINGS,
    PR_CHECKLIST_ITEMS,
    REQUIRED_GUIDES,
)


def test_guide_inventory_current_docs_are_substantive() -> None:
    inventory = evidence.documentation_inventory()
    assert inventory["guide_count"] == len(REQUIRED_GUIDES)
    assert all(item["exists"] for item in inventory["guides"])
    assert all(item["word_count"] >= 120 for item in inventory["guides"])


def test_command_inventory_references_existing_make_targets() -> None:
    inventory = evidence.command_inventory()
    assert inventory["command_count"] == len(COMMANDS)
    assert all(item["make_target_exists"] for item in inventory["commands"])
    assert any(
        item["command"] == "make developer-enablement-full" for item in inventory["commands"]
    )


def test_pr_checklist_coverage() -> None:
    summary = evidence.checklist_summary()
    assert summary["checklist_item_count"] == len(PR_CHECKLIST_ITEMS)
    assert summary["covered_count"] == len(PR_CHECKLIST_ITEMS)


def test_control_mapping_references_developer_guidance() -> None:
    mapping = evidence.control_mapping()
    assert mapping["mapping_count"] == len(CONTROL_MAPPINGS)
    requirement_ids = {
        requirement
        for item in mapping["mappings"]
        for requirement in item["security_requirement_ids"]
    }
    assert {"SR-DEV-001", "SR-DEV-002", "SR-DEV-003", "SR-DEV-004"} <= requirement_ids


def test_prerequisite_status_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_which(name: str) -> str | None:
        if name in {"docker", "python3", "git"}:
            return f"/usr/bin/{name}"
        return None

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(evidence, "_command_ok", lambda command: True)
    summary = evidence.prerequisite_summary()
    statuses = {item["name"]: item["status"] for item in summary["checks"]}
    assert statuses["docker_daemon"] == "available"
    assert statuses["gitleaks"] == "available_via_fallback"
    assert statuses["trivy"] == "available_via_fallback"
    assert statuses["aws_credentials"] == "not_required"


def test_tool_unavailable_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    summary = evidence.prerequisite_summary()
    statuses = {item["name"]: item["status"] for item in summary["checks"]}
    assert statuses["docker_cli"] == "unavailable"
    assert statuses["docker_daemon"] == "unavailable"
    assert statuses["gitleaks"] == "unavailable"
    assert statuses["trivy"] == "unavailable"


def test_validate_docs_detects_missing_make_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guide = tmp_path / "guide.md"
    guide.write_text(("Run `make missing-target` for validation. " * 30), encoding="utf-8")
    monkeypatch.setattr(evidence, "REQUIRED_GUIDES", [type("Guide", (), {"path": str(guide)})()])
    with pytest.raises(ValueError, match="missing-target"):
        evidence.validate_docs()


def test_validate_docs_detects_broken_relative_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    guide = docs_dir / "guide.md"
    guide.write_text(("[broken](missing.md) " * 130), encoding="utf-8")
    monkeypatch.setattr(evidence, "REQUIRED_GUIDES", [type("Guide", (), {"path": str(guide)})()])
    with pytest.raises(ValueError, match="broken markdown link"):
        evidence.validate_docs()


def test_deterministic_evidence_and_tamper_rejection(tmp_path: Path) -> None:
    written = evidence.generate(tmp_path)
    first = {path.name: path.read_text(encoding="utf-8") for path in written}
    evidence.verify(tmp_path)
    evidence.generate(tmp_path)
    second = {path.name: path.read_text(encoding="utf-8") for path in written}
    assert first == second

    (tmp_path / "enablement-summary.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        evidence.verify(tmp_path)


def test_report_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output_dir = tmp_path / "outputs"
    report_dir = tmp_path / "reports"
    evidence.generate(output_dir)
    monkeypatch.setattr(evidence, "OUTPUT_PATH", output_dir)
    monkeypatch.setattr(evidence, "REPORT_PATH", report_dir)
    written = evidence.report()
    assert {path.name for path in written} == {
        "developer-enablement-report.md",
        "developer-onboarding-report.md",
        "developer-security-workflow-report.md",
        "pull-request-security-report.md",
        "security-tooling-readiness-report.md",
    }
    assert "Developer Enablement Report" in (
        report_dir / "developer-enablement-report.md"
    ).read_text(encoding="utf-8")


def test_current_documentation_validates_after_report_generation(tmp_path: Path) -> None:
    evidence.generate()
    evidence.report()
    evidence.validate_docs()
