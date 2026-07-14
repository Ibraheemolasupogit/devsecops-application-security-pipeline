import json
from pathlib import Path
from typing import Any

import pytest

from genomic_research_access_api.security.champions import evidence, reporting
from genomic_research_access_api.security.champions.cli import main
from genomic_research_access_api.security.champions.config import CONFIG_DIR
from genomic_research_access_api.security.champions.inventory import validate_programme
from genomic_research_access_api.security.champions.maturity import maturity_assessment
from genomic_research_access_api.security.champions.metrics import (
    champion_metrics,
    squad_coverage,
    workshop_completion,
    workshop_inventory,
)
from genomic_research_access_api.security.champions.models import (
    ChampionModel,
    MetricDefinitionModel,
    SquadModel,
)
from genomic_research_access_api.security.champions.verify import verify


def test_programme_policy_validates() -> None:
    result = validate_programme()
    assert result["valid"] is True


def test_duplicate_champion_id_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy_config(tmp_path)
    roster = read(tmp_path / "champion-roster.yaml")
    roster["champions"][1]["champion_id"] = roster["champions"][0]["champion_id"]
    write(tmp_path / "champion-roster.yaml", roster)
    monkeypatch.setattr(
        "genomic_research_access_api.security.champions.config.CONFIG_DIR", tmp_path
    )
    with pytest.raises(ValueError, match="duplicate champion_id"):
        validate_programme()


def test_unknown_squad_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy_config(tmp_path)
    roster = read(tmp_path / "champion-roster.yaml")
    roster["champions"][0]["squad_id"] = "SQUAD-UNKNOWN"
    write(tmp_path / "champion-roster.yaml", roster)
    monkeypatch.setattr(
        "genomic_research_access_api.security.champions.config.CONFIG_DIR", tmp_path
    )
    with pytest.raises(ValueError, match="unknown squad"):
        validate_programme()


def test_invalid_status_and_onboarding_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copy_config(tmp_path)
    roster = read(tmp_path / "champion-roster.yaml")
    roster["champions"][0]["status"] = "hero"
    roster["champions"][0]["onboarding_status"] = "done"
    write(tmp_path / "champion-roster.yaml", roster)
    monkeypatch.setattr(
        "genomic_research_access_api.security.champions.config.CONFIG_DIR", tmp_path
    )
    with pytest.raises(ValueError, match="invalid"):
        validate_programme()


def test_invalid_backup_champion_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy_config(tmp_path)
    roster = read(tmp_path / "champion-roster.yaml")
    roster["champions"][0]["backup_champion"] = "CHAMP-NOPE"
    write(tmp_path / "champion-roster.yaml", roster)
    monkeypatch.setattr(
        "genomic_research_access_api.security.champions.config.CONFIG_DIR", tmp_path
    )
    with pytest.raises(ValueError, match="unknown backup champion"):
        validate_programme()


def test_champion_coverage_and_vacant_squads() -> None:
    coverage = squad_coverage()
    assert coverage["squad_count"] == 5
    assert coverage["covered_squad_count"] == 4
    assert coverage["champion_coverage_percentage"] == 100.0
    assert coverage["squads_without_champion"] == []


def test_metrics_derive_from_current_evidence() -> None:
    metrics = champion_metrics()
    assert metrics["findings_by_squad"]["Platform Engineering"] > 0
    assert metrics["owner_assignment_rate"] == 100.0
    assert "Container" in metrics["repeated_vulnerability_categories"]
    assert isinstance(metrics["overdue_findings_by_squad"], dict)
    assert metrics["exception_review_completion_rate"] == 100.0


def test_workshop_inventory_and_completion() -> None:
    inventory = workshop_inventory()
    completion = workshop_completion()
    assert inventory["workshop_count"] == 6
    assert completion["champion_count"] == 4
    assert completion["records"][0]["demonstration_data"] is True


def test_maturity_assessment_is_area_based() -> None:
    assessment = maturity_assessment()
    assert assessment["assessment_mode"].startswith("area-based")
    assert len(assessment["areas"]) == 6
    assert all("assessed_level" in area for area in assessment["areas"])


def test_escalation_criteria_present() -> None:
    summary = evidence.escalation_summary()
    assert summary["criterion_count"] >= 8
    assert any(item["trigger"] == "critical secret" for item in summary["criteria"])


def test_deterministic_evidence_and_manifest_verification(tmp_path: Path) -> None:
    first = evidence.generate(tmp_path)
    first_payloads = {path.name: path.read_text(encoding="utf-8") for path in first}
    second = evidence.generate(tmp_path)
    assert first_payloads == {path.name: path.read_text(encoding="utf-8") for path in second}
    evidence.verify(tmp_path)


def test_tampered_manifest_rejected(tmp_path: Path) -> None:
    evidence.generate(tmp_path)
    (tmp_path / "programme-summary.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        evidence.verify(tmp_path)


def test_report_generation(tmp_path: Path) -> None:
    evidence.generate(tmp_path / "out")
    written = reporting.generate_reports(tmp_path / "out", tmp_path / "reports")
    assert {path.name for path in written} == {
        "security-champions-report.md",
        "champion-coverage-report.md",
        "champion-maturity-report.md",
        "champion-workshop-report.md",
        "champion-escalation-report.md",
    }


def test_current_repository_evidence_integrates_successfully() -> None:
    generated = evidence.generate()
    evidence.verify()
    assert any(path.name == "champion-metrics.json" for path in generated)


def test_typed_models_accept_synthetic_records() -> None:
    champion = ChampionModel(
        champion_id="CHAMP-TEST-001",
        squad_id="SQUAD-APP",
        role="Software Engineer",
        status="active",
        onboarding_status="complete",
        start_date="2026-01-01",
        review_date="2026-04-01",
        workshops_completed=["WS-THREAT-MODEL"],
    )
    squad = SquadModel(
        squad_id="SQUAD-TEST",
        name="Application Engineering",
        engineering_area="application",
        champion_required=True,
    )
    metric = MetricDefinitionModel(
        metric_id="MET-TEST",
        name="Test metric",
        description="A test metric.",
        calculation="count",
        evidence_sources=["outputs/security/champions/champion-metrics.json"],
        anti_gaming_guardrail="Do not hide findings.",
    )
    assert champion.synthetic_record is True
    assert squad.champion_required is True
    assert metric.metric_id == "MET-TEST"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("validate-policy", "validated Security Champions programme policy"),
        ("metrics", "calculated Security Champions metrics"),
        ("generate-evidence", "generated 10 Security Champions evidence files"),
        ("verify-evidence", "verified Security Champions evidence"),
        ("report", "generated 5 Security Champions reports"),
        ("full", "completed Security Champions workflow"),
    ],
)
def test_cli_commands(
    command: str, expected: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["champions", command])
    main()
    assert expected in capsys.readouterr().out


def test_verify_module_reexports_evidence_verifier() -> None:
    evidence.generate()
    verify()


def copy_config(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for path in CONFIG_DIR.glob("*.yaml"):
        (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def read(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
