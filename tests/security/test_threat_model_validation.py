import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from genomic_research_access_api.security.threat_model import validation
from genomic_research_access_api.security.threat_model.evidence import (
    generate_evidence,
    verify_evidence,
)
from genomic_research_access_api.security.threat_model.evidence import (
    main as evidence_main,
)
from genomic_research_access_api.security.threat_model.io import SOURCE_FILES, load_json_yaml
from genomic_research_access_api.security.threat_model.report import generate_reports
from genomic_research_access_api.security.threat_model.report import main as report_main
from genomic_research_access_api.security.threat_model.validate import main as validate_main
from genomic_research_access_api.security.threat_model.validation import (
    ThreatModelValidationError,
    validate_threat_model,
)


@pytest.fixture
def isolated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    copied: dict[str, Path] = {}
    for name, source in SOURCE_FILES.items():
        destination = tmp_path / source.name
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        copied[name] = destination
    monkeypatch.setattr(validation, "SOURCE_FILES", copied)
    return copied


@contextmanager
def _mutate_source(path: Path) -> Iterator[list[dict[str, Any]]]:
    records = load_json_yaml(path)
    assert isinstance(records, list)
    yield records
    path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_committed_threat_model_passes_validation() -> None:
    model = validate_threat_model()

    assert len(model.threats) == 30
    assert len(model.requirements) == 56
    assert len(model.assets) == 18


def test_duplicate_id_rejected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["threats"]) as threats:
        threats[1]["threat_id"] = threats[0]["threat_id"]

    with pytest.raises(ThreatModelValidationError, match="Duplicate threat_id"):
        validate_threat_model()


def test_invalid_reference_rejected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["threats"]) as threats:
        threats[0]["asset_ids"] = ["ASSET-DOES-NOT-EXIST"]

    with pytest.raises(ThreatModelValidationError, match="unknown assets"):
        validate_threat_model()


def test_orphaned_threat_detected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["requirements"]) as requirements:
        for requirement in requirements:
            requirement["source_threat_ids"] = [
                threat_id
                for threat_id in requirement.get("source_threat_ids", [])
                if threat_id != "THR-API-001"
            ]
    with _mutate_source(isolated_sources["traceability"]) as links:
        links[:] = [link for link in links if link["threat_id"] != "THR-API-001"]

    with pytest.raises(ThreatModelValidationError, match="THR-API-001"):
        validate_threat_model()


def test_orphaned_requirement_detected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["requirements"]) as requirements:
        requirements[0]["source_threat_ids"] = []
        requirements[0]["policy_source"] = None

    with pytest.raises(ThreatModelValidationError, match="SR-API-001"):
        validate_threat_model()


def test_invalid_risk_rating_rejected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["residual_risks"]) as risks:
        risks[0]["residual_rating"] = "urgent"

    with pytest.raises(ThreatModelValidationError, match="schema validation"):
        validate_threat_model()


def test_invalid_milestone_reference_rejected(isolated_sources: dict[str, Path]) -> None:
    with _mutate_source(isolated_sources["requirements"]) as requirements:
        requirements[0]["planned_milestone"] = "Milestone 99"

    with pytest.raises(ThreatModelValidationError, match="known portfolio milestone"):
        validate_threat_model()


def test_missing_implementation_reference_rejected(
    isolated_sources: dict[str, Path],
) -> None:
    with _mutate_source(isolated_sources["requirements"]) as requirements:
        requirements[0]["implementation_reference"] = ""

    with pytest.raises(ThreatModelValidationError, match="implemented control lacks reference"):
        validate_threat_model()


def test_deterministic_evidence_generation(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    generate_evidence(first, timestamp="2026-01-01T00:00:00Z")
    generate_evidence(second, timestamp="2026-01-01T00:00:00Z")

    for first_file in sorted(first.glob("*.json")):
        second_file = second / first_file.name
        assert first_file.read_text(encoding="utf-8") == second_file.read_text(encoding="utf-8")


def test_checksum_verification(tmp_path: Path) -> None:
    generate_evidence(tmp_path, timestamp="2026-01-01T00:00:00Z")

    verify_evidence(tmp_path)


def test_stable_json_ordering(tmp_path: Path) -> None:
    generate_evidence(tmp_path, timestamp="2026-01-01T00:00:00Z")

    summary_text = (tmp_path / "threat-model-summary.json").read_text(encoding="utf-8")
    assert summary_text.index('"orphaned_requirements"') < summary_text.index('"total_threats"')


def test_report_generation(tmp_path: Path) -> None:
    reports = generate_reports(tmp_path)

    assert {path.name for path in reports} == {
        "control-traceability-report.md",
        "residual-risk-report.md",
        "security-requirements-report.md",
        "threat-model-report.md",
    }
    assert "THR-AUTH-002" in (tmp_path / "threat-model-report.md").read_text(encoding="utf-8")


def test_cli_entry_points_smoke(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    validate_main()
    assert "Threat model validation passed" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["evidence", "--verify"])
    evidence_main()

    report_main()
