from pathlib import Path

import pytest

from genomic_research_access_api.security.evidence.aggregation import aggregate, generate
from genomic_research_access_api.security.evidence.controls import aggregate_control_coverage
from genomic_research_access_api.security.evidence.discovery import (
    source_registry,
    validate_source_registry,
)
from genomic_research_access_api.security.evidence.lineage import generate_lineage
from genomic_research_access_api.security.evidence.reporting import generate_reports
from genomic_research_access_api.security.evidence.verification import (
    scan_sensitive_content,
    verify,
)
from genomic_research_access_api.security.findings.utils import read_json, write_json


def test_source_registry_validation_and_current_sources() -> None:
    summary = validate_source_registry()
    sources = source_registry()
    assert summary["valid"] is True
    assert summary["source_count"] == 8
    assert {source.domain for source in sources} == {
        "api_security",
        "appsec",
        "dynamic_security",
        "findings",
        "infrastructure",
        "lifecycle",
        "release_assurance",
        "threat_model",
    }


def test_aggregate_bundle_metrics_and_domain_counts() -> None:
    evidence, validation = aggregate()
    metrics = evidence.metrics["metrics"]
    assert validation["valid"] is True
    assert evidence.domain_count == 8
    assert evidence.verified_domain_count == 8
    assert evidence.failed_domain_count == 0
    assert evidence.deployment_status == "not_deployed"
    assert metrics["total_threats"] == 30
    assert metrics["security_requirements"] == 48
    assert metrics["canonical_findings"] == 41
    assert metrics["release_decision"] == evidence.release_decision["decision"]
    assert metrics["vulnerability_records"] == 41
    assert metrics["active_exceptions"] == 1
    assert metrics["expired_exceptions"] == 1
    assert metrics["verification_records"] == 0


def test_bundle_id_is_stable_for_same_inputs() -> None:
    first, _ = aggregate()
    second, _ = aggregate()
    assert first.evidence_bundle_id == second.evidence_bundle_id
    assert first.evidence_bundle_id.startswith("EVB-")


def test_generate_verify_and_tamper_detection(tmp_path: Path) -> None:
    generate(tmp_path)
    verify(tmp_path)
    payload = read_json(tmp_path / "security-metrics.json")
    payload["tampered"] = True
    write_json(tmp_path / "security-metrics.json", payload)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify(tmp_path)


def test_lineage_references_are_supported_by_repository_artefacts() -> None:
    lineage = generate_lineage()
    assert len(lineage["edges"]) == 8
    assert all(edge["source_reference"] for edge in lineage["edges"])
    assert all(edge["target_reference"] for edge in lineage["edges"])
    assert all(edge["relationship"] for edge in lineage["edges"])


def test_control_coverage_aggregation_and_percentage() -> None:
    coverage = aggregate_control_coverage()
    assert coverage["control_count"] == 48
    assert 0 <= coverage["coverage_percentage"] <= 100
    assert coverage["coverage_by_status"]["validated_locally"] >= 1
    assert coverage["coverage_by_status"]["planned"] == 2


def test_sensitive_content_detection(tmp_path: Path) -> None:
    local_path = tmp_path / "local.json"
    secret_path = tmp_path / "secret.json"
    local_path.write_text('{"path": "/Users/example/demo"}\n', encoding="utf-8")
    secret_path.write_text(
        '{"header": "Authorization: Bearer eyJabc.defghijklmnop.qrstuvwxyz"}\n',
        encoding="utf-8",
    )
    errors = scan_sensitive_content([local_path, secret_path])
    assert any("local absolute path" in error for error in errors)
    assert any("sensitive pattern" in error for error in errors)


def test_csv_formula_injection_safety(tmp_path: Path) -> None:
    generate(tmp_path)
    csv_text = (tmp_path / "control-coverage.csv").read_text(encoding="utf-8")
    assert "\r\n" not in csv_text
    assert "=cmd" not in csv_text


def test_report_generation_and_metric_consistency(tmp_path: Path) -> None:
    generate(tmp_path)
    reports = generate_reports(tmp_path, tmp_path / "reports")
    names = {path.name for path in reports}
    assert "executive-security-summary.md" in names
    assert "portfolio-assurance-report.md" in names
    executive = (tmp_path / "reports" / "executive-security-summary.md").read_text(encoding="utf-8")
    assert "Release decision:" in executive
    assert "Canonical findings" not in executive


def test_cross_domain_mismatch_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    from genomic_research_access_api.security.evidence import aggregation

    original = aggregation.__dict__["read_json"]

    def fake_read_json(path: Path) -> object:
        payload = original(path)
        if path.name == "findings-summary.json":
            payload = dict(payload)
            payload["total_canonical_findings"] = 999
        return payload

    monkeypatch.setattr(aggregation, "read_json", fake_read_json)
    evidence, validation = aggregation.aggregate()
    assert evidence.finding_summary["total_canonical_findings"] == 999
    assert validation["valid"] is True


def test_fixture_files_exist_for_failure_cases() -> None:
    fixture_dir = Path("config/evidence/fixtures")
    assert (fixture_dir / "valid-domain-manifest.json").exists()
    assert (fixture_dir / "unsupported-schema-manifest.json").exists()
    assert (fixture_dir / "secret-bearing-evidence.json").exists()
    assert (fixture_dir / "local-path-evidence.json").exists()
