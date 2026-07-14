import json
from importlib import util
from pathlib import Path
from types import ModuleType

import pytest

from genomic_research_access_api.security.appsec.config import (
    Suppression,
    validate_suppressions,
)
from genomic_research_access_api.security.appsec.evidence import (
    generate_evidence,
    generate_minimal_sbom,
    pipeline_summary,
    verify_evidence,
)
from genomic_research_access_api.security.appsec.parsers import (
    bandit_summary,
    checkov_summary,
    gitleaks_summary,
    pip_audit_summary,
    semgrep_summary,
    trivy_summary,
    validate_cyclonedx,
)
from genomic_research_access_api.security.appsec.report import generate_reports
from genomic_research_access_api.security.threat_model.validation import ThreatModelValidationError


def appsec_tools_module() -> ModuleType:
    spec = util.spec_from_file_location("appsec_tools", "scripts/appsec_tools.py")
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_fixture_results(tmp_path: Path) -> Path:
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    fixtures = Path("security/fixtures/scanner-results")
    for fixture in fixtures.glob("*.json"):
        (raw / fixture.name).write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    return raw


def test_suppression_register_is_valid_and_narrow() -> None:
    suppressions = validate_suppressions()

    assert suppressions[0].resource_or_path == "tests/fixtures/keys/dev_private_key.pem"
    assert suppressions[0].tool == "gitleaks"


def test_suppression_rejects_expired_and_wildcard_scope() -> None:
    with pytest.raises(ValueError):
        Suppression.model_validate(
            {
                "suppression_id": "bad",
                "tool": "gitleaks",
                "rule_or_advisory_id": "private-key",
                "resource_or_path": "*",
                "reason": "bad",
                "owner": "owner",
                "approved_by": "owner",
                "created_date": "2026-01-01",
                "review_date": "2026-01-02",
                "expiry_date": "2025-01-01",
                "compensating_control": "none",
                "status": "active",
            }
        )


def test_scanner_parsers_handle_blocking_fixture_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = copy_fixture_results(tmp_path)
    monkeypatch.setattr("genomic_research_access_api.security.appsec.parsers.RAW_DIR", raw)

    assert gitleaks_summary()["blocking_count"] == 1
    assert semgrep_summary()["blocking_count"] == 1
    assert bandit_summary()["blocking_count"] == 1
    assert pip_audit_summary()["blocking_count"] == 1
    assert checkov_summary()["blocking_count"] == 1
    assert trivy_summary()["blocking_count"] == 1


def test_scanner_parsers_report_missing_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("genomic_research_access_api.security.appsec.parsers.RAW_DIR", tmp_path)

    summaries = [
        gitleaks_summary(),
        semgrep_summary(),
        bandit_summary(),
        pip_audit_summary(),
        checkov_summary(),
        trivy_summary(),
    ]

    assert {summary["execution_status"] for summary in summaries} == {"not_run"}
    assert {summary["policy_decision"] for summary in summaries} == {"not_evaluated"}


def test_pipeline_summary_blocks_on_incomplete_scans() -> None:
    summaries = {
        "secret-scan-summary.json": {
            "tool": "gitleaks",
            "execution_status": "not_run",
            "blocking_count": 0,
        },
        "container-scan-summary.json": {
            "tool": "trivy",
            "execution_status": "completed",
            "blocking_count": 0,
        },
    }

    summary = pipeline_summary(summaries)

    assert summary["not_run"] == ["gitleaks"]
    assert summary["policy_decision"] == "not_evaluated"


def test_insecure_and_remediated_fixtures_are_scoped() -> None:
    insecure = Path("security/fixtures/insecure/unsafe_subprocess.py").read_text(encoding="utf-8")
    remediated = Path("security/fixtures/remediated/safe_subprocess.py").read_text(encoding="utf-8")

    assert "shell=True" in insecure
    assert "shell=True" not in remediated
    assert "block_public_policy     = false" in Path(
        "security/fixtures/insecure/public_s3.tf"
    ).read_text(encoding="utf-8")
    assert "block_public_policy     = true" in Path(
        "security/fixtures/remediated/private_s3.tf"
    ).read_text(encoding="utf-8")


def test_sbom_generation_and_validation(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    generate_minimal_sbom(sbom)
    details = validate_cyclonedx(sbom)
    payload = json.loads(sbom.read_text(encoding="utf-8"))

    assert payload["bomFormat"] == "CycloneDX"
    assert details["component_count"] >= 4


def test_cyclonedx_sbom_normalisation_removes_local_file_references(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {
                        "type": "application",
                        "name": "genomic-research-access-api",
                        "externalReferences": [
                            {
                                "type": "website",
                                "url": "file:///Users/example/project",
                            }
                        ],
                    },
                    {"type": "library", "name": "fastapi"},
                ],
            }
        ),
        encoding="utf-8",
    )

    appsec_tools_module().normalize_sbom(sbom)
    details = validate_cyclonedx(sbom)
    payload = json.loads(sbom.read_text(encoding="utf-8"))

    assert "externalReferences" not in payload["components"][0]
    assert details["component_count"] == 2


def test_appsec_evidence_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    generate_evidence(first, timestamp="2026-01-01T00:00:00Z")
    generate_evidence(second, timestamp="2026-01-01T00:00:00Z")

    first_manifest = json.loads((first / "evidence-manifest.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((second / "evidence-manifest.json").read_text(encoding="utf-8"))
    assert first_manifest["output_files"] == second_manifest["output_files"]
    verify_evidence(first)


def test_appsec_evidence_verification_rejects_missing_or_tampered_outputs(tmp_path: Path) -> None:
    with pytest.raises(ThreatModelValidationError, match="manifest does not exist"):
        verify_evidence(tmp_path / "missing")

    evidence_dir = tmp_path / "evidence"
    generate_evidence(evidence_dir, timestamp="2026-01-01T00:00:00Z")
    (evidence_dir / "secret-scan-summary.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ThreatModelValidationError, match="checksum mismatch"):
        verify_evidence(evidence_dir)


def test_appsec_reports_are_generated_from_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "evidence"
    report_dir = tmp_path / "reports"
    generate_evidence(evidence_dir, timestamp="2026-01-01T00:00:00Z")
    monkeypatch.setattr(
        "genomic_research_access_api.security.appsec.report.APPSEC_OUTPUT_DIR", evidence_dir
    )

    reports = generate_reports(report_dir)

    assert {path.name for path in reports} == {
        "appsec-pipeline-report.md",
        "container-security-report.md",
        "dependency-security-report.md",
        "iac-security-report.md",
        "sast-report.md",
        "sbom-report.md",
        "secret-scanning-report.md",
    }
    assert "AppSec Pipeline Report" in (report_dir / "appsec-pipeline-report.md").read_text(
        encoding="utf-8"
    )


def test_appsec_report_rejects_non_object_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = tmp_path / "evidence"
    report_dir = tmp_path / "reports"
    evidence_dir.mkdir()
    (evidence_dir / "secret-scan-summary.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "genomic_research_access_api.security.appsec.report.APPSEC_OUTPUT_DIR", evidence_dir
    )

    with pytest.raises(ValueError):
        generate_reports(report_dir)
