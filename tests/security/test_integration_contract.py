from __future__ import annotations

import json
import shutil
import subprocess
from importlib import util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from genomic_research_access_api.security.integration.cli import main as integration_cli
from genomic_research_access_api.security.integration.config import OUTPUT_DIR
from genomic_research_access_api.security.integration.enums import (
    CompatibilityStatus,
    ConsumerStatus,
)
from genomic_research_access_api.security.integration.exporter import generate_bundle
from genomic_research_access_api.security.integration.mappings import (
    map_status,
    stable_export_record_id,
)
from genomic_research_access_api.security.integration.reporting import generate_reports
from genomic_research_access_api.security.integration.validator import (
    _validate_csv,
    validate_export,
    validate_policy,
)
from genomic_research_access_api.security.integration.verifier import verify


def test_policy_validation_and_current_export_bundle() -> None:
    assert validate_policy()["valid"] is True
    generate_bundle(timestamp="2026-01-01T00:00:00Z", as_of_date="2026-01-01")
    summary = validate_export()
    assert summary["valid"] is True
    manifest = _read_json(OUTPUT_DIR / "integration-manifest.json")
    findings = _read_json(OUTPUT_DIR / "product-security-findings.json")["findings"]
    assert manifest["contract_name"] == "product-security-control-plane-export"
    assert manifest["contract_version"] == "1.0"
    assert manifest["record_count"] == 44
    assert manifest["source_finding_count"] == 46
    assert manifest["lifecycle_record_count"] == 44
    assert manifest["exception_count"] == 3
    assert manifest["verification_record_count"] == 0
    assert len(findings) == 44
    assert {record["release_decision"] for record in findings} == {"conditional_pass"}


def test_stable_export_id_and_mappings() -> None:
    finding_id = "FND-CONTAINER-026cbd40a3d8"
    assert stable_export_record_id(finding_id) == stable_export_record_id(finding_id)
    assert stable_export_record_id(finding_id).startswith("EXP-")
    assert len(stable_export_record_id(finding_id)) == 16
    assert map_status("triaged") == "triaged"
    assert map_status("suppressed") == "deferred"
    assert map_status("risk_accepted") == "risk_accepted"


def test_records_preserve_required_security_context() -> None:
    generate_bundle(timestamp="2026-01-01T00:00:00Z", as_of_date="2026-01-01")
    findings = _read_json(OUTPUT_DIR / "product-security-findings.json")["findings"]
    by_id = {record["finding_id"]: record for record in findings}
    assert all(record["source_finding_ids"] for record in findings)
    assert any(record["suppression_status"] for record in findings)
    assert any(record["consumer_status"] == "risk_accepted" for record in findings)
    assert all(
        record["exception_id"]
        for record in findings
        if record["consumer_status"] == "risk_accepted"
    )
    assert by_id["FND-CONTAINER-026cbd40a3d8"]["source_tools"] == ["trivy"]
    assert by_id["FND-CONTAINER-026cbd40a3d8"]["release_impact"] == "conditional_pass"


def test_lineage_control_metrics_and_reports() -> None:
    generate_bundle(timestamp="2026-01-01T00:00:00Z", as_of_date="2026-01-01")
    lineage = _read_json(OUTPUT_DIR / "finding-source-lineage.json")["lineage_edges"]
    traceability = _read_json(OUTPUT_DIR / "control-traceability.json")["records"]
    metrics = _read_json(OUTPUT_DIR / "security-metrics.json")
    assert len(lineage) == 178
    assert len(traceability) == 44
    assert metrics["total_exported_findings"] == 44
    assert metrics["suppressed_findings"] == 14
    assert metrics["risk_accepted_findings"] == 2
    reports = generate_reports()
    assert {path.name for path in reports} == {
        "integration-compatibility-report.md",
        "integration-data-quality-report.md",
        "integration-lineage-report.md",
        "product-security-export-report.md",
        "repository-5-integration-report.md",
    }


def test_verify_and_sample_consumer_validation() -> None:
    generate_bundle(timestamp="2026-01-01T00:00:00Z", as_of_date="2026-01-01")
    assert verify()["valid"] is True
    result = subprocess.run(
        [
            "python3",
            "examples/integration-consumer/validate_bundle.py",
            "outputs/security/integration",
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0
    assert "validated 44 product-security records" in result.stdout


def test_integration_cli_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    assert ConsumerStatus.RISK_ACCEPTED.value == "risk_accepted"
    assert CompatibilityStatus.COMPATIBLE.value == "compatible"
    for command in [
        "validate-policy",
        "export",
        "validate-export",
        "verify",
        "report",
        "full",
    ]:
        monkeypatch.setattr(sys, "argv", ["integration", command])
        integration_cli()


def test_tampered_checksum_is_rejected(tmp_path: Path) -> None:
    bundle = _bundle_copy(tmp_path)
    path = bundle / "product-security-findings.json"
    payload = _read_json(path)
    payload["findings"][0]["title"] = "tampered"
    _write_json(path, payload)
    summary = validate_export(bundle)
    assert summary["valid"] is False
    assert any("checksum mismatch" in error for error in summary["errors"])


def test_invalid_contract_duplicate_ids_and_missing_field_rejected(tmp_path: Path) -> None:
    bundle = _bundle_copy(tmp_path)
    manifest = _read_json(bundle / "integration-manifest.json")
    manifest["contract_version"] = "9.9"
    _write_json(bundle / "integration-manifest.json", manifest)
    payload = _read_json(bundle / "product-security-findings.json")
    payload["findings"][1]["export_record_id"] = payload["findings"][0]["export_record_id"]
    payload["findings"][2]["finding_id"] = payload["findings"][0]["finding_id"]
    del payload["findings"][3]["source_record_hash"]
    _write_json(bundle / "product-security-findings.json", payload)
    errors = validate_export(bundle)["errors"]
    assert any("contract_version mismatch" in error for error in errors)
    assert "duplicate export_record_id values" in errors
    assert "duplicate finding_id values" in errors
    assert any("schema error" in error for error in errors)


def test_invalid_status_owner_secret_and_local_path_rejected(tmp_path: Path) -> None:
    bundle = _bundle_copy(tmp_path)
    payload = _read_json(bundle / "product-security-findings.json")
    payload["findings"][0]["lifecycle_status"] = "invented"
    payload["findings"][1]["remediation_owner"] = "person@example.com"
    payload["findings"][2]["description"] = "blocked-sensitive-marker"
    payload["findings"][3]["file"] = "/Users/example/project/app.py"
    _write_json(bundle / "product-security-findings.json", payload)
    errors = validate_export(bundle)["errors"]
    assert any("invalid lifecycle status" in error for error in errors)
    assert any("invalid owner value" in error for error in errors)
    assert any("email address detected" in error for error in errors)
    assert any("secret-like value detected" in error for error in errors)
    assert any("local path detected" in error for error in errors)


def test_metric_and_lineage_mismatch_rejected(tmp_path: Path) -> None:
    bundle = _bundle_copy(tmp_path)
    metrics = _read_json(bundle / "security-metrics.json")
    metrics["total_exported_findings"] = 1
    _write_json(bundle / "security-metrics.json", metrics)
    lineage = _read_json(bundle / "finding-source-lineage.json")
    lineage["lineage_edges"][0]["checksum"] = "bad"
    _write_json(bundle / "finding-source-lineage.json", lineage)
    errors = validate_export(bundle)["errors"]
    assert "metrics total_exported_findings mismatch" in errors
    assert any("lineage checksum mismatch" in error for error in errors)


def test_missing_manifest_and_consumer_unsupported_version(tmp_path: Path) -> None:
    bundle = _bundle_copy(tmp_path)
    (bundle / "integration-manifest.json").unlink()
    assert validate_export(bundle)["errors"] == ["missing integration-manifest.json"]
    bundle = _bundle_copy(tmp_path / "unsupported")
    manifest = _read_json(bundle / "integration-manifest.json")
    manifest["contract_version"] = "9.9"
    _write_json(bundle / "integration-manifest.json", manifest)
    spec = util.spec_from_file_location(
        "sample_consumer",
        "examples/integration-consumer/validate_bundle.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = util.module_from_spec(spec)
    assert isinstance(module, ModuleType)
    spec.loader.exec_module(module)
    assert "unsupported contract version" in module.validate_bundle(bundle)["errors"]


def test_safe_csv_formula_injection_detection(tmp_path: Path) -> None:
    csv_path = tmp_path / "unsafe.csv"
    csv_path.write_text("name,value\nok,=cmd\n", encoding="utf-8", newline="\n")
    assert "CSV contains an unsafe formula prefix" in _validate_csv(csv_path)


def _bundle_copy(tmp_path: Path) -> Path:
    generate_bundle(timestamp="2026-01-01T00:00:00Z", as_of_date="2026-01-01")
    target = tmp_path / "bundle"
    shutil.copytree(OUTPUT_DIR, target)
    return target


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
