from __future__ import annotations

import json
from pathlib import Path

import pytest

from genomic_research_access_api.security.dynamic.config import MANIFEST_PATH, validate_local_target
from genomic_research_access_api.security.dynamic.evidence import (
    build_evidence,
    verify_evidence,
)
from genomic_research_access_api.security.dynamic.parsers import (
    pytest_summary,
    schemathesis_summary,
    zap_summary,
)
from genomic_research_access_api.security.dynamic.report import generate_reports


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_local_target_validation_rejects_external_hosts() -> None:
    assert validate_local_target("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert validate_local_target("http://localhost:8000") == "http://localhost:8000"
    with pytest.raises(ValueError):
        validate_local_target("https://www.genomicsengland.co.uk")
    with pytest.raises(ValueError):
        validate_local_target("http://example.com")


def test_pytest_summary_groups_dynamic_categories(tmp_path: Path) -> None:
    raw = tmp_path / "pytest.json"
    write_json(
        raw,
        {
            "exitcode": 0,
            "summary": {"total": 1, "passed": 1},
            "tests": [
                {
                    "nodeid": "tests/dynamic/test_dynamic_api_security.py::test_cors_controls",
                    "outcome": "passed",
                }
            ],
        },
    )
    summary = pytest_summary(raw)
    assert summary["execution_status"] == "completed"
    assert summary["categories"][0]["category"] == "cors"
    assert summary["categories"][0]["failed"] == 0


def test_schemathesis_summary_blocks_failed_checks(tmp_path: Path) -> None:
    raw = tmp_path / "schemathesis.json"
    write_json(
        raw,
        {
            "execution_status": "completed",
            "checks": [{"name": "not_a_server_error", "outcome": "failed"}],
        },
    )
    assert schemathesis_summary(raw)["policy_decision"] == "fail"


def test_zap_summary_blocks_high_alerts(tmp_path: Path) -> None:
    raw = tmp_path / "zap.json"
    write_json(
        raw,
        {
            "site": [{"alerts": [{"riskdesc": "High (Medium)", "alert": "Example"}]}],
            "execution_status": "completed",
        },
    )
    summary = zap_summary(raw)
    assert summary["alerts_by_risk"]["High"] == 1
    assert summary["policy_decision"] == "fail"


def test_dynamic_evidence_verification_and_tamper_detection() -> None:
    build_evidence("2026-01-01T00:00:00Z")
    verify_evidence()
    original = MANIFEST_PATH.read_text(encoding="utf-8")
    manifest = json.loads(original)
    manifest["files"][0]["sha256"] = "0" * 64
    MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        with pytest.raises(SystemExit):
            verify_evidence()
    finally:
        MANIFEST_PATH.write_text(original, encoding="utf-8")
    verify_evidence()


def test_dynamic_report_generation() -> None:
    build_evidence("2026-01-01T00:00:00Z")
    generate_reports()
    assert Path("reports/security/dynamic-security-report.md").exists()
    assert Path("reports/security/zap-report.md").exists()
