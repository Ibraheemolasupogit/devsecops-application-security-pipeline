from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from scripts.dynamic_security_tools import (
    DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
    DYNAMIC_SCANNER_WARMUP_PATHS,
    print_schemathesis_failure_summary,
    redact_command,
    schemathesis_failures,
    schemathesis_payload,
    warm_dynamic_routes,
)

from genomic_research_access_api.config import get_settings
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


def test_schemathesis_warning_only_result_is_completed() -> None:
    payload, completed = schemathesis_payload(
        """
Schemathesis v4.0.26
API Operations:
  Selected: 9/9
Warnings:
  ⚠️ Missing authentication: 3 operations returned only 401/403 responses
Test cases:
  64 generated, 64 passed
""",
        1,
    )

    assert completed is True
    assert payload["execution_status"] == "completed"
    assert payload["scanner_exit_code"] == 1
    assert payload["case_count"] == 64
    assert payload["operation_count"] == 9
    checks = cast(list[dict[str, Any]], payload["checks"])
    assert checks[0]["outcome"] == "passed"
    assert payload["warnings"]


def test_schemathesis_failed_cases_remain_blocking() -> None:
    payload, completed = schemathesis_payload(
        """
API Operations:
  Selected: 9/9
Test cases:
  64 generated, 4 found 4 unique failures
""",
        1,
    )

    assert completed is False
    assert payload["execution_status"] == "failed"
    assert payload["case_count"] == 64
    assert payload["failed_case_count"] == 4
    assert payload["distinct_failure_count"] == 4
    checks = cast(list[dict[str, Any]], payload["checks"])
    assert checks[0]["outcome"] == "failed"


def test_scripts_package_imports_from_repository_root() -> None:
    module = importlib.import_module("scripts.dynamic_security_tools")

    assert module.__name__ == "scripts.dynamic_security_tools"


def test_python_subprocess_imports_scripts_package_from_repository_root() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import scripts.dynamic_security_tools"],
        cwd=Path.cwd(),
        env=os.environ | {"PYTHONPATH": os.pathsep.join([".", "src"])},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_schemathesis_failure_detail_parsing_is_sanitised() -> None:
    failures = schemathesis_failures(
        """
=================================== FAILURES ===================================
_____________________________ GET /api/v1/datasets _____________________________
1. Test Case ID: AbCd12

- Response schema conformance failed

[200] OK:

    `{"dataset_id": 1}`

Reproduce with:

    curl -X GET -H 'Authorization: Bearer secret-token' http://host.docker.internal:8000/api/v1/datasets

___________________ POST /api/v1/access-requests ___________________
1. Test Case ID: EfGh34

- Content-Type does not match the documented media type

[422] Unprocessable Entity:

Reproduce with:

    curl -X POST -H 'Authorization: Bearer second-secret' http://host.docker.internal:8000/api/v1/access-requests
"""
    )

    assert failures == [
        {
            "method": "GET",
            "path": "/api/v1/datasets",
            "test_case_id": "AbCd12",
            "failed_check": "response_schema_conformance",
            "failure_message": "Response schema conformance failed",
            "response_status": "[200] OK",
            "reproduction_command": (
                "curl -X GET -H 'Authorization: <redacted>' "
                "http://host.docker.internal:8000/api/v1/datasets"
            ),
        },
        {
            "method": "POST",
            "path": "/api/v1/access-requests",
            "test_case_id": "EfGh34",
            "failed_check": "content_type_conformance",
            "failure_message": "Content-Type does not match the documented media type",
            "response_status": "[422] Unprocessable Entity",
            "reproduction_command": (
                "curl -X POST -H 'Authorization: <redacted>' "
                "http://host.docker.internal:8000/api/v1/access-requests"
            ),
        },
    ]


def test_schemathesis_failure_summary_prints_bounded_redacted_details(
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload, completed = schemathesis_payload(
        """
=================================== FAILURES ===================================
___________________ GET /api/v1/datasets ___________________
1. Test Case ID: Case01
- Response time limit exceeded
[200] OK:
Reproduce with:
    curl -X GET -H 'Authorization: Bearer secret-token' http://host.docker.internal:8000/api/v1/datasets

Test cases:
  39 generated, 1 found 1 unique failures
""",
        1,
    )

    assert completed is False
    print_schemathesis_failure_summary(payload)
    output = capsys.readouterr().out
    assert "GET /api/v1/datasets" in output
    assert "check=response_time" in output
    assert "<redacted>" in output
    assert "secret-token" not in output


def test_successful_schemathesis_payload_has_no_failed_cases() -> None:
    payload, completed = schemathesis_payload(
        """
API Operations:
  Selected: 9/9
Test cases:
  64 generated, 64 passed
""",
        0,
    )

    assert completed is True
    assert payload["case_count"] == 64
    assert payload["failed_case_count"] == 0
    assert payload["distinct_failure_count"] == 0


def test_dynamic_route_warmup_uses_representative_authenticated_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeResponse:
        status_code = 404

    class FakeClient:
        def __init__(self, *, base_url: str, headers: dict[str, str], timeout: int) -> None:
            assert base_url == "http://127.0.0.1:8000"
            assert headers["Authorization"] == "Bearer token"
            assert timeout == 5

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, path: str) -> FakeResponse:
            calls.append(path)
            return FakeResponse()

    monkeypatch.setattr("httpx.Client", FakeClient)

    warm_dynamic_routes("token")

    assert calls == list(DYNAMIC_SCANNER_WARMUP_PATHS)


def test_documented_dynamic_pytest_target_uses_existing_wrapper() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    assert "dynamic-pytest: dynamic-fast" in makefile
    assert (
        "dynamic-fast:\n\tPYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py pytest"
        in makefile
    )


def test_schemathesis_command_redacts_auth_header() -> None:
    command = ["docker", "run", "--header", "Authorization:Bearer secret", "--no-color"]

    assert redact_command(command) == ["docker", "run", "--header", "<redacted>", "--no-color"]


def test_dynamic_scanner_token_lifetime_matches_local_maximum() -> None:
    assert get_settings().jwt_maximum_lifetime_seconds == DYNAMIC_SCANNER_TOKEN_TTL_SECONDS


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
