from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import scripts.dynamic_security_tools as dynamic_tools
from scripts.dynamic_security_tools import (
    DIAGNOSTIC_TAIL_CHARS,
    DYNAMIC_SCANNER_ROLES,
    DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
    DYNAMIC_SCANNER_WARMUP_DATASET_ID,
    DYNAMIC_SCANNER_WARMUP_PATHS,
    DynamicWarmupState,
    RunningDynamicServer,
    bounded_text_tail,
    normalise_scanner_output,
    print_schemathesis_failure_summary,
    redact_command,
    sanitise_diagnostic_text,
    schemathesis_failure_classification,
    schemathesis_failures,
    schemathesis_payload,
    warm_dynamic_routes,
    write_openapi_schema,
)

from genomic_research_access_api.config import get_settings
from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.main import create_app
from genomic_research_access_api.security.authentication.dev_tokens import issue_dev_token
from genomic_research_access_api.security.authentication.jwt_validator import JwtValidator
from genomic_research_access_api.security.authorisation import Permission, permissions_for
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


def test_schemathesis_exit_one_without_failure_blocks_is_classified_unknown() -> None:
    payload, completed = schemathesis_payload(
        """
Schemathesis v4.0.26
API Operations:
  Selected: 9/9
Test cases:
  47 generated
""",
        1,
    )

    assert completed is False
    assert payload["scanner_exit_code"] == 1
    assert payload["case_count"] == 47
    assert payload["distinct_failure_count"] == 0
    assert payload["failure_classification"] == "unknown_failure"


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("Connection refused while requesting http://host.docker.internal:8000", "network_error"),
        ("Schema Error: Failed to load schema from /work/openapi.json", "schema_error"),
        ("requests.exceptions.ReadTimeout: request timed out", "timeout"),
        ("INTERNAL ERROR\nTraceback (most recent call last):", "scanner_error"),
        ("500 Internal Server Error", "server_error"),
        ("Test cases:\n  39 generated, 1 found 1 unique failures", "test_failures"),
    ],
)
def test_schemathesis_failure_classification(output: str, expected: str) -> None:
    assert schemathesis_failure_classification(output, 1) == expected


def test_diagnostic_tail_is_bounded_and_redacted() -> None:
    raw_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXNlYXJjaGVyLTAwMSJ9.signature"
    raw = "\n".join(
        [
            f"line-{index} Authorization: Bearer secret-token token=secret-value {raw_jwt}"
            for index in range(500)
        ]
    )

    tail = bounded_text_tail(raw, lines=300)

    assert len(tail) <= DIAGNOSTIC_TAIL_CHARS
    assert "secret-token" not in tail
    assert "secret-value" not in tail
    assert raw_jwt not in tail
    assert "<redacted" in tail


def test_diagnostic_redaction_removes_private_key_material() -> None:
    key_type = "PRIVATE KEY"
    text = "\n".join(
        [
            f"-----BEGIN {key_type}-----",
            "not-a-real-key",
            f"-----END {key_type}-----",
            "Authorization:Bearer abc.def.ghi",
        ]
    )

    redacted = sanitise_diagnostic_text(text)

    assert "not-a-real-key" not in redacted
    assert "abc.def.ghi" not in redacted
    assert "<redacted-private-key>" in redacted


def test_scanner_output_normalisation_removes_terminal_padding() -> None:
    raw = "loaded spec   \n\nsummary\t \n"

    assert normalise_scanner_output(raw) == "loaded spec\n\nsummary\n"


def test_dynamic_scanner_uses_linux_reachable_bind_and_split_client_hosts() -> None:
    assert dynamic_tools.DYNAMIC_SERVER_HOST == "0.0.0.0"
    assert dynamic_tools.DYNAMIC_SCANNER_BIND_HOST == "0.0.0.0"
    assert dynamic_tools.DYNAMIC_CLIENT_HOST == "127.0.0.1"
    assert dynamic_tools.DYNAMIC_CONTAINER_HOST == "host.docker.internal"
    assert (
        dynamic_tools.local_target_url(dynamic_tools.DYNAMIC_CLIENT_HOST) == "http://127.0.0.1:8000"
    )
    assert (
        dynamic_tools.local_target_url(dynamic_tools.DYNAMIC_CONTAINER_HOST)
        == "http://host.docker.internal:8000"
    )


def test_dynamic_scanner_bind_host_is_limited_to_local_scanner_hosts() -> None:
    assert dynamic_tools.scanner_bind_host(None) == "0.0.0.0"
    assert dynamic_tools.scanner_bind_host("127.0.0.1") == "127.0.0.1"
    assert dynamic_tools.scanner_bind_host("localhost") == "localhost"

    with pytest.raises(ValueError, match="unsupported dynamic scanner bind host"):
        dynamic_tools.scanner_bind_host("192.0.2.10")


def test_server_log_uses_file_not_unread_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    popen_kwargs: dict[str, Any] = {}

    class FakePopen:
        pid = 12345

        def __init__(self, _args: list[str], **kwargs: Any) -> None:
            popen_kwargs.update(kwargs)

        def poll(self) -> None:
            return None

    monkeypatch.setattr(dynamic_tools, "RAW", tmp_path)
    monkeypatch.setattr(dynamic_tools, "PID_FILE", tmp_path / "dynamic-server.pid")
    monkeypatch.setattr(dynamic_tools, "SERVER_LOG", tmp_path / "dynamic-server.log")
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr(dynamic_tools, "process_group_id", lambda _pid: 12345)

    server = dynamic_tools.dynamic_server_start()

    assert server.pid == 12345
    assert popen_kwargs["stdout"] is not subprocess.PIPE
    assert popen_kwargs["stderr"] == subprocess.STDOUT
    assert popen_kwargs["cwd"] == dynamic_tools.ROOT
    assert popen_kwargs["env"]["PYTHONPATH"] == "src"
    assert popen_kwargs["start_new_session"] is True
    assert server.log_handle is not None
    server.log_handle.close()


def test_dynamic_server_start_binds_to_all_interfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    popen_args: list[str] = []

    class FakePopen:
        pid = 12345

        def __init__(self, args: list[str], **_kwargs: Any) -> None:
            popen_args.extend(args)

        def poll(self) -> None:
            return None

    monkeypatch.setattr(dynamic_tools, "RAW", tmp_path)
    monkeypatch.setattr(dynamic_tools, "PID_FILE", tmp_path / "dynamic-server.pid")
    monkeypatch.setattr(dynamic_tools, "SERVER_LOG", tmp_path / "dynamic-server.log")
    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    monkeypatch.setattr(dynamic_tools, "process_group_id", lambda _pid: 12345)

    server = dynamic_tools.dynamic_server_start()

    assert popen_args[popen_args.index("--host") + 1] == "0.0.0.0"
    assert server.log_handle is not None
    server.log_handle.close()


def test_with_server_pulls_schemathesis_image_before_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    server = RunningDynamicServer(process=None, log_handle=None, pid=12345, process_group_id=12345)

    def record_pull(image: str) -> None:
        events.append(f"pull:{image}")

    def record_start() -> RunningDynamicServer:
        events.append("start")
        return server

    monkeypatch.setattr(
        dynamic_tools,
        "docker_pull_image",
        record_pull,
    )
    monkeypatch.setattr(dynamic_tools, "dynamic_server_start", record_start)
    monkeypatch.setattr(dynamic_tools, "dynamic_server_wait", lambda _server: events.append("wait"))
    monkeypatch.setattr(
        dynamic_tools,
        "assert_server_alive",
        lambda _server, phase: events.append(f"alive:{phase}"),
    )
    monkeypatch.setattr(dynamic_tools, "schemathesis_test", lambda _server: events.append("scan"))
    monkeypatch.setattr(dynamic_tools, "dynamic_server_stop", lambda _server: events.append("stop"))

    dynamic_tools.with_server("schemathesis")

    assert events == [
        "pull:schemathesis/schemathesis:4.0.26",
        "start",
        "wait",
        "alive:after-readiness",
        "scan",
        "stop",
    ]


def test_schemathesis_lifecycle_checks_surround_warmup_probe_and_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phases: list[str] = []
    server_alive_calls = iter([True, True])
    server = RunningDynamicServer(process=None, log_handle=None, pid=12345, process_group_id=12345)

    monkeypatch.setattr(dynamic_tools, "RAW", tmp_path)
    monkeypatch.setattr(
        dynamic_tools,
        "issue_dev_token",
        lambda **_kwargs: "scanner-token",
    )
    monkeypatch.setattr(
        dynamic_tools,
        "assert_server_alive",
        lambda _server, phase: phases.append(phase),
    )
    monkeypatch.setattr(
        dynamic_tools,
        "warm_dynamic_routes",
        lambda token: DynamicWarmupState(request_id=f"{token}-request"),
    )
    monkeypatch.setattr(
        dynamic_tools, "write_openapi_schema", lambda _state: phases.append("schema")
    )
    monkeypatch.setattr(dynamic_tools, "dynamic_preflight_diagnostics", lambda: None)
    monkeypatch.setattr(
        dynamic_tools,
        "docker_network_health_check",
        lambda: subprocess.CompletedProcess(["docker"], 0, "200\n", ""),
    )
    monkeypatch.setattr(
        dynamic_tools,
        "schemathesis_command",
        lambda _token: ["docker", "run", "schemathesis"],
    )
    monkeypatch.setattr(
        dynamic_tools,
        "run",
        lambda _args, check=False: subprocess.CompletedProcess(
            _args,
            0,
            "API Operations:\n  Selected: 9/9\nTest cases:\n  1 generated, 1 passed\n",
            "",
        ),
    )
    monkeypatch.setattr(dynamic_tools, "server_is_alive", lambda _server: next(server_alive_calls))

    dynamic_tools.schemathesis_test(server)

    assert phases == [
        "before-warmup",
        "after-warmup",
        "schema",
        "after-network-probe",
        "before-schemathesis",
    ]


def test_unexpected_server_exit_reports_phase_and_log_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dynamic_tools, "SERVER_LOG", tmp_path / "dynamic-server.log")
    dynamic_tools.SERVER_LOG.write_text("startup ok\ncrashed\n", encoding="utf-8")
    server = RunningDynamicServer(process=None, log_handle=None, pid=12345, process_group_id=12345)
    monkeypatch.setattr(dynamic_tools, "server_is_alive", lambda _server: False)

    with pytest.raises(SystemExit, match="exited unexpectedly") as exc_info:
        dynamic_tools.assert_server_alive(server, "before-schemathesis")

    message = str(exc_info.value)
    assert "phase=before-schemathesis" in message
    assert "exit code unknown" in message
    assert "crashed" in message


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


def test_schemathesis_4_failure_detail_format_is_parsed_and_redacted() -> None:
    failures = schemathesis_failures(
        """
=================================== FAILURES ===================================
GET /api/v1/access-requests
1. Test Case ID: ci-list-001
Failed check: response_schema_conformance
Failure: Undocumented HTTP status code
Response status: 403 Forbidden
Reproduce with:
    curl -X GET -H 'Authorization: Bearer ci-secret' http://host.docker.internal:8000/api/v1/access-requests

GET /api/v1/access-requests/{request_id}
1. Test Case ID: ci-read-001
- Response violates schema: value is not a valid object
[404] Not Found:
Reproduce with:
    curl -X GET -H 'Authorization:Bearer second-secret' http://host.docker.internal:8000/api/v1/access-requests/not-real

GET /api/v1/audit-events
1. Test Case ID: ci-audit-001
Failure: Response status code 403 is not documented
Status: 403 Forbidden
Reproduce with:
    curl -X GET -H "Authorization: Bearer third-secret" http://host.docker.internal:8000/api/v1/audit-events

=================================== SUMMARY ====================================
"""
    )

    assert failures == [
        {
            "method": "GET",
            "path": "/api/v1/access-requests",
            "test_case_id": "ci-list-001",
            "failed_check": "response_schema_conformance",
            "failure_message": "Undocumented HTTP status code",
            "response_status": "403 Forbidden",
            "reproduction_command": (
                "curl -X GET -H 'Authorization: <redacted>' "
                "http://host.docker.internal:8000/api/v1/access-requests"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/access-requests/{request_id}",
            "test_case_id": "ci-read-001",
            "failed_check": "response_schema_conformance",
            "failure_message": "Response violates schema: value is not a valid object",
            "response_status": "[404] Not Found",
            "reproduction_command": (
                "curl -X GET -H 'Authorization:<redacted>' "
                "http://host.docker.internal:8000/api/v1/access-requests/not-real"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/audit-events",
            "test_case_id": "ci-audit-001",
            "failed_check": "response_schema_conformance",
            "failure_message": "Response status code 403 is not documented",
            "response_status": "403 Forbidden",
            "reproduction_command": (
                'curl -X GET -H "Authorization: <redacted>" '
                "http://host.docker.internal:8000/api/v1/audit-events"
            ),
        },
    ]


def test_schemathesis_warning_operations_are_not_reported_as_failures() -> None:
    failures = schemathesis_failures(
        """
=================================== WARNINGS ===================================
403 Forbidden (3 operations):
  - GET /api/v1/audit-events
  - POST /api/v1/access-requests/{request_id}/approve
  - POST /api/v1/access-requests/{request_id}/reject
=================================== SUMMARY ====================================
"""
    )

    assert failures == []


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
    calls: list[tuple[str, str]] = []

    class FakeResponse:
        def __init__(self, status_code: int, payload: dict[str, str] | None = None) -> None:
            self.status_code = status_code
            self._payload = payload or {}

        def json(self) -> dict[str, str]:
            return self._payload

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
            calls.append(("GET", path))
            return FakeResponse(200)

        def post(self, path: str, *, json: dict[str, str]) -> FakeResponse:
            calls.append(("POST", path))
            assert json["dataset_id"] == DYNAMIC_SCANNER_WARMUP_DATASET_ID
            return FakeResponse(201, {"request_id": "schemathesis-access-request-001"})

    monkeypatch.setattr("httpx.Client", FakeClient)

    state = warm_dynamic_routes("token")

    assert state == DynamicWarmupState(request_id="schemathesis-access-request-001")
    assert calls == [
        ("GET", "/api/v1/datasets"),
        ("POST", "/api/v1/access-requests"),
        ("GET", "/api/v1/access-requests"),
        ("GET", "/api/v1/access-requests/schemathesis-access-request-001"),
        ("GET", "/api/v1/audit-events"),
    ]
    assert DYNAMIC_SCANNER_WARMUP_PATHS == (
        "/api/v1/datasets",
        "/api/v1/access-requests",
        "/api/v1/access-requests/{request_id}",
        "/api/v1/audit-events",
    )


def test_dynamic_scanner_token_uses_least_privileged_read_role_union() -> None:
    token = issue_dev_token(
        subject="researcher-001",
        roles=DYNAMIC_SCANNER_ROLES,
        expires_in_seconds=DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
    )
    settings = get_settings()
    principal = JwtValidator(
        public_key=settings.load_jwt_public_key(),
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        algorithm=settings.jwt_algorithm,
        leeway_seconds=settings.jwt_clock_skew_seconds,
        maximum_lifetime_seconds=settings.jwt_maximum_lifetime_seconds,
    ).validate(token)

    assert principal.roles == (ActorRole.RESEARCHER, ActorRole.SECURITY_AUDITOR)
    assert ActorRole.APPLICATION_ADMIN not in principal.roles
    assert {
        Permission.ACCESS_REQUEST_CREATE,
        Permission.ACCESS_REQUEST_LIST_OWN,
        Permission.ACCESS_REQUEST_READ_OWN,
        Permission.ACCESS_REQUEST_LIST_ALL,
        Permission.ACCESS_REQUEST_READ_ALL,
        Permission.AUDIT_EVENT_READ,
    }.issubset(permissions_for(principal))


def test_openapi_documents_dynamic_error_responses_and_request_id_example() -> None:
    write_openapi_schema(DynamicWarmupState(request_id="schemathesis-access-request-001"))
    schema = json.loads(Path("outputs/security/dynamic/raw/openapi.json").read_text())

    assert sorted(schema["paths"]["/api/v1/access-requests"]["get"]["responses"]) == [
        "200",
        "401",
        "403",
        "429",
    ]
    request_responses = schema["paths"]["/api/v1/access-requests/{request_id}"]["get"]["responses"]
    assert {"200", "401", "403", "404", "422", "429"}.issubset(request_responses)
    parameter = schema["paths"]["/api/v1/access-requests/{request_id}"]["get"]["parameters"][0]
    assert parameter["example"] == "schemathesis-access-request-001"
    assert parameter["schema"]["examples"] == ["schemathesis-access-request-001"]
    assert sorted(schema["paths"]["/api/v1/audit-events"]["get"]["responses"]) == [
        "200",
        "401",
        "403",
        "429",
    ]


def test_scanner_role_can_exercise_affected_operations() -> None:
    app = create_app()
    from fastapi.testclient import TestClient

    token = issue_dev_token(
        subject="researcher-001",
        roles=DYNAMIC_SCANNER_ROLES,
        expires_in_seconds=DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
    )
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app, raise_server_exceptions=False) as client:
        created = client.post(
            "/api/v1/access-requests",
            json={
                "dataset_id": DYNAMIC_SCANNER_WARMUP_DATASET_ID,
                "research_purpose": "Schemathesis deterministic dynamic security warm-up.",
                "requested_access_level": "aggregate_analysis",
            },
            headers=headers,
        )
        assert created.status_code == 201
        request_id = created.json()["request_id"]

        listed = client.get("/api/v1/access-requests", headers=headers)
        fetched = client.get(f"/api/v1/access-requests/{request_id}", headers=headers)
        audit = client.get("/api/v1/audit-events", headers=headers)

    assert listed.status_code == 200
    assert any(item["request_id"] == request_id for item in listed.json())
    assert fetched.status_code == 200
    assert fetched.json()["request_id"] == request_id
    assert audit.status_code == 200


def test_documented_dynamic_pytest_target_uses_existing_wrapper() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")

    assert "dynamic-pytest: dynamic-fast" in makefile
    assert "dynamic-diagnostics:" in makefile
    assert "scripts/dynamic_security_tools.py diagnostics" in makefile
    assert (
        "dynamic-fast:\n\tPYTHONPATH=src $(PYTHON) scripts/dynamic_security_tools.py pytest"
        in makefile
    )


def test_api_dynamic_security_workflow_uploads_failure_diagnostics() -> None:
    workflow = Path(".github/workflows/api-security.yml").read_text(encoding="utf-8")

    assert "Print dynamic diagnostics on failure" in workflow
    assert "if: failure()" in workflow
    assert "make dynamic-diagnostics" in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "if: always()" in workflow
    assert "outputs/security/dynamic/raw/" in workflow


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
