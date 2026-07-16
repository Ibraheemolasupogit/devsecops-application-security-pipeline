"""Milestone 6 local dynamic security tool wrappers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.security.authentication.dev_tokens import issue_dev_token
from genomic_research_access_api.security.dynamic.config import validate_local_target

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "outputs/security/dynamic/raw"
PID_FILE = RAW / "dynamic-server.pid"
OPENAPI_FILE = RAW / "openapi.json"
SERVER_LOG = RAW / "dynamic-server.log"
CONFIG = json.loads((ROOT / "security/dynamic/config.yaml").read_text(encoding="utf-8"))
DYNAMIC_SERVER_HOST = os.environ.get("DYNAMIC_SERVER_HOST", "0.0.0.0")
DYNAMIC_CLIENT_HOST = os.environ.get("DYNAMIC_CLIENT_HOST", "127.0.0.1")
DYNAMIC_CONTAINER_HOST = os.environ.get("DYNAMIC_CONTAINER_HOST", "host.docker.internal")
DYNAMIC_SCANNER_TOKEN_TTL_SECONDS = 900
DYNAMIC_SCANNER_ROLES = (ActorRole.RESEARCHER, ActorRole.SECURITY_AUDITOR)
DYNAMIC_SCANNER_WARMUP_DATASET_ID = "syn-rare-disease-001"
DYNAMIC_SCANNER_WARMUP_PATHS = (
    "/api/v1/datasets",
    "/api/v1/access-requests",
    "/api/v1/access-requests/{request_id}",
    "/api/v1/audit-events",
)
SCHEMATHESIS_FAILURE_SUMMARY_LIMIT = 3
DIAGNOSTIC_TAIL_LINES = 160
DIAGNOSTIC_TAIL_CHARS = 16_000
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


@dataclass(frozen=True)
class DynamicWarmupState:
    request_id: str


@dataclass
class RunningDynamicServer:
    process: subprocess.Popen[str] | None
    log_handle: TextIO | None
    pid: int
    process_group_id: int | None


def run(
    args: list[str], *, check: bool = True, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, check=check, text=True, capture_output=True, env=env)


def sanitise_diagnostic_text(value: str) -> str:
    value = sanitise_schemathesis_detail(value)
    value = JWT_RE.sub("<redacted-jwt>", value)
    value = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "<redacted-private-key>",
        value,
        flags=re.S,
    )
    value = re.sub(r"(?i)(password|secret|token)\s*[:=]\s*[^'\"\s]+", r"\1=<redacted>", value)
    value = value.replace(str(ROOT), "<repo>")
    return value


def bounded_text_tail(value: str, *, lines: int = DIAGNOSTIC_TAIL_LINES) -> str:
    tail = "\n".join(value.splitlines()[-lines:])
    if len(tail) > DIAGNOSTIC_TAIL_CHARS:
        tail = tail[-DIAGNOSTIC_TAIL_CHARS:]
    return sanitise_diagnostic_text(tail)


def bounded_file_tail(path: Path, *, lines: int = DIAGNOSTIC_TAIL_LINES) -> str:
    if not path.exists():
        return f"{path.name} is not present"
    return bounded_text_tail(path.read_text(encoding="utf-8", errors="replace"), lines=lines)


def normalise_scanner_output(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.splitlines()) + "\n"


def print_section(title: str, body: str) -> None:
    print(f"--- {title} ---", flush=True)
    print(body or "<empty>", flush=True)


def server_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    env["GRAA_RATE_LIMIT_ENABLED"] = "true"
    env["GRAA_RATE_LIMIT_REQUESTS"] = "500"
    env["GRAA_RATE_LIMIT_WINDOW_SECONDS"] = "60"
    return env


def local_target_url(host: str) -> str:
    return f"http://{host}:8000"


def process_group_id(pid: int) -> int | None:
    if hasattr(os, "getpgid"):
        with suppress(OSError):
            return os.getpgid(pid)
    return None


def docker_pull_image(image: str) -> subprocess.CompletedProcess[str]:
    print_section("docker image pull", f"image={image}")
    result = run(["docker", "pull", image], check=False)
    print_section("docker image pull result", bounded_text_tail(result.stdout + result.stderr))
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    return result


def dynamic_server_start() -> RunningDynamicServer:
    RAW.mkdir(parents=True, exist_ok=True)
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text(encoding="utf-8"))
        try:
            os.kill(pid, 0)
            return RunningDynamicServer(
                process=None,
                log_handle=None,
                pid=pid,
                process_group_id=process_group_id(pid),
            )
        except OSError:
            PID_FILE.unlink()
    log_handle = SERVER_LOG.open("w", encoding="utf-8", buffering=1)
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "genomic_research_access_api.main:app",
            "--host",
            DYNAMIC_SERVER_HOST,
            "--port",
            "8000",
        ],
        cwd=ROOT,
        env=server_env(),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
    )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")
    return RunningDynamicServer(
        process=process,
        log_handle=log_handle,
        pid=process.pid,
        process_group_id=process_group_id(process.pid),
    )


def dynamic_server_wait(server: RunningDynamicServer | None = None) -> None:
    import httpx

    url = validate_local_target(local_target_url(DYNAMIC_CLIENT_HOST)) + "/health"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert_server_alive(server, "readiness")
        try:
            response = httpx.get(url, timeout=1)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.5)
    raise SystemExit(
        "Dynamic security local server did not become healthy.\n" + server_diagnostics()
    )


def server_is_alive(server: RunningDynamicServer | None = None) -> bool:
    if server is not None and server.process is not None:
        return server.process.poll() is None
    if server is not None:
        pid = server.pid
    elif PID_FILE.exists():
        pid = int(PID_FILE.read_text(encoding="utf-8"))
    else:
        return False
    with suppress(OSError):
        os.kill(pid, 0)
        return True
    return False


def server_exit_code(server: RunningDynamicServer | None = None) -> int | str | None:
    if server is not None and server.process is not None:
        return server.process.poll()
    return "unknown"


def server_diagnostics(server: RunningDynamicServer | None = None, phase: str | None = None) -> str:
    details = []
    if phase is not None:
        details.append(f"phase={phase}")
    if server is not None:
        details.append(f"server pid {server.pid}")
        details.append(f"process group {server.process_group_id}")
        details.append(f"exit code {server_exit_code(server)}")
        details.append(f"server alive {server_is_alive(server)}")
    elif PID_FILE.exists():
        pid = int(PID_FILE.read_text(encoding="utf-8"))
        with suppress(OSError):
            os.kill(pid, 0)
            details.append(f"server pid {pid} is still running")
        if not details:
            details.append(f"server pid {pid} is not running")
    else:
        details.append("server pid file is not present")
    if SERVER_LOG.exists():
        log_lines = SERVER_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
        details.append("server log tail:")
        details.extend(log_lines[-40:])
    else:
        details.append("server log is not present")
    return "\n".join(details)


def assert_server_alive(server: RunningDynamicServer | None, phase: str) -> None:
    if server_is_alive(server):
        return
    diagnostic = server_diagnostics(server, phase)
    print_section("dynamic server unexpected exit", diagnostic)
    raise SystemExit("Dynamic security local server exited unexpectedly.\n" + diagnostic)


def dynamic_server_stop(server: RunningDynamicServer | None = None) -> None:
    if server is None and not PID_FILE.exists():
        return
    pid = server.pid if server is not None else int(PID_FILE.read_text(encoding="utf-8"))
    pgid = server.process_group_id if server is not None else process_group_id(pid)
    if pgid is not None:
        with suppress(OSError):
            os.killpg(pgid, signal.SIGTERM)
    else:
        with suppress(OSError):
            os.kill(pid, signal.SIGTERM)
    if server is not None and server.process is not None:
        try:
            server.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if pgid is not None:
                with suppress(OSError):
                    os.killpg(pgid, signal.SIGKILL)
            else:
                with suppress(OSError):
                    os.kill(pid, signal.SIGKILL)
            server.process.wait(timeout=5)
    if server is not None and server.log_handle is not None:
        server.log_handle.close()
    PID_FILE.unlink(missing_ok=True)


def dynamic_pytest(selector: str = "tests/dynamic") -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            selector,
            "-q",
            "--json-report",
            "--json-report-file=outputs/security/dynamic/raw/pytest-dynamic.json",
        ],
        cwd=ROOT,
        check=True,
        env=os.environ | {"PYTHONPATH": "src"},
    )


def write_openapi_schema(state: DynamicWarmupState | None = None) -> None:
    from genomic_research_access_api.main import create_app

    schema = create_app().openapi()
    if state is not None:
        paths = schema["paths"]
        request_parameter = paths["/api/v1/access-requests/{request_id}"]["get"]["parameters"][0]
        request_parameter["example"] = state.request_id
        request_parameter["schema"]["examples"] = [state.request_id]
    OPENAPI_FILE.write_text(json.dumps(schema, sort_keys=True), encoding="utf-8")


def redact_command(args: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        redacted.append(arg)
        if arg == "--header":
            redact_next = True
    return redacted


def schemathesis_command(token: str) -> list[str]:
    cfg = CONFIG["schemathesis"]
    target = validate_local_target(local_target_url(DYNAMIC_CONTAINER_HOST))
    return [
        "docker",
        "run",
        "--rm",
        "--add-host",
        "host.docker.internal:host-gateway",
        "-v",
        f"{RAW}:/work",
        cfg["container_image"],
        "run",
        "/work/openapi.json",
        "--url",
        target,
        "--checks",
        "not_a_server_error,content_type_conformance,response_schema_conformance",
        "--max-examples",
        str(cfg["max_examples"]),
        "--request-timeout",
        str(cfg["request_timeout_seconds"]),
        "--max-response-time",
        str(cfg["max_response_time_ms"] / 1000),
        "--phases",
        ",".join(cfg["phases"]),
        "--generation-deterministic",
        "--seed",
        "20260101",
        "--workers",
        "1",
        "--header",
        f"Authorization:Bearer {token}",
        "--output-sanitize",
        "true",
        "--no-color",
    ]


def warm_dynamic_routes(token: str) -> DynamicWarmupState:
    import httpx

    target = validate_local_target(local_target_url(DYNAMIC_CLIENT_HOST))
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=target, headers=headers, timeout=5) as client:
        dataset_response = client.get("/api/v1/datasets")
        if dataset_response.status_code != 200:
            raise SystemExit(
                "Dynamic security warm-up failed for /api/v1/datasets: "
                f"{dataset_response.status_code}"
            )
        create_response = client.post(
            "/api/v1/access-requests",
            json={
                "dataset_id": DYNAMIC_SCANNER_WARMUP_DATASET_ID,
                "research_purpose": "Schemathesis deterministic dynamic security warm-up.",
                "requested_access_level": "aggregate_analysis",
            },
        )
        if create_response.status_code != 201:
            raise SystemExit(
                "Dynamic security warm-up failed for /api/v1/access-requests: "
                f"{create_response.status_code}"
            )
        request_id = str(create_response.json()["request_id"])
        for path in (
            "/api/v1/access-requests",
            f"/api/v1/access-requests/{request_id}",
            "/api/v1/audit-events",
        ):
            response = client.get(path)
            if response.status_code != 200:
                raise SystemExit(
                    f"Dynamic security warm-up failed for {path}: {response.status_code}"
                )
    return DynamicWarmupState(request_id=request_id)


def sanitise_schemathesis_detail(value: str) -> str:
    value = re.sub(r"(Authorization:\s*Bearer\s+)[^'\"\s]+", r"\1<redacted>", value)
    value = re.sub(r"(Authorization:\s*)[^'\"\s]+", r"\1<redacted>", value)
    value = re.sub(r"(-H\s+['\"]Authorization:\s*)[^'\"]+(['\"])", r"\1<redacted>\2", value)
    return value


def schemathesis_check_name(message: str) -> str:
    lowered = message.lower()
    if "response time" in lowered:
        return "response_time"
    if "content type" in lowered or "content-type" in lowered:
        return "content_type_conformance"
    if (
        "schema" in lowered
        or "undocumented" in lowered
        or "status code" in lowered
        or "does not match any documented" in lowered
    ):
        return "response_schema_conformance"
    if "server error" in lowered or "[5" in lowered:
        return "not_a_server_error"
    return "schemathesis_check"


def schemathesis_failure_count(output: str) -> int:
    unique_match = re.search(r"(\d+) found (\d+) unique failures", output)
    if unique_match:
        return int(unique_match.group(2))
    failure_match = re.search(r"=+\s+(\d+) failures?", output)
    return int(failure_match.group(1)) if failure_match else 0


def schemathesis_failure_classification(output: str, returncode: int) -> str:
    lowered = output.lower()
    if returncode == 0:
        return "none"
    if schemathesis_failure_count(output) > 0 or "failures" in lowered:
        return "test_failures"
    if "schema error" in lowered or "invalid schema" in lowered or "failed to load" in lowered:
        return "schema_error"
    if (
        "connection refused" in lowered
        or "name or service not known" in lowered
        or "temporary failure in name resolution" in lowered
        or "max retries exceeded" in lowered
        or "network is unreachable" in lowered
        or "failed to establish a new connection" in lowered
    ):
        return "network_error"
    if "read timed out" in lowered or "timeout" in lowered or "timed out" in lowered:
        return "timeout"
    if "internal error" in lowered or "traceback" in lowered or "exception" in lowered:
        return "scanner_error"
    if "500 internal server error" in lowered or "server error" in lowered:
        return "server_error"
    return "unknown_failure"


def schemathesis_failures(output: str) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    capture_reproduction = False
    parsing_failures = "FAILURES" not in output
    operation_re = re.compile(
        r"^(?:[_=\-━─\s]+)?"
        r"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
        r"(?P<path>/\S+?)"
        r"(?:\s+[_=\-━─]+)?$"
    )

    def append_current() -> None:
        if current is not None and (
            "failure_message" in current
            or "test_case_id" in current
            or "response_status" in current
            or "reproduction_command" in current
        ):
            failures.append(current)

    for raw_line in output.splitlines():
        line = sanitise_schemathesis_detail(raw_line.rstrip())
        section = line.strip().strip("= ").upper()
        if section == "FAILURES":
            parsing_failures = True
            continue
        if section in {"WARNINGS", "SUMMARY"}:
            append_current()
            current = None
            parsing_failures = False
            continue
        if not parsing_failures:
            continue
        operation_match = operation_re.match(line.strip())
        if operation_match:
            append_current()
            current = {
                "method": operation_match.group("method"),
                "path": operation_match.group("path").strip(),
            }
            capture_reproduction = False
            continue
        if current is None:
            continue
        stripped = line.strip()
        case_match = re.search(r"(?:Test\s+)?Case ID:\s*([A-Za-z0-9._:-]+)", stripped)
        if case_match:
            current["test_case_id"] = case_match.group(1)
            continue
        explicit_check = re.search(r"(?:Check|Failed check):\s*([A-Za-z0-9_.:-]+)", stripped)
        if explicit_check:
            current["failed_check"] = explicit_check.group(1)
            continue
        if stripped.startswith("- ") and "failure_message" not in current:
            message = stripped[2:].strip()
            current["failed_check"] = schemathesis_check_name(message)
            current["failure_message"] = message
            continue
        if stripped.lower().startswith(("failure:", "error:")) and "failure_message" not in current:
            message = stripped.split(":", maxsplit=1)[1].strip()
            current["failed_check"] = schemathesis_check_name(message)
            current["failure_message"] = message
            continue
        bracket_status = re.match(r"^\[(\d{3})\]\s*(.*)", stripped)
        plain_status = re.match(r"^(?:Status|Response status):\s*(\d{3})(?:\s+(.+))?", stripped)
        received_status = re.search(
            r"\b(?:received|returned|status(?: code)?)\D+(\d{3})\b", stripped, re.I
        )
        if bracket_status:
            current["response_status"] = stripped.rstrip(":")
            continue
        if plain_status:
            current["response_status"] = " ".join(
                part for part in plain_status.groups() if part
            ).strip()
            continue
        if received_status and "response_status" not in current:
            current["response_status"] = received_status.group(1)
            if "failure_message" not in current:
                current["failure_message"] = stripped
                current["failed_check"] = schemathesis_check_name(stripped)
            continue
        if stripped == "Reproduce with:":
            capture_reproduction = True
            continue
        if capture_reproduction and stripped:
            current["reproduction_command"] = stripped
            capture_reproduction = False
    if current is not None:
        append_current()
    return failures[:SCHEMATHESIS_FAILURE_SUMMARY_LIMIT]


def schemathesis_payload(output: str, returncode: int) -> tuple[dict[str, object], bool]:
    cfg = CONFIG["schemathesis"]
    operations_match = re.search(r"Operations:\s+(\d+) selected / (\d+) total", output)
    selected_match = re.search(r"Selected:\s+(\d+)/(\d+)", output)
    cases_match = re.search(r"Test cases:\s+(\d+) generated,\s+(\d+) passed", output)
    generated_match = re.search(r"Test cases:\s+(\d+) generated", output)
    operation_count = 0
    if operations_match:
        operation_count = int(operations_match.group(1))
    elif selected_match:
        operation_count = int(selected_match.group(1))
    generated = int(cases_match.group(1)) if cases_match else 0
    if not generated and generated_match:
        generated = int(generated_match.group(1))
    passed = int(cases_match.group(2)) if cases_match else 0
    warning_messages = sorted(set(re.findall(r"⚠️\s+(.+)", output)))
    completed = returncode == 0 or (generated > 0 and generated == passed)
    failures = schemathesis_failures(output)
    distinct_failure_count = schemathesis_failure_count(output)
    failed_case_count = generated - passed if cases_match else distinct_failure_count
    payload: dict[str, object] = {
        "base_url": "local-docker-gateway",
        "case_count": generated,
        "distinct_failure_count": distinct_failure_count,
        "failure_classification": schemathesis_failure_classification(output, returncode),
        "failed_case_count": failed_case_count,
        "failures": failures,
        "checks": [
            {"name": name, "outcome": "passed" if completed else "failed"}
            for name in [
                "not_a_server_error",
                "content_type_conformance",
                "response_schema_conformance",
            ]
        ],
        "execution_status": "completed" if completed else "failed",
        "max_examples": cfg["max_examples"],
        "operation_count": operation_count,
        "request_timeout_seconds": cfg["request_timeout_seconds"],
        "scanner_exit_code": returncode,
        "version": cfg["version"],
        "warnings": warning_messages,
    }
    return payload, completed


def print_schemathesis_failure_summary(payload: dict[str, object]) -> None:
    print("schemathesis failure summary:", flush=True)
    print(f"  classification: {payload['failure_classification']}", flush=True)
    print(f"  distinct failures: {payload['distinct_failure_count']}", flush=True)
    failures = payload.get("failures", [])
    if not isinstance(failures, list) or not failures:
        print(
            "  no bounded failure details parsed; inspect raw schemathesis-output.txt", flush=True
        )
        return
    for index, failure in enumerate(failures, start=1):
        if not isinstance(failure, dict):
            continue
        print(
            "  "
            f"{index}. {failure.get('method', 'UNKNOWN')} {failure.get('path', 'unknown')} "
            f"check={failure.get('failed_check', 'unknown')} "
            f"status={failure.get('response_status', 'unknown')} "
            f"case={failure.get('test_case_id', 'unknown')}",
            flush=True,
        )
        print(f"     message: {failure.get('failure_message', 'unknown')}", flush=True)
        if failure.get("reproduction_command"):
            print(f"     reproduce: {failure['reproduction_command']}", flush=True)


def print_schemathesis_diagnostics() -> None:
    print_section(
        "schemathesis raw output tail", bounded_file_tail(RAW / "schemathesis-output.txt")
    )
    result_file = RAW / "schemathesis.json"
    print_section("schemathesis structured result", bounded_file_tail(result_file, lines=240))
    print_section("dynamic server log tail", bounded_file_tail(SERVER_LOG, lines=120))


def dynamic_preflight_diagnostics() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    docker_version = run(["docker", "--version"], check=False)
    print_section(
        "docker version",
        bounded_text_tail(docker_version.stdout + docker_version.stderr),
    )
    cfg = CONFIG["schemathesis"]
    print_section("schemathesis image", str(cfg["container_image"]))
    print_section(
        "dynamic server binding",
        "\n".join(
            [
                f"server_bind_host={DYNAMIC_SERVER_HOST}",
                f"host_health_url={local_target_url(DYNAMIC_CLIENT_HOST)}/health",
                f"container_health_url={local_target_url(DYNAMIC_CONTAINER_HOST)}/health",
            ]
        ),
    )
    if PID_FILE.exists():
        pid = PID_FILE.read_text(encoding="utf-8").strip()
        print_section("server pid state", f"pid_file={pid}\n{server_diagnostics()}")
    else:
        print_section("server pid state", "server pid file is not present")
    if OPENAPI_FILE.exists():
        digest = hashlib.sha256(OPENAPI_FILE.read_bytes()).hexdigest()
        print_section(
            "openapi file",
            f"path={OPENAPI_FILE.name}\nsize={OPENAPI_FILE.stat().st_size}\nsha256={digest}",
        )
    else:
        print_section("openapi file", "openapi.json is not present")
    raw_stat = RAW.stat()
    print_section("raw directory", f"path={RAW.name}\nmode={oct(raw_stat.st_mode & 0o777)}")


def dynamic_diagnostics() -> None:
    dynamic_preflight_diagnostics()
    print_schemathesis_diagnostics()


def docker_network_health_check() -> subprocess.CompletedProcess[str]:
    target = validate_local_target(local_target_url(DYNAMIC_CONTAINER_HOST)) + "/health"
    return run(
        [
            "docker",
            "run",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--entrypoint",
            "python",
            CONFIG["schemathesis"]["container_image"],
            "-c",
            (
                "import urllib.request; "
                f"response=urllib.request.urlopen({target!r}, timeout=5); "
                "print(response.status, response.read().decode())"
            ),
        ],
        check=False,
    )


def schemathesis_test(server: RunningDynamicServer | None = None) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    token = issue_dev_token(
        subject="researcher-001",
        expires_in_seconds=DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
        roles=DYNAMIC_SCANNER_ROLES,
        token_id="dynamic-schemathesis-scanner",
    )
    assert_server_alive(server, "before-warmup")
    state = warm_dynamic_routes(token)
    assert_server_alive(server, "after-warmup")
    write_openapi_schema(state)
    command = schemathesis_command(token)
    print(f"python executable: {sys.executable}", flush=True)
    print(f"schemathesis image: {CONFIG['schemathesis']['container_image']}", flush=True)
    dynamic_preflight_diagnostics()
    network_check = docker_network_health_check()
    print_section(
        "container network health check",
        bounded_text_tail(network_check.stdout + network_check.stderr),
    )
    if network_check.returncode != 0:
        print(f"container network health check exit={network_check.returncode}", flush=True)
        print_section("dynamic server state after failed network probe", server_diagnostics(server))
        raise SystemExit(network_check.returncode)
    assert_server_alive(server, "after-network-probe")
    assert_server_alive(server, "before-schemathesis")
    print("schemathesis command: " + " ".join(redact_command(command)), flush=True)
    result = run(command, check=False)
    combined_output = result.stdout + result.stderr
    (RAW / "schemathesis-output.txt").write_text(
        normalise_scanner_output(combined_output), encoding="utf-8", newline="\n"
    )
    payload, completed = schemathesis_payload(combined_output, result.returncode)
    payload["server_lifecycle"] = {
        "alive_after_schemathesis": server_is_alive(server),
        "exit_code_after_schemathesis": server_exit_code(server),
        "phase": "after-schemathesis",
    }
    (RAW / "schemathesis.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    warnings = payload["warnings"]
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    print(
        "schemathesis result: "
        f"exit={result.returncode} status={payload['execution_status']} "
        f"cases={payload['case_count']} warnings={warning_count}",
        flush=True,
    )
    if not server_is_alive(server):
        print_section("dynamic server state after schemathesis", server_diagnostics(server))
        print_schemathesis_diagnostics()
        raise SystemExit(result.returncode or 1)
    if not completed:
        print_schemathesis_failure_summary(payload)
        print_schemathesis_diagnostics()
        raise SystemExit(result.returncode)


def zap_baseline() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    cfg = CONFIG["zap"]
    target = validate_local_target(CONFIG["local_targets"]["docker_base_url"])
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "-v",
            f"{RAW}:/zap/wrk",
            cfg["container_image"],
            "zap-baseline.py",
            "-t",
            target,
            "-m",
            "1",
            "-T",
            str(cfg["max_scan_minutes"]),
            "-J",
            "zap-report.json",
            "-r",
            "zap-report.html",
            "-I",
        ],
        check=False,
    )
    (RAW / "zap-output.txt").write_text(
        normalise_scanner_output(result.stdout + result.stderr), encoding="utf-8", newline="\n"
    )
    report_path = RAW / "zap-report.json"
    if report_path.exists():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    else:
        payload = {"site": [], "alerts": []}
    html_report_path = RAW / "zap-report.html"
    if html_report_path.exists():
        html_report_path.write_text(
            normalise_scanner_output(html_report_path.read_text(encoding="utf-8")),
            encoding="utf-8",
            newline="\n",
        )
    payload["execution_status"] = "completed" if result.returncode == 0 else "failed"
    payload["scan_mode"] = "baseline-passive"
    payload["target"] = "local-docker-gateway"
    payload["version"] = cfg["version"]
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def with_server(command: str) -> None:
    if command == "schemathesis":
        docker_pull_image(CONFIG["schemathesis"]["container_image"])
    server = dynamic_server_start()
    try:
        dynamic_server_wait(server)
        assert_server_alive(server, "after-readiness")
        if command == "schemathesis":
            schemathesis_test(server)
        else:
            zap_baseline()
    finally:
        dynamic_server_stop(server)


def dynamic_evidence() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "genomic_research_access_api.security.dynamic.evidence",
            "--timestamp",
            "2026-01-01T00:00:00Z",
        ],
        cwd=ROOT,
        check=True,
        env=os.environ | {"PYTHONPATH": "src"},
    )


def dynamic_report() -> None:
    subprocess.run(
        [sys.executable, "-m", "genomic_research_access_api.security.dynamic.report"],
        cwd=ROOT,
        check=True,
        env=os.environ | {"PYTHONPATH": "src"},
    )


def dynamic_full() -> None:
    dynamic_pytest()
    with_server("schemathesis")
    with_server("zap")
    dynamic_evidence()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "genomic_research_access_api.security.dynamic.evidence",
            "--verify",
        ],
        cwd=ROOT,
        check=True,
        env=os.environ | {"PYTHONPATH": "src"},
    )
    dynamic_report()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    args = parser.parse_args()
    commands: dict[str, Callable[[], object]] = {
        "tools": lambda: print(json.dumps(CONFIG, indent=2, sort_keys=True)),
        "server-start": dynamic_server_start,
        "server-wait": dynamic_server_wait,
        "server-stop": dynamic_server_stop,
        "pytest": dynamic_pytest,
        "schemathesis": lambda: with_server("schemathesis"),
        "zap": lambda: with_server("zap"),
        "diagnostics": dynamic_diagnostics,
        "evidence": dynamic_evidence,
        "report": dynamic_report,
        "full": dynamic_full,
    }
    commands[args.command]()


if __name__ == "__main__":
    main()
