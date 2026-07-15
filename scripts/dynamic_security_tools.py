"""Milestone 6 local dynamic security tool wrappers."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from genomic_research_access_api.security.authentication.dev_tokens import issue_dev_token
from genomic_research_access_api.security.dynamic.config import validate_local_target

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "outputs/security/dynamic/raw"
PID_FILE = RAW / "dynamic-server.pid"
OPENAPI_FILE = RAW / "openapi.json"
SERVER_LOG = RAW / "dynamic-server.log"
CONFIG = json.loads((ROOT / "security/dynamic/config.yaml").read_text(encoding="utf-8"))
DYNAMIC_SCANNER_TOKEN_TTL_SECONDS = 900
DYNAMIC_SCANNER_WARMUP_PATHS = (
    "/api/v1/datasets",
    "/api/v1/access-requests/__schemathesis_warmup__",
)


def run(
    args: list[str], *, check: bool = True, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, check=check, text=True, capture_output=True, env=env)


def server_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    env["GRAA_RATE_LIMIT_ENABLED"] = "true"
    env["GRAA_RATE_LIMIT_REQUESTS"] = "500"
    env["GRAA_RATE_LIMIT_WINDOW_SECONDS"] = "60"
    return env


def dynamic_server_start() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    if PID_FILE.exists():
        try:
            os.kill(int(PID_FILE.read_text(encoding="utf-8")), 0)
            return
        except OSError:
            PID_FILE.unlink()
    log_handle = SERVER_LOG.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "genomic_research_access_api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=ROOT,
        env=server_env(),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    PID_FILE.write_text(str(process.pid), encoding="utf-8")


def dynamic_server_wait() -> None:
    import httpx

    url = validate_local_target(CONFIG["local_targets"]["default_base_url"]) + "/health"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=1)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.5)
    raise SystemExit(
        "Dynamic security local server did not become healthy.\n" + server_diagnostics()
    )


def server_diagnostics() -> str:
    details = []
    if PID_FILE.exists():
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


def dynamic_server_stop() -> None:
    if not PID_FILE.exists():
        return
    pid = int(PID_FILE.read_text(encoding="utf-8"))
    with suppress(OSError):
        os.kill(pid, signal.SIGTERM)
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


def write_openapi_schema() -> None:
    from genomic_research_access_api.main import create_app

    OPENAPI_FILE.write_text(json.dumps(create_app().openapi(), sort_keys=True), encoding="utf-8")


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
    target = validate_local_target(CONFIG["local_targets"]["docker_base_url"])
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


def warm_dynamic_routes(token: str) -> None:
    import httpx

    target = validate_local_target(CONFIG["local_targets"]["default_base_url"])
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=target, headers=headers, timeout=5) as client:
        for path in DYNAMIC_SCANNER_WARMUP_PATHS:
            response = client.get(path)
            if response.status_code >= 500:
                raise SystemExit(
                    f"Dynamic security warm-up failed for {path}: {response.status_code}"
                )


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
    payload: dict[str, object] = {
        "base_url": "local-docker-gateway",
        "case_count": generated,
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


def schemathesis_test() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    write_openapi_schema()
    token = issue_dev_token(
        subject="researcher-001",
        expires_in_seconds=DYNAMIC_SCANNER_TOKEN_TTL_SECONDS,
    )
    warm_dynamic_routes(token)
    command = schemathesis_command(token)
    print(f"python executable: {sys.executable}", flush=True)
    print(f"schemathesis image: {CONFIG['schemathesis']['container_image']}", flush=True)
    print("schemathesis command: " + " ".join(redact_command(command)), flush=True)
    result = run(command, check=False)
    (RAW / "schemathesis-output.txt").write_text(
        result.stdout + result.stderr, encoding="utf-8", newline="\n"
    )
    combined_output = result.stdout + result.stderr
    payload, completed = schemathesis_payload(combined_output, result.returncode)
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
    if not completed:
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
        result.stdout + result.stderr, encoding="utf-8", newline="\n"
    )
    report_path = RAW / "zap-report.json"
    if report_path.exists():
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    else:
        payload = {"site": [], "alerts": []}
    payload["execution_status"] = "completed" if result.returncode == 0 else "failed"
    payload["scan_mode"] = "baseline-passive"
    payload["target"] = "local-docker-gateway"
    payload["version"] = cfg["version"]
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def with_server(command: str) -> None:
    dynamic_server_start()
    try:
        dynamic_server_wait()
        {"schemathesis": schemathesis_test, "zap": zap_baseline}[command]()
    finally:
        dynamic_server_stop()


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
    commands: dict[str, Callable[[], None]] = {
        "tools": lambda: print(json.dumps(CONFIG, indent=2, sort_keys=True)),
        "server-start": dynamic_server_start,
        "server-wait": dynamic_server_wait,
        "server-stop": dynamic_server_stop,
        "pytest": dynamic_pytest,
        "schemathesis": lambda: with_server("schemathesis"),
        "zap": lambda: with_server("zap"),
        "evidence": dynamic_evidence,
        "report": dynamic_report,
        "full": dynamic_full,
    }
    commands[args.command]()


if __name__ == "__main__":
    main()
