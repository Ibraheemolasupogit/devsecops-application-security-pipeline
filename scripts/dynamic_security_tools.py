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
    raise SystemExit("Dynamic security local server did not become healthy.")


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
            str(ROOT / ".venv/bin/pytest"),
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


def schemathesis_test() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    write_openapi_schema()
    token = issue_dev_token(subject="researcher-001")
    cfg = CONFIG["schemathesis"]
    target = validate_local_target(CONFIG["local_targets"]["docker_base_url"])
    command = [
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
    result = run(command, check=False)
    (RAW / "schemathesis-output.txt").write_text(
        result.stdout + result.stderr, encoding="utf-8", newline="\n"
    )
    combined_output = result.stdout + result.stderr
    operations_match = re.search(r"Operations:\s+(\d+) selected / (\d+) total", combined_output)
    cases_match = re.search(r"Test cases:\s+(\d+) generated,\s+(\d+) passed", combined_output)
    payload = {
        "base_url": "local-docker-gateway",
        "case_count": int(cases_match.group(1)) if cases_match else 0,
        "checks": [
            {"name": name, "outcome": "passed" if result.returncode == 0 else "failed"}
            for name in [
                "not_a_server_error",
                "content_type_conformance",
                "response_schema_conformance",
            ]
        ],
        "execution_status": "completed" if result.returncode == 0 else "failed",
        "max_examples": cfg["max_examples"],
        "operation_count": int(operations_match.group(1)) if operations_match else 0,
        "request_timeout_seconds": cfg["request_timeout_seconds"],
        "version": cfg["version"],
    }
    (RAW / "schemathesis.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if result.returncode != 0:
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
    commands = {
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
