"""Milestone 5 AppSec scanner command wrappers."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "outputs/security/appsec/raw"
IMAGE = "devsecops-application-security-pipeline:milestone5"


def tool_image(name: str) -> str:
    payload = json.loads((ROOT / "security/config/tools.yaml").read_text(encoding="utf-8"))
    return str(payload["tools"][name]["container_image"])


def require(command: str) -> str:
    venv_command = ROOT / ".venv" / "bin" / command
    if venv_command.exists():
        return str(venv_command)
    path = shutil.which(command)
    if path is None:
        raise SystemExit(f"REQUIRED TOOL UNAVAILABLE: {command}")
    return path


def run(args: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT, check=True, env=env)


def semgrep_env() -> dict[str, str]:
    env = os.environ.copy()
    env["SEMGREP_SEND_METRICS"] = "off"
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    semgrep_home = ROOT / "outputs/security/appsec/.semgrep-home"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(semgrep_home)
    try:
        import certifi
    except ImportError:
        return env
    ca_bundle = certifi.where()
    env["SSL_CERT_FILE"] = ca_bundle
    env["REQUESTS_CA_BUNDLE"] = ca_bundle
    return env


def security_tools() -> None:
    print((ROOT / "security/config/tools.yaml").read_text(encoding="utf-8"))


def gitleaks() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    binary = shutil.which("gitleaks")
    if binary is None:
        run(
            [
                require("docker"),
                "run",
                "--rm",
                "-v",
                f"{ROOT}:/repo",
                "-w",
                "/repo",
                tool_image("gitleaks"),
                "detect",
                "--source",
                ".",
                "--config",
                ".gitleaks.toml",
                "--report-format",
                "json",
                "--report-path",
                "outputs/security/appsec/raw/gitleaks.json",
                "--no-banner",
            ]
        )
        return
    run(
        [
            binary,
            "detect",
            "--source",
            ".",
            "--config",
            ".gitleaks.toml",
            "--report-format",
            "json",
            "--report-path",
            str(RAW / "gitleaks.json"),
            "--no-banner",
        ]
    )


def semgrep() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    run(
        [
            require("semgrep"),
            "scan",
            "--config",
            "security/semgrep/rules",
            "--disable-version-check",
            "--json",
            "--output",
            str(RAW / "semgrep.json"),
            "--exclude",
            "security/fixtures",
            "--exclude",
            "security/semgrep",
        ],
        env=semgrep_env(),
    )


def semgrep_test() -> None:
    run([require("semgrep"), "test", "security/semgrep/rules"], env=semgrep_env())


def bandit() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    run(
        [
            require("bandit"),
            "-r",
            "src",
            "scripts",
            "-c",
            "security/bandit/bandit.yaml",
            "--severity-level",
            "medium",
            "--confidence-level",
            "medium",
            "-f",
            "json",
            "-o",
            str(RAW / "bandit.json"),
        ]
    )


def dependency_audit() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    run([require("pip-audit"), ".", "--format", "json", "--output", str(RAW / "pip-audit.json")])


def sbom() -> None:
    cyclonedx = shutil.which("cyclonedx-py")
    if cyclonedx is None:
        run(
            [sys.executable, "-m", "genomic_research_access_api.security.appsec.evidence", "--sbom"]
        )
    else:
        run(
            [
                cyclonedx,
                "environment",
                "--of",
                "JSON",
                "--output-file",
                "outputs/security/appsec/sbom.cdx.json",
            ]
        )


def checkov() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    output_dir = RAW / "checkov-output"
    if output_dir.exists():
        shutil.rmtree(output_dir)
    normalized_output = RAW / "checkov.json"
    if normalized_output.is_dir():
        shutil.rmtree(normalized_output)
    elif normalized_output.exists():
        normalized_output.unlink()
    run(
        [
            require("checkov"),
            "-d",
            "infrastructure",
            "--config-file",
            "security/checkov/config.yaml",
            "-o",
            "json",
            "--output-file-path",
            str(output_dir),
            "--soft-fail",
        ]
    )
    raw_output = (output_dir / "results_json.json").read_text(encoding="utf-8")
    normalized_output.write_text(raw_output.replace(str(ROOT), ""), encoding="utf-8")
    shutil.rmtree(output_dir)


def container_build() -> None:
    run([require("docker"), "build", "-t", IMAGE, "."])


def trivy() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    binary = shutil.which("trivy")
    if binary is None:
        run(
            [
                require("docker"),
                "run",
                "--rm",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                f"{ROOT}:/repo",
                "-w",
                "/repo",
                tool_image("trivy"),
                "image",
                "--format",
                "json",
                "--output",
                "outputs/security/appsec/raw/trivy.json",
                "--severity",
                "HIGH,CRITICAL",
                "--scanners",
                "vuln,secret,misconfig",
                IMAGE,
            ]
        )
        return
    run(
        [
            binary,
            "image",
            "--format",
            "json",
            "--output",
            str(RAW / "trivy.json"),
            "--severity",
            "HIGH,CRITICAL",
            "--scanners",
            "vuln,secret,misconfig",
            IMAGE,
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "security-tools",
            "gitleaks",
            "semgrep",
            "semgrep-test",
            "bandit",
            "dependency-audit",
            "sbom",
            "checkov",
            "container-build",
            "trivy",
        ],
    )
    args = parser.parse_args()
    {
        "security-tools": security_tools,
        "gitleaks": gitleaks,
        "semgrep": semgrep,
        "semgrep-test": semgrep_test,
        "bandit": bandit,
        "dependency-audit": dependency_audit,
        "sbom": sbom,
        "checkov": checkov,
        "container-build": container_build,
        "trivy": trivy,
    }[args.command]()


if __name__ == "__main__":
    main()
