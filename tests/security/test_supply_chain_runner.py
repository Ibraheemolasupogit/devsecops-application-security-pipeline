from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from genomic_research_access_api.security.supply_chain import runner
from genomic_research_access_api.security.supply_chain.contract import SupplyChainError
from genomic_research_access_api.security.threat_model.io import ROOT

COMMIT = "2" * 40
DIGEST = "sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _isolated_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    shutil.copytree(
        ROOT / "schemas/security/supply-chain", tmp_path / "schemas/security/supply-chain"
    )
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    (tmp_path / ".dockerignore").write_text("__pycache__/\n")
    output = tmp_path / "outputs/security/supply-chain"
    raw = tmp_path / "outputs/security/appsec/raw/trivy.json"
    output.mkdir(parents=True)
    raw.parent.mkdir(parents=True)
    monkeypatch.setattr(runner, "OUTPUT", output)
    monkeypatch.setattr(runner, "RAW_TRIVY", raw)
    return output, raw


def test_json_io_and_command_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, _ = _isolated_paths(tmp_path, monkeypatch)
    path = output / "record.json"
    runner._write_json(path, {"z": 2, "a": 1})
    assert runner._read_json(path) == {"a": 1, "z": 2}
    assert runner._relative(path) == "outputs/security/supply-chain/record.json"
    assert runner._sha256(path) == _sha(path)
    with pytest.raises(SupplyChainError, match="unreadable"):
        runner._read_json(output / "missing.json")
    with pytest.raises(SupplyChainError, match="JSON object"):
        array_path = output / "array.json"
        array_path.write_text("[]")
        runner._read_json(array_path)

    def command_failure(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(7, args[0][0])

    monkeypatch.setattr(subprocess, "run", command_failure)
    with pytest.raises(subprocess.CalledProcessError):
        runner._command(["false"])


def test_repository_and_dockerfile_inputs_are_sanitised(monkeypatch: pytest.MonkeyPatch) -> None:
    values = iter(
        [
            "git@github.com:example/project.git",
        ]
    )
    monkeypatch.setattr(runner, "_git", lambda *_: next(values))
    assert runner._repository_url() == "https://github.com/example/project"
    assert runner._local_image_ref(COMMIT) == f"genomic-research-access-api:git-{COMMIT}"


def test_build_records_one_buildx_digest_and_cleans_stale_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = _isolated_paths(tmp_path, monkeypatch)
    (tmp_path / "Dockerfile").write_text("FROM python:3.11.17-slim-trixie\n")
    (tmp_path / ".dockerignore").write_text("__pycache__/\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nversion='0.1.0'\n")
    stale = output / "publication-eligibility.json"
    stale.write_text('{"status":"eligible"}\n')
    monkeypatch.setattr(runner, "_source_identity", lambda: (COMMIT, "2026-10-12T00:00:00Z", False))
    monkeypatch.setattr(
        runner,
        "_dockerfile_inputs",
        lambda: (
            _sha(tmp_path / "Dockerfile"),
            _sha(tmp_path / ".dockerignore"),
            _sha(tmp_path / "pyproject.toml"),
            "python:3.11.17-slim-trixie",
        ),
    )
    monkeypatch.setattr(
        runner,
        "_git",
        lambda *args: "https://github.com/example/project.git"
        if args[0] == "config"
        else "1791763200",
    )
    monkeypatch.setattr(runner, "validate_runtime", lambda *_: None)

    def fake_command(command: list[str], *, capture: bool = False) -> str:
        if command[:3] == ["docker", "buildx", "build"]:
            metadata = Path(command[command.index("--metadata-file") + 1])
            metadata.write_text(json.dumps({"containerimage.digest": DIGEST}))
        if command[:3] == ["docker", "image", "inspect"]:
            return IMAGE_ID
        if command[:3] == ["docker", "buildx", "version"]:
            return "github.com/docker/buildx v0.20.1"
        return ""

    monkeypatch.setattr(runner, "_command", fake_command)
    metadata = runner.build()
    assert metadata["image_digest"] == DIGEST
    assert metadata["image_id"] == IMAGE_ID
    assert metadata["dirty_worktree"] is False
    assert metadata["built_image_reference"].endswith(f":git-{COMMIT}")
    assert not stale.exists()
    assert not (output / ".buildx-metadata.tmp.json").exists()
    assert json.loads((output / "image-metadata.json").read_text())["tag_is_authoritative"] is False


def test_runtime_probe_requires_readonly_uid_and_health(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def command(args: list[str], *, capture: bool = False) -> str:
        calls.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            return IMAGE_ID
        if args[-2:] == ["id", "-u"]:
            return "10001"
        return ""

    results = iter(
        [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )
    monkeypatch.setattr(runner, "_command", command)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: next(results))
    runner.validate_runtime("local:git-test", IMAGE_ID)
    assert any("--read-only" in command_args for command_args in calls)
    assert any("10001:10001" in command_args for command_args in calls)


def test_container_sbom_and_scan_use_the_built_local_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, raw = _isolated_paths(tmp_path, monkeypatch)
    metadata = {
        "image_digest": DIGEST,
        "built_image_reference": f"api:git-{COMMIT}",
        "image_id": IMAGE_ID,
    }
    monkeypatch.setattr(runner, "_assert_built_image", lambda: metadata)
    monkeypatch.setattr(shutil, "which", lambda name: "/bin/trivy")
    sbom_payload = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "api"}]}

    def generate_sbom(_image: str, path: Path) -> None:
        path.write_text(json.dumps(sbom_payload))

    monkeypatch.setattr(runner, "_generate_container_sbom", generate_sbom)
    monkeypatch.setattr(runner, "_command", lambda *_a, **_k: "Version: 0.54.1")
    sbom_summary = runner.sbom()
    assert sbom_summary["artifact_digest"] == DIGEST
    assert sbom_summary["component_count"] == 1

    scan_payload = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "Severity": "HIGH",
                        "VulnerabilityID": "CVE-2026-1234",
                        "PkgName": "demo-package",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "2.0",
                        "Title": "Test vulnerability",
                    }
                ],
                "Secrets": [],
                "Misconfigurations": [],
            }
        ]
    }

    def scan_command(args: list[str], *, capture: bool = False) -> str:
        if "--output" in args:
            scan_output = Path(args[args.index("--output") + 1])
            if not scan_output.is_absolute():
                scan_output = output.parents[2] / scan_output
            scan_output.write_text(json.dumps(scan_payload))
        return "Version: 0.54.1"

    monkeypatch.setattr(runner, "_command", scan_command)
    monkeypatch.setattr(
        runner,
        "trivy_summary",
        lambda: {"suppressed_count": 0, "blocking_count": 1, "policy_decision": "block"},
    )
    summary = runner.scan()
    assert summary["image_digest"] == DIGEST
    assert summary["counts_by_severity"]["HIGH"] == 1
    assert summary["blocking_count"] == 1
    assert raw.is_file()
    assert (output / "container-scan-summary.json").is_file()


def test_trivy_container_fallback_path_is_pinned_and_generates_image_sbom(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = _isolated_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    commands: list[list[str]] = []

    def docker_trivy(args: list[str], *, capture: bool = False) -> str:
        commands.append(args)
        relative_output = args[args.index("--output") + 1]
        target = output.parents[2] / relative_output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "api"}]}))
        return ""

    monkeypatch.setattr(runner, "_command", docker_trivy)
    runner._generate_container_sbom("local:git-candidate", output / "container-sbom.cdx.json")
    assert commands[0][0:3] == ["docker", "run", "--rm"]
    assert "aquasec/trivy:0.54.1" in commands[0]


def test_publish_requires_eligible_candidate_before_any_aws_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolated_paths(tmp_path, monkeypatch)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("SUPPLY_CHAIN_OIDC_AUTHENTICATED", "true")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "offline-test-session")
    monkeypatch.setattr(
        runner,
        "_read_json",
        lambda path: {"status": "blocked", "publication_allowed": False},
    )
    called = False

    def forbidden(*_args: Any, **_kwargs: Any) -> str:
        nonlocal called
        called = True
        return ""

    monkeypatch.setattr(runner, "_command", forbidden)
    with pytest.raises(SupplyChainError, match="blocked"):
        runner.publish(
            repository_url="123456789012.dkr.ecr.eu-west-2.amazonaws.com/genomic-research-access-api",
            region="eu-west-2",
            role_arn="arn:aws:iam::123456789012:role/graa-artifact-publisher",
        )
    assert called is False


def test_publish_uses_mocked_oidc_ecr_push_and_checks_exact_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = _isolated_paths(tmp_path, monkeypatch)
    repository_url = "123456789012.dkr.ecr.eu-west-2.amazonaws.com/genomic-research-access-api"
    role_arn = "arn:aws:iam::123456789012:role/graa-artifact-publisher"
    manifest = {
        "schema_version": "1.0",
        "source_commit": COMMIT,
        "image_repository": "genomic-research-access-api",
        "source_image_tag": f"genomic-research-access-api:git-{COMMIT}",
        "local_digest": DIGEST,
        "published_digest": None,
        "ecr_repository_url": None,
        "sbom_reference": "sbom.json",
        "provenance_reference": "provenance.json",
        "container_scan_reference": "scan.json",
        "release_decision": "pass",
        "release_decision_id": "REL-0123456789abcdef",
        "publication_decision": "eligible",
        "build_timestamp": "2026-10-12T00:00:00Z",
        "verification_status": "locally_verified",
    }
    runner._write_json(output / "release-artifact.json", manifest)
    runner._write_json(
        output / "publication-eligibility.json", {"status": "eligible", "publication_allowed": True}
    )
    runner._write_json(output / "build-metadata.json", {"image_id": IMAGE_ID})
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("SUPPLY_CHAIN_OIDC_AUTHENTICATED", "true")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "offline-test-session")
    monkeypatch.setattr(runner, "_source_identity", lambda: (COMMIT, "2026-10-12T00:00:00Z", False))
    commands: list[list[str]] = []

    def docker_and_aws(args: list[str], *, capture: bool = False) -> str:
        commands.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            return IMAGE_ID
        if args[:4] == ["aws", "ecr", "describe-images", "--region"]:
            return DIGEST
        return ""

    def mocked_aws_calls(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:4] == ["aws", "ecr", "get-login-password", "--region"]:
            return subprocess.CompletedProcess(args, 0, "offline-password", "")
        assert args[:4] == ["docker", "login", "--username", "AWS"]
        assert kwargs["input"] == "offline-password"
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner, "_command", docker_and_aws)
    monkeypatch.setattr(subprocess, "run", mocked_aws_calls)
    monkeypatch.setattr(runner, "_finalize_integrity", lambda *_: None)
    monkeypatch.setattr(runner, "verify", lambda: None)
    result = runner.publish(repository_url=repository_url, region="eu-west-2", role_arn=role_arn)
    assert result["published_digest"] == DIGEST
    assert result["verification_status"] == "published_verified"
    assert any(args[:2] == ["docker", "push"] for args in commands)
    assert any(args[:3] == ["aws", "ecr", "describe-images"] for args in commands)


@pytest.mark.parametrize(
    ("command", "target", "result"),
    [
        ("build", "build", {"image_digest": DIGEST}),
        ("sbom", "sbom", {"component_count": 1}),
        ("scan", "scan", {"blocking_count": 0}),
        ("provenance", "assurance", {"status": "eligible"}),
        ("publication-manifest", "publication_manifest", {"local_digest": DIGEST}),
        ("full", "run_full", {"status": "eligible"}),
    ],
)
def test_cli_dispatches_to_repository_owned_operations(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    target: str,
    result: dict[str, Any],
) -> None:
    monkeypatch.setattr(sys, "argv", ["container_supply_chain.py", command])
    monkeypatch.setattr(runner, target, lambda **_kwargs: result)
    runner.main()
    assert json.loads(capsys.readouterr().out) == result


def test_assurance_generation_links_release_findings_sbom_scan_and_checksums(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, raw = _isolated_paths(tmp_path, monkeypatch)
    (tmp_path / "Dockerfile").write_text("FROM python:3.11.17-slim-trixie\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nversion='0.1.0'\n")
    release_dir = tmp_path / "outputs/security/release"
    findings_dir = tmp_path / "outputs/security/findings"
    release_dir.mkdir(parents=True)
    findings_dir.mkdir(parents=True)
    release = {
        "decision": "pass",
        "decision_id": "REL-0123456789abcdef",
    }
    (release_dir / "release-gate-decision.json").write_text(json.dumps(release))
    (findings_dir / "deduplicated-findings.json").write_text(
        json.dumps({"findings": [{"finding_id": "FND-CONTAINER-123456", "source_tool": "trivy"}]})
    )
    sbom_data = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "api"}]}
    sbom_path = output / "container-sbom.cdx.json"
    sbom_path.write_text(json.dumps(sbom_data))
    (output / "image-metadata.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "source_commit": COMMIT,
                "repository": "genomic-research-access-api",
                "tag": f"git-{COMMIT}",
                "tag_is_authoritative": False,
                "image_id": IMAGE_ID,
                "digest": DIGEST,
                "target_platform": "linux/amd64",
            }
        )
    )
    raw.write_text(json.dumps({"Results": []}))
    scan_summary = {
        "schema_version": "1.0",
        "scanner": "Trivy",
        "scanner_version": "0.54.1",
        "execution_status": "completed",
        "image_reference": f"genomic-research-access-api:git-{COMMIT}",
        "image_digest": DIGEST,
        "finding_count": 0,
        "counts_by_severity": {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
        "suppressed_count": 0,
        "blocking_count": 0,
        "policy_outcome": "pass",
        "canonical_findings_reference": "outputs/security/findings/deduplicated-findings.json",
        "raw_evidence_reference": "outputs/security/appsec/raw/trivy.json",
        "raw_evidence_sha256": _sha(raw),
    }
    runner._write_json(
        output / "sbom-summary.json",
        {
            "schema_version": "1.0",
            "format": "CycloneDX JSON",
            "spec_version": "1.5",
            "generator": "Trivy",
            "generator_version": "0.54.1",
            "component_count": 1,
            "artifact_digest": DIGEST,
            "sbom_reference": "outputs/security/supply-chain/container-sbom.cdx.json",
            "sha256": _sha(sbom_path),
        },
    )
    runner._write_json(output / "container-scan-summary.json", scan_summary)
    runner._write_json(
        output / "build-metadata.json",
        {
            "schema_version": "1.0",
            "source_repository": "https://github.com/example/project",
            "repository_name": "project",
            "source_commit": COMMIT,
            "controlled_timestamp": "2026-10-12T00:00:00Z",
            "application_version": "0.1.0",
            "dockerfile_sha256": _sha(tmp_path / "Dockerfile"),
            "dockerignore_sha256": _sha(tmp_path / ".dockerignore"),
            "dependency_definition_sha256": _sha(tmp_path / "pyproject.toml"),
            "dependency_inputs": ["pyproject.toml"],
            "base_image_reference": "python:3.11.17-slim-trixie",
            "built_image_reference": f"genomic-research-access-api:git-{COMMIT}",
            "image_id": IMAGE_ID,
            "image_digest": DIGEST,
            "target_platform": "linux/amd64",
            "builder": {"docker_buildx": "buildx v0.20.1"},
            "dirty_worktree": False,
            "build_command_policy": "one build",
            "sbom_reference": None,
            "sbom_sha256": None,
            "container_scan_reference": None,
            "container_scan_sha256": None,
            "release_decision_reference": None,
            "release_decision_sha256": None,
            "release_decision_id": None,
            "release_decision": None,
            "publication_eligibility_reference": (
                "outputs/security/supply-chain/publication-eligibility.json"
            ),
            "publication_eligibility_status": "pending",
        },
    )

    monkeypatch.setattr(
        "genomic_research_access_api.security.appsec.evidence.generate_evidence", lambda **_: []
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.appsec.evidence.verify_evidence", lambda: None
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.findings.evidence.generate", lambda **_: []
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.findings.evidence.verify", lambda: None
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.release.evidence.generate", lambda **_: []
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.release.evidence.verify", lambda: None
    )
    monkeypatch.setattr(runner, "generate_findings", lambda **_: [])
    monkeypatch.setattr(runner, "generate_release", lambda **_: [])
    result = runner.assurance(timestamp="2026-10-12T00:00:00Z", as_of_date="2026-10-12")
    assert result["status"] == "eligible"
    assert result["publication_allowed"] is True
    assert result["container_findings"] == ["FND-CONTAINER-123456"]
    assert (output / "checksums.sha256").is_file()
    assert (output / "supply-chain-manifest.json").is_file()
    runner.verify()
    sbom_path.write_text(json.dumps({**sbom_data, "components": []}))
    with pytest.raises(SupplyChainError, match="checksum"):
        runner.verify()
