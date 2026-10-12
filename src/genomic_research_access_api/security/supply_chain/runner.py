"""Canonical build-once, scan, evidence, and optional ECR publication workflow."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from genomic_research_access_api.security.appsec.parsers import trivy_summary
from genomic_research_access_api.security.findings.evidence import generate as generate_findings
from genomic_research_access_api.security.release.evidence import generate as generate_release
from genomic_research_access_api.security.supply_chain.contract import (
    SupplyChainError,
    canonical_json,
    evaluate_publication,
    validate_checksum_index,
    validate_digest,
    validate_publication_manifest,
    validate_release_reference,
)
from genomic_research_access_api.security.threat_model.io import ROOT
from genomic_research_access_api.version import __version__

OUTPUT = ROOT / "outputs/security/supply-chain"
RAW_TRIVY = ROOT / "outputs/security/appsec/raw/trivy.json"
IMAGE_REPOSITORY = "genomic-research-access-api"
ECR_REPOSITORY = "genomic-research-access-api"
PLATFORM = "linux/amd64"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SupplyChainError(
            f"required evidence is unreadable: {path.relative_to(ROOT)}"
        ) from exc
    if not isinstance(value, dict):
        raise SupplyChainError(f"evidence must be a JSON object: {path.relative_to(ROOT)}")
    return value


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _command(command: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def _git(*args: str) -> str:
    return _command(["git", *args], capture=True)


def _source_identity() -> tuple[str, str, bool]:
    commit = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise SupplyChainError("Git source commit is unavailable")
    committed_at = (
        dt.datetime.fromtimestamp(int(_git("show", "-s", "--format=%ct", commit)), dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    status = _git("status", "--porcelain", "--untracked-files=all")
    source_changes = [
        line for line in status.splitlines() if not line[3:].startswith(("outputs/", "reports/"))
    ]
    dirty = bool(source_changes)
    return commit, committed_at, dirty


def _repository_url() -> str:
    remote = _git("config", "--get", "remote.origin.url")
    if remote.startswith("git@github.com:"):
        return "https://github.com/" + remote.removeprefix("git@github.com:").removesuffix(".git")
    parsed = urlsplit(remote)
    if parsed.scheme and parsed.hostname:
        return urlunsplit(
            (parsed.scheme, parsed.hostname, parsed.path.removesuffix(".git"), "", "")
        )
    raise SupplyChainError("origin must identify a GitHub source repository")


def _dockerfile_inputs() -> tuple[str, str, str, str]:
    dockerfile = ROOT / "Dockerfile"
    dockerignore = ROOT / ".dockerignore"
    pyproject = ROOT / "pyproject.toml"
    docker_text = dockerfile.read_text(encoding="utf-8")
    base = next(
        (
            line.split(maxsplit=1)[1].strip()
            for line in docker_text.splitlines()
            if line.startswith("FROM ")
        ),
        "unknown",
    )
    return _sha256(dockerfile), _sha256(dockerignore), _sha256(pyproject), base


def _local_image_ref(commit: str) -> str:
    return f"{IMAGE_REPOSITORY}:git-{commit[:40]}"


def _assert_built_image() -> dict[str, Any]:
    metadata = _read_json(OUTPUT / "build-metadata.json")
    image_id = _command(
        [
            "docker",
            "image",
            "inspect",
            str(metadata.get("built_image_reference", "")),
            "--format",
            "{{.Id}}",
        ],
        capture=True,
    )
    if image_id != metadata.get("image_id"):
        raise SupplyChainError(
            "local image ID differs from the image built and recorded by this run"
        )
    return metadata


def validate_runtime(image_ref: str, image_id: str) -> None:
    """Exercise the built image as UID 10001 with a read-only root and real health route."""
    name = f"graa-supply-chain-{os.getpid()}"
    runtime_tmp = os.path.join(os.sep, "tmp")
    _command(
        [
            "docker",
            "run",
            "--rm",
            "--detach",
            "--name",
            name,
            "--read-only",
            "--tmpfs",
            f"{runtime_tmp}:rw,noexec,nosuid,size=16m",
            "--network",
            "none",
            "--user",
            "10001:10001",
            image_ref,
        ]
    )
    deadline = time.monotonic() + 30
    last_error = "container health endpoint did not respond"
    try:
        observed_id = _command(
            ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"], capture=True
        )
        if observed_id != image_id:
            raise SupplyChainError("image identity changed before runtime validation")
        while time.monotonic() < deadline:
            probe = subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "python",
                    "-c",
                    (
                        "import urllib.request; "
                        "urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"
                    ),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if probe.returncode == 0:
                uid = _command(["docker", "exec", name, "id", "-u"], capture=True)
                if uid != "10001":
                    raise SupplyChainError("application container did not run with UID 10001")
                return
            last_error = probe.stderr.strip() or probe.stdout.strip() or last_error
            time.sleep(0.5)
        raise SupplyChainError(f"read-only non-root container health check failed: {last_error}")
    finally:
        subprocess.run(
            ["docker", "container", "rm", "--force", name],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )


def build(*, platform: str = PLATFORM) -> dict[str, Any]:
    commit, timestamp, dirty = _source_identity()
    dockerfile_sha, dockerignore_sha, dependencies_sha, base_image = _dockerfile_inputs()
    image_ref = _local_image_ref(commit)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name in (
        "build-metadata.json",
        "image-metadata.json",
        "sbom-summary.json",
        "container-scan-summary.json",
        "container-sbom.cdx.json",
        "provenance.json",
        "publication-eligibility.json",
        "release-artifact.json",
        "supply-chain-manifest.json",
        "checksums.sha256",
    ):
        (OUTPUT / name).unlink(missing_ok=True)
    metadata_file = OUTPUT / ".buildx-metadata.tmp.json"
    try:
        _command(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                platform,
                "--load",
                "--metadata-file",
                str(metadata_file),
                "--build-arg",
                f"APP_VERSION={__version__}",
                "--build-arg",
                f"VCS_REF={commit}",
                "--build-arg",
                f"BUILD_TIMESTAMP={timestamp}",
                "--build-arg",
                f"SOURCE_DATE_EPOCH={_git('show', '-s', '--format=%ct', commit)}",
                "--tag",
                image_ref,
                ".",
            ]
        )
        buildx_metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    finally:
        metadata_file.unlink(missing_ok=True)
    digest = validate_digest(buildx_metadata.get("containerimage.digest"))
    image_id = _command(
        ["docker", "image", "inspect", image_ref, "--format", "{{.Id}}"], capture=True
    )
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise SupplyChainError("Docker did not return a valid built image ID")
    validate_runtime(image_ref, image_id)
    if (
        _sha256(ROOT / "Dockerfile") != dockerfile_sha
        or _sha256(ROOT / ".dockerignore") != dockerignore_sha
        or _sha256(ROOT / "pyproject.toml") != dependencies_sha
    ):
        raise SupplyChainError("build input changed while the image was being built")
    buildx_version = _command(["docker", "buildx", "version"], capture=True)
    build_metadata = {
        "schema_version": "1.0",
        "source_repository": _repository_url(),
        "repository_name": "devsecops-application-security-pipeline",
        "source_commit": commit,
        "controlled_timestamp": timestamp,
        "application_version": __version__,
        "dockerfile_sha256": dockerfile_sha,
        "dockerignore_sha256": dockerignore_sha,
        "dependency_definition_sha256": dependencies_sha,
        "dependency_inputs": ["pyproject.toml"],
        "base_image_reference": base_image,
        "built_image_reference": image_ref,
        "image_id": image_id,
        "image_digest": digest,
        "target_platform": platform,
        "builder": {"docker_buildx": buildx_version},
        "dirty_worktree": dirty,
        "build_command_policy": (
            "docker buildx build --load --platform linux/amd64 with OCI source labels"
        ),
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
    }
    _write_json(OUTPUT / "build-metadata.json", build_metadata)
    _write_json(
        OUTPUT / "image-metadata.json",
        {
            "schema_version": "1.0",
            "source_commit": commit,
            "repository": IMAGE_REPOSITORY,
            "tag": f"git-{commit}",
            "tag_is_authoritative": False,
            "image_id": image_id,
            "digest": digest,
            "target_platform": platform,
        },
    )
    return build_metadata


def _generate_container_sbom(image_ref: str, output_path: Path) -> None:
    binary = shutil.which("trivy")
    if binary:
        _command(
            [binary, "image", "--format", "cyclonedx", "--output", str(output_path), image_ref]
        )
        return
    _command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{ROOT}:/repo",
            "-w",
            "/repo",
            "aquasec/trivy:0.54.1",
            "image",
            "--format",
            "cyclonedx",
            "--output",
            _relative(output_path),
            image_ref,
        ]
    )


def sbom() -> dict[str, Any]:
    metadata = _assert_built_image()
    digest = validate_digest(metadata.get("image_digest"))
    path = OUTPUT / "container-sbom.cdx.json"
    path.unlink(missing_ok=True)
    (OUTPUT / "sbom-summary.json").unlink(missing_ok=True)
    _generate_container_sbom(str(metadata["built_image_reference"]), path)
    _assert_built_image()
    payload = _read_json(path)
    if payload.get("bomFormat") != "CycloneDX":
        raise SupplyChainError("Trivy did not return a CycloneDX container SBOM")
    sbom_text = path.read_text(encoding="utf-8")
    if "/Users/" in sbom_text or "/private/" in sbom_text:
        raise SupplyChainError("container SBOM contains a machine-specific absolute path")
    component_count = len(payload.get("components", []))
    if component_count < 1:
        raise SupplyChainError("container SBOM has no components")
    trivy_binary = shutil.which("trivy")
    trivy_version = (
        _command([trivy_binary, "--version"], capture=True).splitlines()[0]
        if trivy_binary
        else "0.54.1"
    )
    summary = {
        "schema_version": "1.0",
        "format": "CycloneDX JSON",
        "spec_version": payload.get("specVersion"),
        "generator": "Trivy",
        "generator_version": trivy_version,
        "component_count": component_count,
        "artifact_digest": digest,
        "sbom_reference": _relative(path),
        "sha256": _sha256(path),
    }
    _write_json(OUTPUT / "sbom-summary.json", summary)
    return summary


def scan() -> dict[str, Any]:
    metadata = _assert_built_image()
    digest = validate_digest(metadata.get("image_digest"))
    image_ref = str(metadata.get("built_image_reference", ""))
    RAW_TRIVY.unlink(missing_ok=True)
    (OUTPUT / "container-scan-summary.json").unlink(missing_ok=True)
    binary = shutil.which("trivy")
    output = _relative(RAW_TRIVY)
    if binary:
        _command(
            [
                binary,
                "image",
                "--format",
                "json",
                "--output",
                output,
                "--severity",
                "HIGH,CRITICAL",
                "--scanners",
                "vuln,secret,misconfig",
                image_ref,
            ]
        )
        version = _command([binary, "--version"], capture=True).splitlines()[0]
    else:
        _command(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                f"{ROOT}:/repo",
                "-w",
                "/repo",
                "aquasec/trivy:0.54.1",
                "image",
                "--format",
                "json",
                "--output",
                output,
                "--severity",
                "HIGH,CRITICAL",
                "--scanners",
                "vuln,secret,misconfig",
                image_ref,
            ]
        )
        version = "0.54.1"
    _assert_built_image()
    result = _read_json(RAW_TRIVY)
    counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    findings: list[dict[str, Any]] = []
    for item in result.get("Results", []):
        for collection in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            for finding in item.get(collection, []):
                findings.append(finding)
                severity = str(finding.get("Severity", "UNKNOWN")).upper()
                counts[severity if severity in counts else "UNKNOWN"] += 1
    summary = trivy_summary()
    scan_summary = {
        "schema_version": "1.0",
        "scanner": "Trivy",
        "scanner_version": version,
        "execution_status": "completed",
        "image_reference": image_ref,
        "image_digest": digest,
        "finding_count": len(findings),
        "counts_by_severity": counts,
        "suppressed_count": int(summary["suppressed_count"]),
        "blocking_count": int(summary["blocking_count"]),
        "policy_outcome": str(summary["policy_decision"]),
        "canonical_findings_reference": "outputs/security/findings/deduplicated-findings.json",
        "raw_evidence_reference": _relative(RAW_TRIVY),
        "raw_evidence_sha256": _sha256(RAW_TRIVY),
    }
    _write_json(OUTPUT / "container-scan-summary.json", scan_summary)
    return scan_summary


def _canonical_finding_ids() -> list[str]:
    findings = _read_json(ROOT / "outputs/security/findings/deduplicated-findings.json")
    items = findings.get("findings", [])
    return sorted(
        str(item["finding_id"])
        for item in items
        if isinstance(item, dict) and item.get("source_tool") == "trivy" and item.get("finding_id")
    )


def assurance(
    *, timestamp: str = DEFAULT_TIMESTAMP, as_of_date: str = "2026-01-01"
) -> dict[str, Any]:
    from genomic_research_access_api.security.appsec.evidence import (
        generate_evidence,
    )
    from genomic_research_access_api.security.appsec.evidence import (
        verify_evidence as verify_appsec,
    )
    from genomic_research_access_api.security.findings.evidence import verify as verify_findings
    from genomic_research_access_api.security.release.evidence import verify as verify_release

    generate_evidence(timestamp=timestamp)
    verify_appsec()
    generate_findings(timestamp=timestamp, as_of_date=as_of_date)
    verify_findings()
    generate_release(timestamp=timestamp, as_of_date=as_of_date, environment="dev")
    verify_release()
    release = _read_json(ROOT / "outputs/security/release/release-gate-decision.json")
    scan_summary = _read_json(OUTPUT / "container-scan-summary.json")
    sbom_summary = _read_json(OUTPUT / "sbom-summary.json")
    manifest = _read_json(OUTPUT / "build-metadata.json")
    release_reference = "outputs/security/release/release-gate-decision.json"
    manifest.update(
        {
            "sbom_reference": _relative(OUTPUT / "container-sbom.cdx.json"),
            "sbom_sha256": _sha256(OUTPUT / "container-sbom.cdx.json"),
            "container_scan_reference": _relative(OUTPUT / "container-scan-summary.json"),
            "container_scan_sha256": _sha256(OUTPUT / "container-scan-summary.json"),
            "release_decision_reference": release_reference,
            "release_decision_sha256": _sha256(ROOT / release_reference),
            "release_decision_id": release["decision_id"],
            "release_decision": release["decision"],
        }
    )
    _write_json(OUTPUT / "build-metadata.json", manifest)
    provenance = {
        "schema_version": "1.0",
        "predicate_type": "https://devsecops.example/supply-chain/provenance/v1",
        "source_repository": manifest["source_repository"],
        "source_commit": manifest["source_commit"],
        "build_metadata_reference": _relative(OUTPUT / "build-metadata.json"),
        "build_metadata_sha256": _sha256(OUTPUT / "build-metadata.json"),
        "dockerfile_sha256": manifest["dockerfile_sha256"],
        "dockerignore_sha256": manifest["dockerignore_sha256"],
        "dependency_definition_sha256": manifest["dependency_definition_sha256"],
        "build_command_policy": manifest["build_command_policy"],
        "image_digest": validate_digest(manifest["image_digest"]),
        "sbom_reference": sbom_summary["sbom_reference"],
        "sbom_sha256": sbom_summary["sha256"],
        "container_scan_reference": _relative(OUTPUT / "container-scan-summary.json"),
        "container_scan_sha256": _sha256(OUTPUT / "container-scan-summary.json"),
        "canonical_trivy_finding_ids": _canonical_finding_ids(),
        "release_decision_reference": "outputs/security/release/release-gate-decision.json",
        "release_decision_sha256": _sha256(
            ROOT / "outputs/security/release/release-gate-decision.json"
        ),
        "release_decision_id": release["decision_id"],
        "release_decision": release["decision"],
        "publication_eligibility_reference": (
            "outputs/security/supply-chain/publication-eligibility.json"
        ),
    }
    build_integrity = (
        manifest["dockerfile_sha256"] == _sha256(ROOT / "Dockerfile")
        and manifest["dockerignore_sha256"] == _sha256(ROOT / ".dockerignore")
        and manifest["dependency_definition_sha256"] == _sha256(ROOT / "pyproject.toml")
        and manifest["sbom_sha256"] == _sha256(OUTPUT / "container-sbom.cdx.json")
        and manifest["container_scan_sha256"] == _sha256(OUTPUT / "container-scan-summary.json")
        and manifest["release_decision_sha256"] == _sha256(ROOT / release_reference)
    )
    _write_json(OUTPUT / "provenance.json", provenance)
    publication = evaluate_publication(
        build_succeeded=True,
        build_integrity=build_integrity,
        worktree_clean=not bool(manifest.get("dirty_worktree", True)),
        image_digest=manifest.get("image_digest"),
        sbom_integrity=_sha256(OUTPUT / "container-sbom.cdx.json") == sbom_summary["sha256"],
        scan_completed=scan_summary["execution_status"] == "completed",
        scan_blocking_count=int(scan_summary["blocking_count"]),
        provenance_integrity=(
            provenance["image_digest"]
            == sbom_summary["artifact_digest"]
            == scan_summary["image_digest"]
            and provenance["release_decision_sha256"]
            == _sha256(ROOT / provenance["release_decision_reference"])
            and provenance["build_metadata_sha256"] == _sha256(OUTPUT / "build-metadata.json")
        ),
        release_decision=str(release["decision"]),
    )
    manifest["publication_eligibility_status"] = publication["status"]
    _write_json(OUTPUT / "build-metadata.json", manifest)
    provenance["build_metadata_sha256"] = _sha256(OUTPUT / "build-metadata.json")
    _write_json(OUTPUT / "provenance.json", provenance)
    publication = evaluate_publication(
        build_succeeded=True,
        build_integrity=build_integrity,
        worktree_clean=not bool(manifest.get("dirty_worktree", True)),
        image_digest=manifest.get("image_digest"),
        sbom_integrity=_sha256(OUTPUT / "container-sbom.cdx.json") == sbom_summary["sha256"],
        scan_completed=scan_summary["execution_status"] == "completed",
        scan_blocking_count=int(scan_summary["blocking_count"]),
        provenance_integrity=(
            provenance["image_digest"]
            == sbom_summary["artifact_digest"]
            == scan_summary["image_digest"]
            and provenance["release_decision_sha256"] == _sha256(ROOT / release_reference)
            and provenance["build_metadata_sha256"] == _sha256(OUTPUT / "build-metadata.json")
        ),
        release_decision=str(release["decision"]),
    )
    manifest["publication_eligibility_status"] = publication["status"]
    _write_json(OUTPUT / "build-metadata.json", manifest)
    provenance["build_metadata_sha256"] = _sha256(OUTPUT / "build-metadata.json")
    _write_json(OUTPUT / "provenance.json", provenance)
    publication.update(
        {
            "release_decision_id": release["decision_id"],
            "container_findings": _canonical_finding_ids(),
            "container_scan_reference": _relative(OUTPUT / "container-scan-summary.json"),
            "sbom_reference": _relative(OUTPUT / "container-sbom.cdx.json"),
            "provenance_reference": _relative(OUTPUT / "provenance.json"),
        }
    )
    _write_json(OUTPUT / "publication-eligibility.json", publication)
    release_artifact = {
        "schema_version": "1.0",
        "source_commit": manifest["source_commit"],
        "image_repository": IMAGE_REPOSITORY,
        "source_image_tag": manifest["built_image_reference"],
        "local_digest": manifest["image_digest"],
        "published_digest": None,
        "ecr_repository_url": None,
        "sbom_reference": _relative(OUTPUT / "container-sbom.cdx.json"),
        "provenance_reference": _relative(OUTPUT / "provenance.json"),
        "container_scan_reference": _relative(OUTPUT / "container-scan-summary.json"),
        "release_decision": release["decision"],
        "release_decision_id": release["decision_id"],
        "publication_decision": publication["status"],
        "build_timestamp": manifest["controlled_timestamp"],
        "verification_status": "locally_verified"
        if publication["status"] != "blocked"
        else "blocked",
    }
    validate_publication_manifest(release_artifact)
    _write_json(OUTPUT / "release-artifact.json", release_artifact)
    _finalize_integrity(release_artifact)
    return publication


def publication_manifest() -> dict[str, Any]:
    manifest = _read_json(OUTPUT / "release-artifact.json")
    validate_publication_manifest(manifest)
    return manifest


def validate_assurance_links(
    release_artifact: dict[str, Any],
    sbom_summary: dict[str, Any],
    scan_summary: dict[str, Any],
    provenance: dict[str, Any],
) -> None:
    digest = validate_digest(release_artifact.get("local_digest"))
    linked_digests = {
        sbom_summary.get("artifact_digest"),
        scan_summary.get("image_digest"),
        provenance.get("image_digest"),
    }
    if linked_digests != {digest}:
        raise SupplyChainError("SBOM, scan, provenance, and publication digests do not match")
    published = release_artifact.get("published_digest")
    if published is not None and validate_digest(published) != digest:
        raise SupplyChainError("published image digest differs from QA candidate digest")


def verify() -> None:
    manifest = publication_manifest()
    expected = _evidence_checksums()
    checksums_path = OUTPUT / "checksums.sha256"
    if not checksums_path.is_file():
        raise SupplyChainError("supply-chain checksum index is missing")
    manifest_files = _read_json(OUTPUT / "supply-chain-manifest.json").get("files", {})
    validate_checksum_index(expected, checksums_path.read_text(encoding="utf-8"), manifest_files)
    provenance = _read_json(OUTPUT / "provenance.json")
    if provenance.get("image_digest") != manifest["local_digest"]:
        raise SupplyChainError("provenance and release artifact digests do not match")
    sbom_summary = _read_json(OUTPUT / "sbom-summary.json")
    scan_summary = _read_json(OUTPUT / "container-scan-summary.json")
    build_meta = _read_json(OUTPUT / "build-metadata.json")
    if sbom_summary.get("sha256") != _sha256(OUTPUT / "container-sbom.cdx.json"):
        raise SupplyChainError("container SBOM checksum differs from its summary")
    if scan_summary.get("raw_evidence_sha256") != _sha256(RAW_TRIVY):
        raise SupplyChainError("Trivy evidence checksum differs from its summary")
    if provenance.get("container_scan_sha256") != _sha256(OUTPUT / "container-scan-summary.json"):
        raise SupplyChainError("provenance scan checksum differs from its evidence")
    if provenance.get("release_decision_sha256") != _sha256(
        ROOT / provenance["release_decision_reference"]
    ):
        raise SupplyChainError("provenance release-decision checksum differs from its evidence")
    if provenance.get("build_metadata_sha256") != _sha256(OUTPUT / "build-metadata.json"):
        raise SupplyChainError("provenance build-metadata checksum differs from its evidence")
    if build_meta.get("dockerfile_sha256") != _sha256(ROOT / "Dockerfile"):
        raise SupplyChainError("Dockerfile changed after the recorded build")
    if build_meta.get("dockerignore_sha256") != _sha256(ROOT / ".dockerignore"):
        raise SupplyChainError(".dockerignore changed after the recorded build")
    if build_meta.get("dependency_definition_sha256") != _sha256(ROOT / "pyproject.toml"):
        raise SupplyChainError("dependency definitions changed after the recorded build")
    validate_assurance_links(manifest, sbom_summary, scan_summary, provenance)
    _validate_schema_outputs()


def _evidence_checksums() -> dict[str, str]:
    names = (
        "build-metadata.json",
        "image-metadata.json",
        "sbom-summary.json",
        "container-scan-summary.json",
        "provenance.json",
        "publication-eligibility.json",
        "release-artifact.json",
        "container-sbom.cdx.json",
    )
    checksums: dict[str, str] = {}
    for name in names:
        path = OUTPUT / name
        if not path.is_file():
            raise SupplyChainError(f"supply-chain evidence is missing: {_relative(path)}")
        checksums[name] = _sha256(path)
    return checksums


def _finalize_integrity(release_artifact: dict[str, Any]) -> None:
    checksums = _evidence_checksums()
    (OUTPUT / "checksums.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items())),
        encoding="utf-8",
    )
    _write_json(
        OUTPUT / "supply-chain-manifest.json",
        {
            "schema_version": "1.0",
            "source_commit": release_artifact["source_commit"],
            "artifact_digest": release_artifact["local_digest"],
            "publication_decision": release_artifact["publication_decision"],
            "files": {
                name: {"path": name, "sha256": digest} for name, digest in sorted(checksums.items())
            },
        },
    )


def _validate_schema_outputs() -> None:
    from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

    for file_name, schema_name in (
        ("build-metadata.json", "build-metadata.schema.json"),
        ("image-metadata.json", "image-metadata.schema.json"),
        ("sbom-summary.json", "sbom-summary.schema.json"),
        ("container-scan-summary.json", "container-scan-summary.schema.json"),
        ("provenance.json", "provenance.schema.json"),
        ("release-artifact.json", "release-artifact.schema.json"),
        ("publication-eligibility.json", "publication-decision.schema.json"),
        ("supply-chain-manifest.json", "supply-chain-manifest.schema.json"),
    ):
        data = _read_json(OUTPUT / file_name)
        schema = _read_json(ROOT / "schemas/security/supply-chain" / schema_name)
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(data),
            key=lambda error: list(error.absolute_path),
        )
        if errors:
            location = ".".join(str(item) for item in errors[0].absolute_path)
            raise SupplyChainError(
                f"schema validation failed for {file_name} at {location}: {errors[0].message}"
            )
    digest = validate_digest(_read_json(OUTPUT / "release-artifact.json").get("local_digest"))
    if digest != _read_json(OUTPUT / "image-metadata.json").get("digest"):
        raise SupplyChainError("build metadata and image metadata digest mismatch")


def publish(*, repository_url: str, region: str, role_arn: str) -> dict[str, Any]:
    if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/graa-artifact-publisher", role_arn):
        raise SupplyChainError("publication requires the configured artifact-publisher role ARN")
    if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("GITHUB_REF") != "refs/heads/main":
        raise SupplyChainError(
            "ECR publication is permitted only in the trusted main-branch GitHub Actions job"
        )
    if os.getenv("SUPPLY_CHAIN_OIDC_AUTHENTICATED") != "true" or not os.getenv("AWS_SESSION_TOKEN"):
        raise SupplyChainError(
            "publication requires short-lived credentials from the GitHub OIDC workflow"
        )
    host, ecr_name = validate_release_reference(repository_url, region)
    if ecr_name != ECR_REPOSITORY or role_arn.split(":")[4] != host.split(".")[0]:
        raise SupplyChainError(
            "publisher role account and M3 application ECR repository must match"
        )
    eligibility = _read_json(OUTPUT / "publication-eligibility.json")
    if (
        eligibility.get("status") != "eligible"
        or eligibility.get("publication_allowed") is not True
    ):
        raise SupplyChainError(
            "publication is blocked until release policy is unconditionally eligible"
        )
    manifest = publication_manifest()
    if manifest.get("source_commit") != _source_identity()[0]:
        raise SupplyChainError("source commit differs from the locally assured release artifact")
    local_digest = validate_digest(manifest.get("local_digest"))
    local_ref = str(manifest["source_image_tag"])
    image_id = _command(
        ["docker", "image", "inspect", local_ref, "--format", "{{.Id}}"], capture=True
    )
    if image_id != _read_json(OUTPUT / "build-metadata.json").get("image_id"):
        raise SupplyChainError("local image content changed after assurance")
    password = subprocess.run(
        ["aws", "ecr", "get-login-password", "--region", region],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    subprocess.run(
        ["docker", "login", "--username", "AWS", "--password-stdin", host],
        cwd=ROOT,
        check=True,
        input=password,
        text=True,
        stdout=subprocess.DEVNULL,
    )
    ecr_ref = f"{repository_url}:git-{manifest['source_commit']}"
    _command(["docker", "tag", local_ref, ecr_ref])
    _command(["docker", "push", ecr_ref])
    pushed_digest = _command(
        [
            "aws",
            "ecr",
            "describe-images",
            "--region",
            region,
            "--repository-name",
            ecr_name,
            "--image-ids",
            f"imageTag=git-{manifest['source_commit']}",
            "--query",
            "imageDetails[0].imageDigest",
            "--output",
            "text",
        ],
        capture=True,
    )
    pushed_digest = validate_digest(pushed_digest)
    if pushed_digest != local_digest:
        raise SupplyChainError(
            "ECR digest differs from the locally assured artifact; publication rejected"
        )
    manifest.update(
        {
            "published_digest": pushed_digest,
            "ecr_repository_url": repository_url,
            "verification_status": "published_verified",
        }
    )
    validate_publication_manifest(manifest)
    _write_json(OUTPUT / "release-artifact.json", manifest)
    _finalize_integrity(manifest)
    verify()
    return manifest


def run_full(*, platform: str = PLATFORM, timestamp: str = DEFAULT_TIMESTAMP) -> dict[str, Any]:
    metadata = build(platform=platform)
    sbom()
    scan()
    controlled_timestamp = (
        metadata["controlled_timestamp"] if timestamp == DEFAULT_TIMESTAMP else timestamp
    )
    result = assurance(timestamp=controlled_timestamp, as_of_date=controlled_timestamp[:10])
    verify()
    if result["status"] == "blocked":
        raise SupplyChainError("publication eligibility is blocked; see canonical evidence outputs")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "build",
            "inspect",
            "sbom",
            "scan",
            "provenance",
            "verify",
            "publication-manifest",
            "publish",
            "full",
        ],
    )
    parser.add_argument("--platform", default=PLATFORM)
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--repository-url", default=os.getenv("ECR_REPOSITORY_URL"))
    parser.add_argument("--region", default=os.getenv("AWS_REGION"))
    parser.add_argument("--role-arn", default=os.getenv("ARTIFACT_PUBLISHER_ROLE_ARN"))
    args = parser.parse_args()
    if args.command == "build":
        result = build(platform=args.platform)
    elif args.command == "inspect":
        result = _read_json(OUTPUT / "image-metadata.json")
    elif args.command == "sbom":
        result = sbom()
    elif args.command == "scan":
        result = scan()
    elif args.command == "provenance":
        result = assurance(timestamp=args.timestamp, as_of_date=args.timestamp[:10])
    elif args.command == "verify":
        verify()
        result = {"verification_status": "verified"}
    elif args.command == "publication-manifest":
        result = publication_manifest()
    elif args.command == "publish":
        if not (args.repository_url and args.region and args.role_arn):
            raise SystemExit(
                "publish requires ECR_REPOSITORY_URL, AWS_REGION, and ARTIFACT_PUBLISHER_ROLE_ARN"
            )
        if os.getenv("SUPPLY_CHAIN_ALLOW_LIVE_PUBLICATION") != "true":
            raise SystemExit(
                "live ECR publication is disabled unless SUPPLY_CHAIN_ALLOW_LIVE_PUBLICATION=true"
            )
        result = publish(
            repository_url=args.repository_url, region=args.region, role_arn=args.role_arn
        )
    else:
        result = run_full(platform=args.platform, timestamp=args.timestamp)
    print(canonical_json(result), end="")


if __name__ == "__main__":
    main()
