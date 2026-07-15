"""Consolidated evidence integrity verification."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.evidence.config import OUTPUT_DIR
from genomic_research_access_api.security.evidence.discovery import manifest_path, source_registry
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"Authorization:\s*Bearer", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(password|secret|token)\s*[:=]\s*[A-Za-z0-9_./+-]{16,}"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
]


def resolve_manifest_reference(manifest: Path, path_ref: str) -> Path:
    path = Path(path_ref)
    if path.is_absolute():
        return path
    if "/" in path_ref:
        return ROOT / path_ref
    return manifest.parent / path_ref


def verify_sources() -> dict[str, Any]:
    domains: list[dict[str, Any]] = []
    for source in source_registry():
        path = manifest_path(source)
        errors: list[str] = []
        manifest: dict[str, Any] = {}
        if not path.exists():
            errors.append("manifest missing")
        else:
            manifest = read_json(path)
            schema_version = str(manifest.get("schema_version") or source.expected_schema_version)
            if schema_version != source.expected_schema_version:
                errors.append("unsupported schema version")
            output_files = _manifest_outputs(manifest)
            for expected in source.expected_outputs:
                if expected not in output_files:
                    errors.append(f"missing expected output: {expected}")
            for name, details in output_files.items():
                target = resolve_manifest_reference(path, str(details["path"]))
                expected = str(details.get("sha256"))
                if not target.exists():
                    errors.append(f"missing output file: {name}")
                elif sha256_file(target) != expected:
                    errors.append(f"checksum mismatch: {name}")
        status = "passed" if not errors else "failed"
        if errors and not source.required:
            status = "warning"
        domains.append(
            {
                "source_id": source.source_id,
                "domain": source.domain,
                "required": source.required,
                "manifest_path": source.manifest_path,
                "status": status,
                "errors": errors,
                "source_checksum": sha256_file(path) if path.exists() else "",
            }
        )
    failed_required = [item for item in domains if item["required"] and item["status"] == "failed"]
    return {
        "schema_version": "1.0",
        "valid": not failed_required,
        "domains": domains,
        "verified_domains": sum(1 for item in domains if item["status"] == "passed"),
        "failed_domains": sum(1 for item in domains if item["status"] == "failed"),
    }


def _manifest_outputs(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if "output_files" in manifest:
        return dict(manifest["output_files"])
    return {Path(str(item["path"])).name: item for item in manifest.get("files", [])}


def scan_sensitive_content(paths: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "/Users/" in text or "/private/" in text:
            errors.append(f"local absolute path found: {path.name}")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"sensitive pattern found: {path.name}")
                break
    return sorted(errors)


def verify(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ValueError("consolidated evidence manifest does not exist")
    manifest = read_json(manifest_path)
    errors: list[str] = []
    for name, details in manifest["output_files"].items():
        path = resolve_manifest_reference(manifest_path, str(details["path"]))
        if not path.exists() or sha256_file(path) != details["sha256"]:
            errors.append(f"checksum mismatch: {name}")
    paths = [
        resolve_manifest_reference(manifest_path, str(item["path"]))
        for item in manifest["output_files"].values()
    ]
    errors.extend(scan_sensitive_content(paths))
    sources = verify_sources()
    if not sources["valid"]:
        errors.append("required source verification failed")
    with tempfile.TemporaryDirectory() as temp_dir:
        from genomic_research_access_api.security.evidence.aggregation import generate

        evidence = read_json(
            resolve_manifest_reference(manifest_path, "consolidated-evidence.json")
        )
        generate(
            Path(temp_dir),
            timestamp=manifest["controlled_timestamp"],
            as_of_date=manifest["as_of_date"],
            repository_metadata={
                "repository": manifest["repository"],
                "branch": manifest["branch"],
                "commit": manifest["commit"],
                "dirty_worktree": bool(evidence["dirty_worktree"]),
            },
        )
        for name, details in manifest["output_files"].items():
            if sha256_file(Path(temp_dir) / name) != details["sha256"]:
                errors.append(f"non-deterministic output: {name}")
    if errors:
        raise ValueError("\n".join(sorted(errors)))
