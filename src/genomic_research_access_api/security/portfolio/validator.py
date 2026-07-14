"""Validate portfolio readiness artefacts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

from genomic_research_access_api.security.findings.utils import read_json, relative
from genomic_research_access_api.security.portfolio.config import (
    OUTPUT_DIR,
    PACKAGE_DIR,
    PORTFOLIO_DOCS_DIR,
)
from genomic_research_access_api.security.portfolio.generator import markdown_links
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

SENSITIVE_PATTERNS = [
    re.compile(r"/Users/[A-Za-z0-9_.-]+"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"-----BEGIN [A-Z ]+-----"),
]


def verify(output_dir: Path = OUTPUT_DIR) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = output_dir / "portfolio-manifest.json"
    if not manifest_path.exists():
        return {"valid": False, "errors": ["missing portfolio-manifest.json"]}
    manifest = read_json(manifest_path)
    errors.extend(validate_manifest(manifest))
    errors.extend(validate_indexes(output_dir))
    errors.extend(scan_sensitive_content([*output_dir.glob("*.json"), *PACKAGE_DIR.glob("*.json")]))
    errors.extend(markdown_links([*PORTFOLIO_DOCS_DIR.glob("*.md"), ROOT / "README.md"]))
    return {"valid": not errors, "errors": errors}


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    errors = []
    output_files = cast(dict[str, dict[str, Any]], manifest.get("output_files", {}))
    for name, metadata in output_files.items():
        path = ROOT / str(metadata["path"])
        if not path.exists():
            errors.append(f"missing manifest output: {name}")
            continue
        if sha256_file(path) != metadata["sha256"]:
            errors.append(f"checksum mismatch: {name}")
    return errors


def validate_indexes(output_dir: Path) -> list[str]:
    errors = []
    for name in ["evidence-index.json", "report-index.json"]:
        index = read_json(output_dir / name)
        if index["missing_paths"]:
            errors.append(f"{name} has missing paths")
        for item in cast(list[dict[str, Any]], index["items"]):
            path = ROOT / str(item["path"])
            if not path.exists():
                errors.append(f"indexed path missing: {item['path']}")
            elif sha256_file(path) != item["sha256"]:
                errors.append(f"indexed checksum mismatch: {item['path']}")
    return errors


def scan_sensitive_content(paths: list[Path]) -> list[str]:
    errors = []
    for path in paths:
        if not path.exists() or path.is_dir():
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(text):
                errors.append(f"sensitive content in {relative(path)}")
                break
    return errors
