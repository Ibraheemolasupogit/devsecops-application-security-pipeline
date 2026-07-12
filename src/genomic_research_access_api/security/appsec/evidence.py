"""Deterministic AppSec evidence generation."""

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.appsec.config import (
    APPSEC_OUTPUT_DIR,
    RAW_DIR,
    SECURITY_DIR,
    load_json_yaml,
    validate_suppressions,
)
from genomic_research_access_api.security.appsec.parsers import (
    bandit_summary,
    checkov_summary,
    gitleaks_summary,
    pip_audit_summary,
    semgrep_summary,
    trivy_summary,
    validate_cyclonedx,
)
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file, write_json
from genomic_research_access_api.security.threat_model.validation import ThreatModelValidationError
from genomic_research_access_api.version import __version__

SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
SBOM_PATH = APPSEC_OUTPUT_DIR / "sbom.cdx.json"


def tool_versions() -> dict[str, str]:
    payload = load_json_yaml(SECURITY_DIR / "config" / "tools.yaml")
    return {name: details["version"] for name, details in payload["tools"].items()}


def all_summaries() -> dict[str, dict[str, Any]]:
    return {
        "secret-scan-summary.json": gitleaks_summary(),
        "sast-summary.json": _combine_sast(),
        "dependency-scan-summary.json": pip_audit_summary(),
        "iac-scan-summary.json": checkov_summary(),
        "container-scan-summary.json": trivy_summary(),
    }


def _combine_sast() -> dict[str, Any]:
    semgrep = semgrep_summary()
    bandit = bandit_summary()
    return {
        "tool": "semgrep+bandit",
        "execution_status": "completed"
        if semgrep["execution_status"] == bandit["execution_status"] == "completed"
        else "not_run",
        "finding_count": semgrep["finding_count"] + bandit["finding_count"],
        "blocking_count": semgrep["blocking_count"] + bandit["blocking_count"],
        "suppressed_count": semgrep["suppressed_count"] + bandit["suppressed_count"],
        "policy_decision": "block"
        if semgrep["blocking_count"] + bandit["blocking_count"]
        else "pass"
        if semgrep["execution_status"] == bandit["execution_status"] == "completed"
        else "not_evaluated",
        "limitations": "; ".join(
            item["limitations"] for item in [semgrep, bandit] if item["limitations"]
        ),
        "children": [semgrep, bandit],
    }


def pipeline_summary(summaries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    blocking = sum(item["blocking_count"] for item in summaries.values())
    not_run = [
        item["tool"] for item in summaries.values() if item["execution_status"] != "completed"
    ]
    return {
        "tool_versions": tool_versions(),
        "scanner_count": len(summaries),
        "blocking_count": blocking,
        "not_run": sorted(not_run),
        "policy_decision": "block" if blocking else "not_evaluated" if not_run else "pass",
        "suppression_count": len(validate_suppressions()),
    }


def generate_minimal_sbom(path: Path = SBOM_PATH) -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "genomic-research-access-api",
                "version": __version__,
            },
            "tools": [
                {
                    "vendor": "CycloneDX",
                    "name": "cyclonedx-bom",
                    "version": tool_versions()["cyclonedx"],
                }
            ],
        },
        "components": [
            {"type": "application", "name": "genomic-research-access-api", "version": __version__},
            {"type": "library", "name": "fastapi", "version": "0.139.0"},
            {"type": "library", "name": "pydantic", "version": "2.11.7"},
            {"type": "library", "name": "PyJWT", "version": "2.13.0"},
            {"type": "library", "name": "starlette", "version": "1.3.1"},
        ],
        "dependencies": [
            {
                "ref": "genomic-research-access-api",
                "dependsOn": ["fastapi", "pydantic", "PyJWT", "starlette"],
            }
        ],
    }
    write_json(path, payload)


def generate_evidence(
    output_dir: Path = APPSEC_OUTPUT_DIR, timestamp: str = DEFAULT_TIMESTAMP
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not SBOM_PATH.exists():
        generate_minimal_sbom(SBOM_PATH)
    summaries = all_summaries()
    summaries["appsec-pipeline-summary.json"] = pipeline_summary(summaries)
    written: list[Path] = []
    for filename, payload in sorted(summaries.items()):
        path = output_dir / filename
        write_json(path, payload)
        written.append(path)

    manifest_path = output_dir / "evidence-manifest.json"
    input_files = sorted(
        [
            SECURITY_DIR / "config" / "tools.yaml",
            SECURITY_DIR / "config" / "policy.yaml",
            SECURITY_DIR / "config" / "suppressions.yaml",
            *RAW_DIR.glob("*.json"),
            SBOM_PATH,
        ]
    )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "project_version": __version__,
        "generation_metadata": {
            "generated_at": timestamp,
            "generator": "genomic_research_access_api.security.appsec.evidence",
        },
        "input_files": {
            str(path.relative_to(ROOT)): {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
            }
            for path in input_files
            if path.exists()
        },
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
        "tool_versions": tool_versions(),
    }
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify_evidence(output_dir: Path = APPSEC_OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ThreatModelValidationError("AppSec evidence manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for details in manifest["output_files"].values():
        path = output_dir / details["path"]
        if not path.exists() or sha256_file(path) != details["sha256"]:
            raise ThreatModelValidationError(f"AppSec evidence checksum mismatch: {path}")
    validate_cyclonedx(SBOM_PATH)
    with tempfile.TemporaryDirectory() as temp_dir:
        generate_evidence(Path(temp_dir), manifest["generation_metadata"]["generated_at"])
        for name, details in manifest["output_files"].items():
            if sha256_file(Path(temp_dir) / name) != details["sha256"]:
                raise ThreatModelValidationError(f"non-deterministic AppSec evidence: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--sbom", action="store_true")
    args = parser.parse_args()
    if args.sbom:
        generate_minimal_sbom()
    elif args.verify:
        verify_evidence()
    else:
        generate_evidence(timestamp=args.timestamp)


if __name__ == "__main__":
    main()
