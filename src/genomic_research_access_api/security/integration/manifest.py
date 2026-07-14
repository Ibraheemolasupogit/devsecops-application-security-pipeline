"""Manifest and checksum helpers for integration exports."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import write_json
from genomic_research_access_api.security.integration.config import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    DEPLOYMENT_STATUS,
    PRODUCER,
    PRODUCER_REPOSITORY,
    PRODUCER_SCHEMA_VERSION,
    SCHEMA_DIR,
)
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file
from genomic_research_access_api.version import __version__


def git_value(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def checksums_for(paths: list[Path], output_dir: Path) -> dict[str, str]:
    return {
        str(path.relative_to(output_dir)).replace("\\", "/"): sha256_file(path) for path in paths
    }


def write_checksum_file(output_dir: Path, checksums: dict[str, str]) -> Path:
    checksum_path = output_dir / "checksums.sha256"
    lines = [f"{value}  {name}" for name, value in sorted(checksums.items())]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return checksum_path


def build_manifest(
    *,
    output_dir: Path,
    timestamp: str,
    as_of_date: str,
    input_manifests: dict[str, str],
    input_checksums: dict[str, str],
    output_files: list[Path],
    record_count: int,
    source_finding_count: int,
    lifecycle_record_count: int,
    exception_count: int,
    verification_record_count: int,
    lineage_edge_count: int,
    compatibility_status: str,
    validation_status: str,
    limitations: list[str],
) -> dict[str, Any]:
    output_checksums = checksums_for(output_files, output_dir)
    return {
        "as_of_date": as_of_date,
        "branch": git_value("branch", "--show-current"),
        "commit": git_value("rev-parse", "HEAD"),
        "compatibility_status": compatibility_status,
        "consumer": "enterprise-data-saas-security-control-plane",
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "controlled_timestamp": timestamp,
        "deployment_status": DEPLOYMENT_STATUS,
        "dirty_worktree": bool(git_value("status", "--short")),
        "exception_count": exception_count,
        "export_schema_version": PRODUCER_SCHEMA_VERSION,
        "export_schemas": [
            "schemas/security/integration/product-security-finding.schema.json",
            "schemas/security/integration/integration-manifest.schema.json",
        ],
        "input_checksums": input_checksums,
        "input_manifests": input_manifests,
        "lifecycle_record_count": lifecycle_record_count,
        "limitations": limitations,
        "lineage_edge_count": lineage_edge_count,
        "minimum_consumer_version": "1.0",
        "output_checksums": output_checksums,
        "output_files": [
            str(path.relative_to(output_dir)).replace("\\", "/") for path in sorted(output_files)
        ],
        "producer": PRODUCER,
        "producer_project_version": __version__,
        "producer_repository": PRODUCER_REPOSITORY,
        "producer_schema_version": PRODUCER_SCHEMA_VERSION,
        "record_count": record_count,
        "source_finding_count": source_finding_count,
        "source_schemas": [
            "schemas/security/findings/canonical-finding.schema.json",
            "schemas/security/release/release-gate-decision.schema.json",
            "schemas/security/lifecycle/vulnerability-record.schema.json",
        ],
        "validation_status": validation_status,
        "verification_record_count": verification_record_count,
    }


def write_schema_files() -> list[Path]:
    from genomic_research_access_api.security.integration.models import ExportFindingRecord

    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    finding_schema = SCHEMA_DIR / "product-security-finding.schema.json"
    manifest_schema = SCHEMA_DIR / "integration-manifest.schema.json"
    write_json(finding_schema, ExportFindingRecord.model_json_schema())
    write_json(
        manifest_schema,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "additionalProperties": True,
            "required": [
                "contract_name",
                "contract_version",
                "producer",
                "producer_repository",
                "record_count",
                "lineage_edge_count",
                "output_checksums",
                "compatibility_status",
                "validation_status",
            ],
            "type": "object",
        },
    )
    return [finding_schema, manifest_schema]
