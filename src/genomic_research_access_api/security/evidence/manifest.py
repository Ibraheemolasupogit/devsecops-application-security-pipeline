"""Consolidated evidence manifest helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.evidence.config import all_config_files, load_config
from genomic_research_access_api.security.findings.utils import relative
from genomic_research_access_api.security.threat_model.io import sha256_file


def build_manifest(
    *,
    bundle_id: str,
    output_dir: Path,
    outputs: list[Path],
    source_manifests: dict[str, str],
    source_checksums: dict[str, str],
    timestamp: str,
    as_of_date: str,
    repository: str,
    branch: str,
    commit: str,
    verified_domains: int,
    failed_domains: int,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "bundle_id": bundle_id,
        "project_version": "0.1.0",
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "repository": repository,
        "branch": branch,
        "commit": commit,
        "deployment_status": "not_deployed",
        "source_manifests": source_manifests,
        "source_manifest_checksums": source_checksums,
        "input_files": {
            relative(path): {"path": relative(path), "sha256": sha256_file(path)}
            for path in all_config_files()
        },
        "input_checksums": {relative(path): sha256_file(path) for path in all_config_files()},
        "output_files": {
            path.name: {
                "path": path.name if path.parent == output_dir else relative(path),
                "sha256": sha256_file(path),
            }
            for path in sorted(outputs)
        },
        "verified_domains": verified_domains,
        "failed_domains": failed_domains,
        "policy_versions": {relative(path): "1.0" for path in all_config_files()},
        "metric_definition_version": load_config("metric-definitions.yaml")[
            "metric_definition_version"
        ],
        "control_mapping_version": load_config("control-mapping.yaml")["control_mapping_version"],
        "report_policy_version": load_config("report-policy.yaml")["policy_version"],
    }
