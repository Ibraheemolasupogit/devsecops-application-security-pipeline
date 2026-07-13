"""Deterministic release-assurance evidence generation and verification."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from genomic_research_access_api.security.findings.utils import read_json, relative, write_json
from genomic_research_access_api.security.release.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_ENVIRONMENT,
    DEFAULT_TIMESTAMP,
    OUTPUT_DIR,
    SCHEMA_DIR,
    all_config_files,
)
from genomic_research_access_api.security.release.evaluator import evaluate
from genomic_research_access_api.security.release.models import (
    FindingEvaluation,
    ReleaseDecisionRecord,
)
from genomic_research_access_api.security.release.rules import validate_policy_config
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file
from genomic_research_access_api.version import __version__

EVIDENCE_FILES = {
    "release-gate-decision.json": "decision",
    "finding-evaluations.json": "finding_evaluations",
    "matched-rules.json": "matched_rules",
    "release-actions.json": "release_actions",
    "required-approvals.json": "required_approvals",
    "release-risk-summary.json": "risk_summary",
    "policy-validation-summary.json": "policy_validation",
}


def generate(
    output_dir: Path = OUTPUT_DIR,
    *,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
    environment: str = DEFAULT_ENVIRONMENT,
    approval_roles: set[str] | None = None,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    policy_validation = validate_policy_config()
    if not policy_validation["valid"]:
        raise ValueError("release policy validation failed")
    result = evaluate(
        timestamp=timestamp,
        as_of_date=as_of_date,
        environment=environment,
        approval_roles=approval_roles,
    )
    result["policy_validation"] = policy_validation

    write_json(
        SCHEMA_DIR / "release-gate-decision.schema.json", ReleaseDecisionRecord.model_json_schema()
    )
    write_json(SCHEMA_DIR / "finding-evaluation.schema.json", FindingEvaluation.model_json_schema())

    written: list[Path] = []
    for filename, key in EVIDENCE_FILES.items():
        path = output_dir / filename
        write_json(path, result[key])
        written.append(path)

    manifest = {
        "schema_version": "1.0",
        "project_version": __version__,
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "environment": environment,
        "generator": "genomic_research_access_api.security.release.evidence",
        "input_files": {
            relative(path): {"path": relative(path), "sha256": sha256_file(path)}
            for path in _input_files()
            if path.exists()
        },
        "output_files": {
            path.name: {"path": _path_ref(path), "sha256": sha256_file(path)}
            for path in sorted(written)
        },
        "policy_version": result["decision"]["policy_version"],
        "decision_id": result["decision"]["decision_id"],
        "decision": result["decision"]["decision"],
    }
    manifest_path = output_dir / "evidence-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return [
        *written,
        SCHEMA_DIR / "release-gate-decision.schema.json",
        SCHEMA_DIR / "finding-evaluation.schema.json",
    ]


def verify(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ValueError("release evidence manifest does not exist")
    manifest = read_json(manifest_path)
    for details in manifest["output_files"].values():
        path = _manifest_output_path(output_dir, str(details["path"]))
        if not path.exists() or sha256_file(path) != details["sha256"]:
            raise ValueError(f"release evidence checksum mismatch: {details['path']}")

    with tempfile.TemporaryDirectory() as temp_dir:
        generate(
            Path(temp_dir),
            timestamp=manifest["controlled_timestamp"],
            as_of_date=manifest["as_of_date"],
            environment=manifest["environment"],
        )
        for filename, details in manifest["output_files"].items():
            if sha256_file(Path(temp_dir) / filename) != details["sha256"]:
                raise ValueError(f"non-deterministic release evidence: {filename}")


def _input_files() -> list[Path]:
    return [
        *all_config_files(),
        ROOT / "outputs" / "security" / "findings" / "deduplicated-findings.json",
        ROOT / "outputs" / "security" / "findings" / "evidence-manifest.json",
    ]


def _path_ref(path: Path) -> str:
    try:
        return relative(path)
    except ValueError:
        return path.name


def _manifest_output_path(output_dir: Path, path_ref: str) -> Path:
    if "/" not in path_ref:
        return output_dir / path_ref
    return ROOT / path_ref


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    parser.add_argument("--environment", default=DEFAULT_ENVIRONMENT)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify()
    else:
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date, environment=args.environment)


if __name__ == "__main__":
    main()
