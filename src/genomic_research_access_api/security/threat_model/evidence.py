"""Deterministic evidence generation for the threat model."""

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.threat_model.io import (
    OUTPUT_DIR,
    SOURCE_FILES,
    normalise_model,
    sha256_file,
    write_json,
)
from genomic_research_access_api.security.threat_model.validation import (
    ThreatModelValidationError,
    validate_threat_model,
)
from genomic_research_access_api.version import __version__

SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"


def _counter(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def build_summary(model: Any) -> dict[str, Any]:
    requirement_threats = {
        threat_id
        for requirement in model.requirements
        for threat_id in requirement.source_threat_ids
    }
    requirement_ids = {requirement.requirement_id for requirement in model.requirements}
    traceability_requirement_ids = {
        requirement_id for link in model.traceability for requirement_id in link.requirement_ids
    }
    return {
        "orphaned_requirements": sorted(requirement_ids - traceability_requirement_ids),
        "orphaned_threats": sorted(
            {threat.threat_id for threat in model.threats} - requirement_threats
        ),
        "requirements_by_category": _counter([item.category for item in model.requirements]),
        "requirements_by_implementation_status": _counter(
            [item.implementation_status for item in model.requirements]
        ),
        "residual_risks_by_rating": _counter(
            [item.residual_rating for item in model.residual_risks]
        ),
        "threats_by_inherent_risk": _counter([item.inherent_risk for item in model.threats]),
        "threats_by_stride_category": _counter([item.stride_category for item in model.threats]),
        "total_threats": len(model.threats),
        "validation_status": "passed",
    }


def generate_evidence(
    output_dir: Path = OUTPUT_DIR, timestamp: str = DEFAULT_TIMESTAMP
) -> list[Path]:
    model = validate_threat_model()
    outputs = {
        "validated-control-traceability.json": normalise_model(model.traceability),
        "validated-residual-risk-register.json": normalise_model(model.residual_risks),
        "validated-security-requirements.json": normalise_model(model.requirements),
        "validated-threat-register.json": normalise_model(model.threats),
        "threat-model-summary.json": build_summary(model),
    }
    written: list[Path] = []
    for filename, payload in sorted(outputs.items()):
        path = output_dir / filename
        write_json(path, payload)
        written.append(path)

    manifest_path = output_dir / "evidence-manifest.json"
    manifest = {
        "generation_metadata": {
            "generated_at": timestamp,
            "generator": "genomic_research_access_api.security.threat_model.evidence",
        },
        "input_files": {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path in sorted(SOURCE_FILES.items())
        },
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
        "project_version": __version__,
        "run_id": f"threat-model-{timestamp}",
        "schema_version": SCHEMA_VERSION,
    }
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify_evidence(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ThreatModelValidationError("evidence manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for details in manifest["output_files"].values():
        path = output_dir / details["path"]
        if not path.exists():
            raise ThreatModelValidationError(f"missing evidence output: {path}")
        checksum = sha256_file(path)
        if checksum != details["sha256"]:
            raise ThreatModelValidationError(f"checksum mismatch for {path}")

    with tempfile.TemporaryDirectory() as temp_dir:
        generate_evidence(Path(temp_dir), manifest["generation_metadata"]["generated_at"])
        for name, details in manifest["output_files"].items():
            regenerated = Path(temp_dir) / name
            if sha256_file(regenerated) != details["sha256"]:
                raise ThreatModelValidationError(f"non-deterministic evidence output: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify_evidence()
    else:
        generate_evidence(timestamp=args.timestamp)


if __name__ == "__main__":
    main()
