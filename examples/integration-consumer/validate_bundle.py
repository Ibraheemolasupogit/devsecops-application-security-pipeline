"""Technology-neutral sample validation for an integration export bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SUPPORTED_CONTRACTS = {"1.0"}
LOCAL_PATH_RE = re.compile(r"(/Users/|/private/|[A-Za-z]:\\\\)")
SECRET_RE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]+\.|AKIA[0-9A-Z]{16}|secret\s*=)",
    re.IGNORECASE,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    summary = validate_bundle(args.bundle)
    if not summary["valid"]:
        raise SystemExit(summary["errors"])
    print(f"validated {summary['record_count']} product-security records")


def validate_bundle(bundle: Path) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = bundle / "integration-manifest.json"
    if not manifest_path.exists():
        return {"errors": ["missing integration-manifest.json"], "valid": False}
    manifest = _read_json(manifest_path)
    if manifest.get("contract_version") not in SUPPORTED_CONTRACTS:
        errors.append("unsupported contract version")
    for name, checksum in manifest.get("output_checksums", {}).items():
        path = bundle / name
        if not path.exists():
            errors.append(f"missing output: {name}")
        elif _sha256(path) != checksum:
            errors.append(f"checksum mismatch: {name}")
    findings_path = bundle / "product-security-findings.json"
    findings = _read_json(findings_path).get("findings", [])
    if len(findings) != manifest.get("record_count"):
        errors.append("record count mismatch")
    export_ids = [item.get("export_record_id") for item in findings]
    if len(export_ids) != len(set(export_ids)):
        errors.append("duplicate export_record_id")
    required = {
        "contract_version",
        "export_record_id",
        "finding_id",
        "source_finding_ids",
        "consumer_status",
        "source_record_hash",
    }
    for index, record in enumerate(findings):
        missing = sorted(required - set(record))
        if missing:
            errors.append(f"record {index} missing fields: {missing}")
        serialized = json.dumps(record, sort_keys=True)
        if LOCAL_PATH_RE.search(serialized):
            errors.append(f"record {index} contains an absolute local path")
        if SECRET_RE.search(serialized):
            errors.append(f"record {index} contains a secret-like value")
    return {"errors": errors, "record_count": len(findings), "valid": not errors}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    main()
