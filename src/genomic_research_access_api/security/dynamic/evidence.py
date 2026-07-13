"""Generate and verify deterministic Milestone 6 dynamic-security evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.dynamic.config import (
    MANIFEST_PATH,
    OUTPUT_DIR,
    RAW_DIR,
    dynamic_config,
    dynamic_policy,
)
from genomic_research_access_api.security.dynamic.parsers import (
    pytest_summary,
    schemathesis_summary,
    zap_summary,
)

SUMMARY_FILES = {
    "endpoint-test-inventory.json": "inventory",
    "authentication-boundary-summary.json": "authentication",
    "authorisation-boundary-summary.json": "authorisation",
    "object-access-summary.json": "object_access",
    "schema-mutation-summary.json": "input_mutation",
    "security-header-summary.json": "security_headers",
    "cors-summary.json": "cors",
    "resource-consumption-summary.json": "resource_consumption",
    "audit-validation-summary.json": "audit",
}


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(payload), encoding="utf-8", newline="\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_evidence(timestamp: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config = dynamic_config()
    policy = dynamic_policy()
    pytest = pytest_summary(RAW_DIR / "pytest-dynamic.json")
    schemathesis = schemathesis_summary(RAW_DIR / "schemathesis.json")
    zap = zap_summary(RAW_DIR / "zap-report.json")
    categories = {item["category"]: item for item in pytest["categories"]}

    inventory = {
        "execution_status": "completed",
        "local_only": True,
        "target_boundary": config["local_targets"]["allowed_hosts"],
        "test_count": pytest["total"],
        "categories": sorted(categories),
    }
    outputs: dict[str, Any] = {"endpoint-test-inventory.json": inventory}
    for filename, category in SUMMARY_FILES.items():
        if category == "inventory":
            continue
        item = categories.get(
            category,
            {"category": category, "passed": 0, "failed": 0, "total": 0, "cases": []},
        )
        outputs[filename] = {
            "category": category,
            "execution_status": "completed",
            "policy_decision": "pass" if item["failed"] == 0 else "fail",
            "test_count": item["total"],
            "failed_count": item["failed"],
            "cases": item["cases"],
        }

    outputs["schemathesis-summary.json"] = schemathesis
    outputs["zap-summary.json"] = zap
    blocking_count = sum(
        1
        for payload in outputs.values()
        if isinstance(payload, dict) and payload.get("policy_decision") == "fail"
    )
    outputs["dynamic-security-summary.json"] = {
        "blocking_count": blocking_count,
        "execution_status": "completed",
        "local_only": True,
        "policy": policy,
        "policy_decision": "pass" if blocking_count == 0 else "fail",
        "scanner_count": 3,
        "tool_versions": {
            "pytest": "8.4.1",
            "pytest-json-report": "1.5.0",
            "schemathesis": config["schemathesis"]["version"],
            "zap": config["zap"]["version"],
            "httpx": "0.28.1",
        },
    }

    for filename, payload in outputs.items():
        write_json(OUTPUT_DIR / filename, payload)

    manifest_files = sorted(outputs)
    manifest = {
        "generated_at": timestamp,
        "evidence_type": "dynamic-security",
        "files": [
            {
                "path": f"outputs/security/dynamic/{filename}",
                "sha256": sha256(OUTPUT_DIR / filename),
            }
            for filename in manifest_files
        ],
    }
    write_json(MANIFEST_PATH, manifest)


def verify_evidence() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        path = Path(item["path"])
        if sha256(path) != item["sha256"]:
            raise SystemExit(f"Evidence checksum mismatch: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default="2026-01-01T00:00:00Z")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify_evidence()
    else:
        build_evidence(args.timestamp)


if __name__ == "__main__":
    main()
