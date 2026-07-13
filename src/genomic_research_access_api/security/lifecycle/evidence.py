"""Generate and verify deterministic lifecycle evidence."""

from __future__ import annotations

import argparse
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import (
    read_json,
    relative,
    write_csv,
    write_json,
)
from genomic_research_access_api.security.lifecycle.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    FINDINGS_PATH,
    OUTPUT_DIR,
    RELEASE_DECISION_PATH,
    SCHEMA_DIR,
    SOURCE_MAP_PATH,
    all_config_files,
    load_config,
)
from genomic_research_access_api.security.lifecycle.exceptions import exception_expiry_status
from genomic_research_access_api.security.lifecycle.models import (
    SecurityException,
    VerificationRecord,
    VulnerabilityRecord,
)
from genomic_research_access_api.security.lifecycle.repository import build_register
from genomic_research_access_api.security.lifecycle.state_machine import valid_transition_count
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file
from genomic_research_access_api.version import __version__

REGISTER_COLUMNS = [
    "vulnerability_id",
    "finding_id",
    "title",
    "severity",
    "priority",
    "risk_score",
    "status",
    "technical_owner",
    "risk_owner",
    "remediation_owner",
    "squad",
    "due_date",
    "overdue",
    "verification_status",
    "exception_id",
    "review_date",
]


def validate_policy() -> dict[str, Any]:
    lifecycle = load_config("lifecycle-policy.yaml")
    transition = load_config("transition-rules.yaml")
    verification = load_config("verification-policy.yaml")
    exception = load_config("exception-policy.yaml")
    ownership = load_config("ownership-policy.yaml")
    actor_roles = set(load_config("actor-roles.yaml")["roles"])
    errors: list[str] = []
    states = {
        "detected",
        "validated",
        "triaged",
        "assigned",
        "in_remediation",
        "resolved",
        "verified",
        "closed",
        "false_positive",
        "risk_accepted",
        "deferred",
    }
    for source, target in transition["valid_transitions"]:
        if source not in states or target not in states:
            errors.append(f"invalid transition state: {source}->{target}")
    for role in verification["verifier_roles"]:
        if role not in actor_roles:
            errors.append(f"unknown verifier role: {role}")
    for roles in exception["approval_roles"].values():
        for role in roles:
            if role not in actor_roles:
                errors.append(f"unknown exception approval role: {role}")
    if ownership["unowned_value"] != "unowned":
        errors.append("ownership unowned value must remain stable")
    return {
        "schema_version": "1.0",
        "policy_version": lifecycle["policy_version"],
        "valid": not errors,
        "valid_transition_count": len(transition["valid_transitions"]),
        "actor_role_count": len(actor_roles),
        "errors": errors,
    }


def generate(
    output_dir: Path = OUTPUT_DIR,
    *,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    policy_validation = validate_policy()
    if not policy_validation["valid"]:
        raise ValueError("lifecycle policy validation failed")

    records, exceptions, validations = build_register(as_of_date=as_of_date, timestamp=timestamp)
    verifications: list[VerificationRecord] = []
    outputs = _outputs(records, exceptions, verifications, validations, as_of_date)
    write_json(
        SCHEMA_DIR / "vulnerability-record.schema.json", VulnerabilityRecord.model_json_schema()
    )
    write_json(SCHEMA_DIR / "security-exception.schema.json", SecurityException.model_json_schema())
    write_json(
        SCHEMA_DIR / "verification-record.schema.json", VerificationRecord.model_json_schema()
    )

    written: list[Path] = []
    for name, payload in outputs.items():
        path = output_dir / name
        if name.endswith(".csv"):
            write_csv(path, payload, _csv_columns(name))
        else:
            write_json(path, payload)
        written.append(path)

    manifest = {
        "schema_version": "1.0",
        "project_version": __version__,
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "deployment_status": "not_deployed",
        "input_findings_checksum": sha256_file(FINDINGS_PATH),
        "release_decision_checksum": sha256_file(RELEASE_DECISION_PATH),
        "policy_versions": {relative(path): "1.0" for path in all_config_files()},
        "input_files": {
            relative(path): {"path": relative(path), "sha256": sha256_file(path)}
            for path in _input_files()
            if path.exists()
        },
        "output_files": {
            path.name: {"path": _path_ref(path), "sha256": sha256_file(path)}
            for path in sorted(written)
        },
        "vulnerability_count": len(records),
        "exception_count": len(exceptions),
        "verification_count": len(verifications),
    }
    manifest_path = output_dir / "evidence-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return [
        *written,
        SCHEMA_DIR / "vulnerability-record.schema.json",
        SCHEMA_DIR / "security-exception.schema.json",
        SCHEMA_DIR / "verification-record.schema.json",
    ]


def verify(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ValueError("lifecycle evidence manifest does not exist")
    manifest = read_json(manifest_path)
    for details in manifest["output_files"].values():
        path = _manifest_output_path(output_dir, str(details["path"]))
        if not path.exists() or sha256_file(path) != details["sha256"]:
            raise ValueError(f"lifecycle evidence checksum mismatch: {details['path']}")
    _scan_for_local_paths(output_dir)
    with tempfile.TemporaryDirectory() as temp_dir:
        generate(
            Path(temp_dir),
            timestamp=manifest["controlled_timestamp"],
            as_of_date=manifest["as_of_date"],
        )
        for name, details in manifest["output_files"].items():
            if sha256_file(Path(temp_dir) / name) != details["sha256"]:
                raise ValueError(f"non-deterministic lifecycle evidence: {name}")


def _outputs(
    records: list[VulnerabilityRecord],
    exceptions: list[SecurityException],
    verifications: list[VerificationRecord],
    validations: list[dict[str, Any]],
    as_of_date: str,
) -> dict[str, Any]:
    rows = [record.model_dump(mode="json") for record in records]
    exception_rows = [item.model_dump(mode="json") for item in exceptions]
    verification_rows = [item.model_dump(mode="json") for item in verifications]
    history = [entry.model_dump(mode="json") for record in records for entry in record.history]
    exception_history = [
        entry.model_dump(mode="json") for item in exceptions for entry in item.history
    ]
    return {
        "vulnerability-register.json": {"schema_version": "1.0", "vulnerabilities": rows},
        "vulnerability-register.csv": rows,
        "lifecycle-history.json": {
            "schema_version": "1.0",
            "history": sorted(history, key=lambda item: item["event_id"]),
        },
        "verification-register.json": {"schema_version": "1.0", "verifications": verification_rows},
        "security-exceptions.json": {"schema_version": "1.0", "exceptions": exception_rows},
        "exception-history.json": {
            "schema_version": "1.0",
            "history": sorted(exception_history, key=lambda item: item["event_id"]),
        },
        "overdue-findings.csv": [row for row in rows if row["overdue"]],
        "due-soon-findings.csv": [
            row for row in rows if _due_soon(row.get("due_date"), as_of_date)
        ],
        "unowned-findings.csv": [
            row
            for row in rows
            if row.get("technical_owner") == "unowned" or row.get("remediation_owner") == "unowned"
        ],
        "expired-exceptions.csv": [
            row
            for row in exception_rows
            if exception_expiry_status(SecurityException.model_validate(row), as_of_date)
            == "expired"
        ],
        "expiring-exceptions.csv": [
            row
            for row in exception_rows
            if exception_expiry_status(SecurityException.model_validate(row), as_of_date)
            == "expiring_soon"
        ],
        "unverified-resolutions.csv": [
            row
            for row in rows
            if row["status"] == "resolved" and row["verification_status"] != "passed"
        ],
        "false-positive-register.csv": [row for row in rows if row["status"] == "false_positive"],
        "risk-accepted-findings.csv": [row for row in rows if row["status"] == "risk_accepted"],
        "lifecycle-summary.json": _summary(
            records, exceptions, verifications, validations, as_of_date
        ),
    }


def _summary(
    records: list[VulnerabilityRecord],
    exceptions: list[SecurityException],
    verifications: list[VerificationRecord],
    validations: list[dict[str, Any]],
    as_of_date: str,
) -> dict[str, Any]:
    by_status = Counter(str(item.status) for item in records)
    by_severity = Counter(item.severity for item in records)
    by_priority = Counter(str(item.priority or "unknown") for item in records)
    exception_statuses = [exception_expiry_status(item, as_of_date) for item in exceptions]
    return {
        "schema_version": "1.0",
        "total_vulnerabilities": len(records),
        "vulnerabilities_by_status": dict(sorted(by_status.items())),
        "vulnerabilities_by_severity": dict(sorted(by_severity.items())),
        "vulnerabilities_by_priority": dict(sorted(by_priority.items())),
        "overdue_findings": sum(1 for item in records if item.overdue),
        "due_soon_findings": sum(1 for item in records if _due_soon(item.due_date, as_of_date)),
        "unowned_findings": sum(
            1
            for item in records
            if item.technical_owner == "unowned" or item.remediation_owner == "unowned"
        ),
        "resolved_but_unverified": sum(
            1
            for item in records
            if item.status == "resolved" and item.verification_status != "passed"
        ),
        "verified_but_not_closed": sum(1 for item in records if item.status == "verified"),
        "closed_findings": sum(1 for item in records if item.status == "closed"),
        "false_positives": sum(1 for item in records if item.status == "false_positive"),
        "risk_accepted": sum(1 for item in records if item.status == "risk_accepted"),
        "active_exceptions": exception_statuses.count("active"),
        "expired_exceptions": exception_statuses.count("expired"),
        "expiring_exceptions": exception_statuses.count("expiring_soon"),
        "reopened_findings": sum(item.reopened_count for item in records),
        "invalid_transitions": 0,
        "security_exception_count": len(exceptions),
        "verification_record_count": len(verifications),
        "valid_transition_count": valid_transition_count(),
        "validations": validations,
    }


def _csv_columns(name: str) -> list[str]:
    if "exception" in name:
        return [
            "exception_id",
            "vulnerability_id",
            "finding_id",
            "status",
            "approver_roles",
            "expiry_date",
            "review_date",
            "scope",
            "decision",
        ]
    return REGISTER_COLUMNS


def _due_soon(value: str | None, as_of_date: str) -> bool:
    if not value:
        return False
    days = (date.fromisoformat(value) - date.fromisoformat(as_of_date)).days
    return 0 <= days <= int(load_config("lifecycle-policy.yaml")["due_soon_days"])


def _input_files() -> list[Path]:
    return [*all_config_files(), FINDINGS_PATH, SOURCE_MAP_PATH, RELEASE_DECISION_PATH]


def _path_ref(path: Path) -> str:
    try:
        return relative(path)
    except ValueError:
        return path.name


def _manifest_output_path(output_dir: Path, path_ref: str) -> Path:
    if "/" not in path_ref:
        return output_dir / path_ref
    return ROOT / path_ref


def _scan_for_local_paths(output_dir: Path) -> None:
    for path in output_dir.glob("*"):
        if path.is_file() and "/Users/" in path.read_text(encoding="utf-8"):
            raise ValueError(f"local path leaked into lifecycle evidence: {path.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify()
    else:
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)


if __name__ == "__main__":
    main()
