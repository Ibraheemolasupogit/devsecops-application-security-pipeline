"""Validation for integration policies and export bundles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import read_json, write_json
from genomic_research_access_api.security.integration.config import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    OUTPUT_DIR,
    PRODUCER_REPOSITORY,
    load_config,
)
from genomic_research_access_api.security.integration.mappings import (
    approved_owner_values,
    map_status,
    stable_export_record_id,
)
from genomic_research_access_api.security.integration.models import ExportFindingRecord
from genomic_research_access_api.security.threat_model.io import sha256_file

LOCAL_PATH_RE = re.compile(r"(/Users/|/private/|[A-Za-z]:\\\\)")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]+\.|AKIA[0-9A-Z]{16}|"
    r"aws_secret_access_key|password\s*=|secret\s*=|blocked-sensitive-marker)",
    re.IGNORECASE,
)
FORMULA_RE = re.compile(r"(^|,)[=+@-]")


def validate_policy() -> dict[str, Any]:
    errors: list[str] = []
    policy = load_config("integration-policy.yaml")
    compatibility = load_config("compatibility-policy.yaml")
    if policy.get("contract_name") != CONTRACT_NAME:
        errors.append("integration policy contract_name mismatch")
    if str(policy.get("contract_version")) != CONTRACT_VERSION:
        errors.append("integration policy contract_version mismatch")
    if CONTRACT_VERSION not in compatibility.get("supported_contract_versions", []):
        errors.append("contract version is not listed as supported")
    for name in [
        "field-mapping.yaml",
        "status-mapping.yaml",
        "severity-mapping.yaml",
        "ownership-mapping.yaml",
        "control-mapping.yaml",
    ]:
        if not load_config(name):
            errors.append(f"{name} is empty")
    summary = {
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "errors": errors,
        "valid": not errors,
    }
    if OUTPUT_DIR.exists():
        write_json(OUTPUT_DIR / "integration-policy-validation-summary.json", summary)
    return summary


def validate_export(output_dir: Path = OUTPUT_DIR) -> dict[str, Any]:
    errors: list[str] = []
    manifest_path = output_dir / "integration-manifest.json"
    if not manifest_path.exists():
        return {"errors": ["missing integration-manifest.json"], "valid": False}
    manifest = read_json(manifest_path)
    findings_payload = read_json(output_dir / "product-security-findings.json")
    records = findings_payload["findings"]
    if manifest.get("contract_name") != CONTRACT_NAME:
        errors.append("manifest contract_name mismatch")
    if manifest.get("contract_version") != CONTRACT_VERSION:
        errors.append("manifest contract_version mismatch")
    if manifest.get("producer_repository") != PRODUCER_REPOSITORY:
        errors.append("manifest producer_repository mismatch")
    errors.extend(_validate_checksums(output_dir, manifest))
    errors.extend(_validate_records(records))
    errors.extend(_validate_lineage(output_dir, records))
    errors.extend(_validate_metrics(output_dir, records))
    errors.extend(_validate_csv(output_dir / "product-security-findings.csv"))
    summary = {
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "errors": errors,
        "record_count": len(records),
        "valid": not errors,
    }
    return summary


def _validate_checksums(output_dir: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected = manifest.get("output_checksums", {})
    for name, checksum in expected.items():
        path = output_dir / name
        if not path.exists():
            errors.append(f"missing output file: {name}")
        elif sha256_file(path) != checksum:
            errors.append(f"checksum mismatch: {name}")
    checksum_path = output_dir / "checksums.sha256"
    if checksum_path.exists():
        listed = {
            line.split("  ", 1)[1]: line.split("  ", 1)[0]
            for line in checksum_path.read_text(encoding="utf-8").splitlines()
            if "  " in line
        }
        for name, checksum in expected.items():
            if listed.get(name) != checksum:
                errors.append(f"checksums.sha256 mismatch: {name}")
    else:
        errors.append("missing checksums.sha256")
    return errors


def _validate_records(records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    export_ids: list[str] = []
    finding_ids: list[str] = []
    owner_values = approved_owner_values()
    status_values = set(load_config("status-mapping.yaml")["statuses"])
    consumer_values = set(load_config("status-mapping.yaml")["statuses"].values())
    release_decisions = {"block", "conditional_pass", "pass", "warn"}
    exception_statuses = {"active", "expired", "closed", "revoked", None}
    verification_statuses = {
        "failed",
        "not_verified",
        "source-observed",
        "unverified",
        "verified",
        None,
    }
    for index, record in enumerate(records):
        try:
            ExportFindingRecord.model_validate(record)
        except ValueError as exc:
            errors.append(f"record {index} schema error: {exc}")
            continue
        finding_id = str(record["finding_id"])
        export_ids.append(str(record["export_record_id"]))
        finding_ids.append(finding_id)
        if record["export_record_id"] != stable_export_record_id(finding_id):
            errors.append(f"unstable export ID for {finding_id}")
        if record["consumer_status"] != map_status(record.get("producer_status")):
            errors.append(f"status mapping mismatch for {finding_id}")
        if (
            record.get("lifecycle_status") not in status_values
            and record.get("lifecycle_status") not in consumer_values
        ):
            errors.append(f"invalid lifecycle status for {finding_id}")
        if record.get("exception_status") not in exception_statuses:
            errors.append(f"invalid exception status for {finding_id}")
        if record.get("verification_status") not in verification_statuses:
            errors.append(f"invalid verification status for {finding_id}")
        if record.get("release_decision") not in release_decisions:
            errors.append(f"invalid release decision for {finding_id}")
        for owner_field in ["technical_owner", "risk_owner", "remediation_owner", "squad"]:
            value = record.get(owner_field)
            if value is not None and value not in owner_values:
                errors.append(f"invalid owner value for {finding_id}: {owner_field}={value}")
        if record.get("consumer_status") == "risk_accepted" and not record.get("exception_id"):
            errors.append(f"risk accepted finding missing exception metadata: {finding_id}")
        serialized = str(record)
        if LOCAL_PATH_RE.search(serialized):
            errors.append(f"local path detected in {finding_id}")
        if EMAIL_RE.search(serialized):
            errors.append(f"email address detected in {finding_id}")
        if SECRET_RE.search(serialized):
            errors.append(f"secret-like value detected in {finding_id}")
    if len(export_ids) != len(set(export_ids)):
        errors.append("duplicate export_record_id values")
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("duplicate finding_id values")
    return errors


def _validate_lineage(output_dir: Path, records: list[dict[str, Any]]) -> list[str]:
    payload = read_json(output_dir / "finding-source-lineage.json")
    edges = payload["lineage_edges"]
    edge_targets = {edge["target_id"] for edge in edges}
    errors = []
    for record in records:
        if record["export_record_id"] not in edge_targets:
            errors.append(f"missing lineage edge to export record: {record['finding_id']}")
    for edge in edges:
        checksum_source = "|".join(
            [
                edge["source_id"],
                edge["target_id"],
                edge["relationship"],
                edge["source_domain"],
                edge["target_domain"],
                edge["source_reference"],
                edge["target_reference"],
            ]
        )
        import hashlib

        if hashlib.sha256(checksum_source.encode("utf-8")).hexdigest() != edge["checksum"]:
            errors.append(f"lineage checksum mismatch: {edge['source_id']}->{edge['target_id']}")
    return errors


def _validate_metrics(output_dir: Path, records: list[dict[str, Any]]) -> list[str]:
    metrics = read_json(output_dir / "security-metrics.json")
    if metrics["total_exported_findings"] != len(records):
        return ["metrics total_exported_findings mismatch"]
    return []


def _validate_csv(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors = []
    if "\r\n" in text:
        errors.append("CSV does not use LF line endings")
    if FORMULA_RE.search(text):
        errors.append("CSV contains an unsafe formula prefix")
    if LOCAL_PATH_RE.search(text):
        errors.append("CSV contains local path")
    if SECRET_RE.search(text):
        errors.append("CSV contains secret-like value")
    return errors
