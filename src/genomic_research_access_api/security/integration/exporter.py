"""Generate the deterministic product-security integration export bundle."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.utils import (
    canonical_json,
    read_json,
    write_csv,
    write_json,
)
from genomic_research_access_api.security.integration.config import (
    CONTRACT_NAME,
    CONTRACT_VERSION,
    DEPLOYMENT_STATUS,
    OUTPUT_DIR,
    PRODUCER,
    PRODUCER_REPOSITORY,
    PRODUCER_SCHEMA_VERSION,
    load_config,
)
from genomic_research_access_api.security.integration.lineage import edge
from genomic_research_access_api.security.integration.manifest import (
    build_manifest,
    checksums_for,
    write_checksum_file,
    write_schema_files,
)
from genomic_research_access_api.security.integration.mappings import (
    map_status,
    stable_export_record_id,
)
from genomic_research_access_api.security.integration.models import ExportFindingRecord
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

CSV_FIELDS = list(ExportFindingRecord.model_fields)


def generate_bundle(
    output_dir: Path = OUTPUT_DIR,
    *,
    timestamp: str,
    as_of_date: str,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    schema_paths = write_schema_files()
    findings_payload = read_json(ROOT / "outputs/security/findings/deduplicated-findings.json")
    source_map = read_json(ROOT / "outputs/security/findings/finding-source-map.json")
    lifecycle_payload = read_json(ROOT / "outputs/security/lifecycle/vulnerability-register.json")
    exceptions_payload = read_json(ROOT / "outputs/security/lifecycle/security-exceptions.json")
    verifications_payload = read_json(
        ROOT / "outputs/security/lifecycle/verification-register.json"
    )
    release_decision = read_json(ROOT / "outputs/security/release/release-gate-decision.json")
    release_evaluations = read_json(ROOT / "outputs/security/release/finding-evaluations.json")
    matched_rules = read_json(ROOT / "outputs/security/release/matched-rules.json")
    metrics_payload = read_json(ROOT / "outputs/security/evidence/security-metrics.json")
    consolidated = read_json(ROOT / "outputs/security/evidence/consolidated-evidence.json")

    findings = sorted(findings_payload["findings"], key=lambda item: str(item["finding_id"]))
    lifecycle = {item["finding_id"]: item for item in lifecycle_payload["vulnerabilities"]}
    exceptions_by_finding = {item["finding_id"]: item for item in exceptions_payload["exceptions"]}
    evaluations = {item["finding_id"]: item for item in release_evaluations["evaluations"]}
    rules_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in matched_rules["matched_rules"]:
        rules_by_finding[rule["finding_id"]].append(rule)
    controls_by_id = {
        item["control_id"]: item for item in consolidated["control_coverage"]["controls"]
    }

    export_records: list[dict[str, Any]] = []
    lifecycle_status: list[dict[str, Any]] = []
    release_impact: list[dict[str, Any]] = []
    control_traceability: list[dict[str, Any]] = []
    ownership: list[dict[str, Any]] = []
    lineage_edges: list[dict[str, str]] = []

    for finding in findings:
        finding_id = str(finding["finding_id"])
        lifecycle_record = lifecycle.get(finding_id, {})
        exception_record = exceptions_by_finding.get(finding_id, {})
        evaluation = evaluations.get(finding_id, {})
        export_id = stable_export_record_id(finding_id)
        producer_status = str(lifecycle_record.get("status") or finding.get("status") or "open")
        consumer_status = map_status(producer_status)
        source_info = source_map.get(finding_id, {})
        source_evidence = _source_evidence_paths(finding)
        source_tools = sorted(
            set(source_info.get("source_tools") or [finding.get("source_tool") or "unknown"])
        )
        source_finding_ids = sorted(
            set(source_info.get("source_finding_ids") or [finding.get("source_finding_id")])
            - {None}
        )
        matched_rule_ids = sorted(
            set(
                evaluation.get("matched_rule_ids")
                or [r["rule_id"] for r in rules_by_finding[finding_id]]
            )
        )
        release_contribution = evaluation.get("decision_contribution")
        traceability = _traceability_for_finding(
            finding=finding,
            lifecycle_record=lifecycle_record,
            evaluation=evaluation,
            controls_by_id=controls_by_id,
        )
        control_traceability.append(traceability)
        lifecycle_status.append(
            {
                "due_date": lifecycle_record.get("due_date") or finding.get("due_date"),
                "exception_expiry": exception_record.get("expiry_date"),
                "exception_id": lifecycle_record.get("exception_id")
                or exception_record.get("exception_id"),
                "exception_status": exception_record.get("status"),
                "finding_id": finding_id,
                "lifecycle_status": lifecycle_record.get("status"),
                "overdue": lifecycle_record.get("overdue"),
                "previous_status": lifecycle_record.get("previous_status"),
                "reopened_count": lifecycle_record.get("reopened_count", 0),
                "verification_status": lifecycle_record.get("verification_status")
                or finding.get("verification_status"),
                "vulnerability_id": lifecycle_record.get("vulnerability_id"),
            }
        )
        release_impact.append(
            {
                "decision_id": release_decision["decision_id"],
                "finding_id": finding_id,
                "matched_release_rule_ids": matched_rule_ids,
                "policy_version": release_decision["policy_version"],
                "release_decision": release_decision["decision"],
                "release_impact": release_contribution,
                "required_actions": evaluation.get("required_actions", []),
                "required_approvals": evaluation.get("required_approvals", []),
            }
        )
        ownership.append(
            {
                "due_date": lifecycle_record.get("due_date") or finding.get("due_date"),
                "finding_id": finding_id,
                "overdue": lifecycle_record.get("overdue"),
                "remediation_owner": finding.get("remediation_owner"),
                "remediation_sla_days": finding.get("remediation_sla_days"),
                "risk_owner": finding.get("risk_owner"),
                "squad": finding.get("squad"),
                "technical_owner": finding.get("technical_owner"),
            }
        )
        export_record = ExportFindingRecord(
            contract_version=CONTRACT_VERSION,
            export_record_id=export_id,
            finding_id=finding_id,
            source_finding_ids=source_finding_ids,
            source_tools=source_tools,
            finding_type=finding.get("finding_type"),
            security_domain=finding.get("security_domain"),
            title=str(finding.get("title") or finding_id),
            description=str(finding.get("description") or ""),
            normalised_severity=finding.get("normalised_severity"),
            risk_score=finding.get("risk_score"),
            priority=finding.get("priority"),
            status=consumer_status,
            producer_status=producer_status,
            consumer_status=consumer_status,
            lifecycle_status=lifecycle_record.get("status"),
            asset_id=finding.get("asset_id"),
            asset_type=finding.get("asset_type"),
            asset_criticality=finding.get("asset_criticality"),
            data_sensitivity=finding.get("data_sensitivity"),
            internet_exposure=finding.get("internet_exposure"),
            environment=finding.get("environment"),
            application=finding.get("application"),
            service=finding.get("service"),
            repository=finding.get("repository"),
            component=finding.get("component"),
            resource=finding.get("resource"),
            file=finding.get("file"),
            line=finding.get("line"),
            package_name=finding.get("package_name"),
            installed_version=finding.get("installed_version"),
            fixed_version=finding.get("fixed_version"),
            cve=finding.get("cve"),
            cwe=finding.get("cwe"),
            owasp_category=finding.get("owasp_category"),
            cloud_provider=finding.get("cloud_provider"),
            region=finding.get("region"),
            threat_ids=finding.get("threat_ids", []),
            security_requirement_ids=finding.get("security_requirement_ids", []),
            control_ids=finding.get("control_ids", []),
            squad=finding.get("squad"),
            technical_owner=finding.get("technical_owner"),
            risk_owner=finding.get("risk_owner"),
            remediation_owner=finding.get("remediation_owner"),
            first_detected=finding.get("first_detected"),
            last_detected=finding.get("last_detected"),
            due_date=lifecycle_record.get("due_date") or finding.get("due_date"),
            overdue=lifecycle_record.get("overdue"),
            remediation_sla_days=finding.get("remediation_sla_days"),
            suppression_id=finding.get("suppression_id"),
            suppression_status=finding.get("suppression_status"),
            exception_id=lifecycle_record.get("exception_id")
            or exception_record.get("exception_id"),
            exception_status=exception_record.get("status"),
            exception_expiry=exception_record.get("expiry_date"),
            verification_status=lifecycle_record.get("verification_status")
            or finding.get("verification_status"),
            release_decision=release_decision["decision"],
            release_impact=release_contribution,
            required_actions=evaluation.get("required_actions", []),
            required_approvals=evaluation.get("required_approvals", []),
            remediation_guidance=finding.get("remediation_guidance"),
            source_evidence=source_evidence,
            source_record_hash=str(finding.get("source_record_hash") or _record_hash(finding)),
            lineage_references=[
                "outputs/security/integration/finding-source-lineage.json",
                "outputs/security/findings/finding-source-map.json",
            ],
            producer_metadata={
                "contract_name": CONTRACT_NAME,
                "deployment_status": DEPLOYMENT_STATUS,
                "producer": PRODUCER,
                "producer_repository": PRODUCER_REPOSITORY,
                "producer_schema_version": PRODUCER_SCHEMA_VERSION,
            },
        ).model_dump(mode="json")
        export_records.append(export_record)
        lineage_edges.extend(
            _lineage_edges_for_record(
                export_id=export_id,
                finding_id=finding_id,
                source_finding_ids=source_finding_ids,
                source_tools=source_tools,
                lifecycle_record=lifecycle_record,
                evaluation=evaluation,
            )
        )

    metrics = _metrics(
        records=export_records,
        lifecycle_payload=lifecycle_payload,
        exceptions_payload=exceptions_payload,
        verifications_payload=verifications_payload,
        release_decision=release_decision,
        metrics_payload=metrics_payload,
        control_traceability=control_traceability,
    )
    compatibility = {
        "compatibility_status": "compatible",
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "minimum_consumer_version": "1.0",
        "warnings": [
            "No live consumer compatibility check is performed by this repository.",
            "Consumer-side identifiers are intentionally not generated.",
        ],
    }
    data_quality = _data_quality(export_records, lineage_edges, metrics)
    summary = {
        "as_of_date": as_of_date,
        "compatibility_status": compatibility["compatibility_status"],
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "controlled_timestamp": timestamp,
        "export_record_count": len(export_records),
        "lineage_edge_count": len(lineage_edges),
        "release_decision": release_decision["decision"],
        "source_finding_count": len(
            {item for record in export_records for item in record["source_finding_ids"]}
        ),
        "validation_status": "passed" if data_quality["valid"] else "failed",
    }
    field_summary = {
        "contract_name": CONTRACT_NAME,
        "field_count": len(CSV_FIELDS),
        "mapping_version": load_config("field-mapping.yaml")["mapping_version"],
        "required_fields": CSV_FIELDS,
    }
    output_payloads: dict[str, Any] = {
        "product-security-findings.json": {
            "contract_name": CONTRACT_NAME,
            "contract_version": CONTRACT_VERSION,
            "findings": export_records,
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "finding-source-lineage.json": {
            "contract_version": CONTRACT_VERSION,
            "lineage_edges": sorted(lineage_edges, key=lambda item: item["checksum"]),
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "finding-lifecycle-status.json": {
            "records": sorted(lifecycle_status, key=lambda item: item["finding_id"]),
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "finding-release-impact.json": {
            "records": sorted(release_impact, key=lambda item: item["finding_id"]),
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "security-exceptions.json": exceptions_payload,
        "verification-status.json": verifications_payload,
        "control-traceability.json": {
            "records": sorted(control_traceability, key=lambda item: item["finding_id"]),
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "ownership-and-sla.json": {
            "records": sorted(ownership, key=lambda item: item["finding_id"]),
            "schema_version": PRODUCER_SCHEMA_VERSION,
        },
        "security-metrics.json": metrics,
        "integration-summary.json": summary,
        "integration-validation-summary.json": data_quality,
        "field-mapping-summary.json": field_summary,
        "compatibility-summary.json": compatibility,
        "data-quality-summary.json": data_quality,
    }

    written: list[Path] = []
    for name, payload in output_payloads.items():
        path = output_dir / name
        write_json(path, payload)
        written.append(path)
    csv_path = output_dir / "product-security-findings.csv"
    write_csv(csv_path, export_records, CSV_FIELDS)
    written.append(csv_path)

    input_manifests, input_checksums = _inputs()
    manifest = build_manifest(
        output_dir=output_dir,
        timestamp=timestamp,
        as_of_date=as_of_date,
        input_manifests=input_manifests,
        input_checksums=input_checksums,
        output_files=written,
        record_count=len(export_records),
        source_finding_count=summary["source_finding_count"],
        lifecycle_record_count=len(lifecycle_payload["vulnerabilities"]),
        exception_count=len(exceptions_payload["exceptions"]),
        verification_record_count=len(verifications_payload["verifications"]),
        lineage_edge_count=len(lineage_edges),
        compatibility_status=str(compatibility["compatibility_status"]),
        validation_status=str(summary["validation_status"]),
        limitations=[
            "This is a local export bundle only; no Repository 5 files are modified.",
            "No deployment, external upload, API integration or AWS resource creation occurs.",
            "Consumer-side identifiers and ingestion status are intentionally absent.",
        ],
    )
    manifest_path = output_dir / "integration-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    checksums = checksums_for(written, output_dir)
    checksum_path = write_checksum_file(output_dir, checksums)
    written.append(checksum_path)
    return [*written, *schema_paths]


def _source_evidence_paths(finding: dict[str, Any]) -> list[str]:
    evidence = finding.get("source_evidence") or []
    return sorted({str(item.get("path")) for item in evidence if item.get("path")})


def _record_hash(record: dict[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def _lineage_edges_for_record(
    *,
    export_id: str,
    finding_id: str,
    source_finding_ids: list[str],
    source_tools: list[str],
    lifecycle_record: dict[str, Any],
    evaluation: dict[str, Any],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    for index, source_id in enumerate(source_finding_ids or [finding_id]):
        tool = (
            source_tools[index]
            if index < len(source_tools)
            else (source_tools[0] if source_tools else "unknown")
        )
        edges.append(
            edge(
                source_id=source_id,
                target_id=finding_id,
                relationship="normalised_to_canonical_finding",
                source_domain=tool,
                target_domain="canonical_findings",
                source_reference="outputs/security/appsec/raw",
                target_reference="outputs/security/findings/deduplicated-findings.json",
            )
        )
    vulnerability_id = str(
        lifecycle_record.get("vulnerability_id") or f"missing-lifecycle:{finding_id}"
    )
    edges.append(
        edge(
            source_id=finding_id,
            target_id=vulnerability_id,
            relationship="tracked_as_lifecycle_record",
            source_domain="canonical_findings",
            target_domain="vulnerability_lifecycle",
            source_reference="outputs/security/findings/deduplicated-findings.json",
            target_reference="outputs/security/lifecycle/vulnerability-register.json",
        )
    )
    edges.append(
        edge(
            source_id=finding_id,
            target_id=str(evaluation.get("finding_id") or f"missing-release:{finding_id}"),
            relationship="evaluated_for_release",
            source_domain="canonical_findings",
            target_domain="release_assurance",
            source_reference="outputs/security/findings/deduplicated-findings.json",
            target_reference="outputs/security/release/finding-evaluations.json",
        )
    )
    edges.append(
        edge(
            source_id=finding_id,
            target_id=export_id,
            relationship="exported_as_control_plane_record",
            source_domain="canonical_findings",
            target_domain="integration_export",
            source_reference="outputs/security/findings/deduplicated-findings.json",
            target_reference="outputs/security/integration/product-security-findings.json",
        )
    )
    return edges


def _traceability_for_finding(
    *,
    finding: dict[str, Any],
    lifecycle_record: dict[str, Any],
    evaluation: dict[str, Any],
    controls_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    controls = [
        controls_by_id[item] for item in finding.get("control_ids", []) if item in controls_by_id
    ]
    evidence_refs = sorted(
        {ref for control in controls for ref in control.get("evidence_references", [])}
    )
    missing = []
    if not finding.get("threat_ids"):
        missing.append("threat_ids")
    if not finding.get("security_requirement_ids"):
        missing.append("security_requirement_ids")
    if not finding.get("control_ids"):
        missing.append("control_ids")
    if not evidence_refs:
        missing.append("control_evidence")
    return {
        "complete": not missing,
        "control_ids": finding.get("control_ids", []),
        "evidence_references": evidence_refs,
        "finding_id": finding["finding_id"],
        "implementation_references": [
            ref for control in controls for ref in control.get("implementation_references", [])
        ],
        "lifecycle_status": lifecycle_record.get("status"),
        "missing_links": missing,
        "release_impact": evaluation.get("decision_contribution"),
        "security_requirement_ids": finding.get("security_requirement_ids", []),
        "test_references": [
            ref for control in controls for ref in control.get("verification_methods", [])
        ],
        "threat_ids": finding.get("threat_ids", []),
    }


def _metrics(
    *,
    records: list[dict[str, Any]],
    lifecycle_payload: dict[str, Any],
    exceptions_payload: dict[str, Any],
    verifications_payload: dict[str, Any],
    release_decision: dict[str, Any],
    metrics_payload: dict[str, Any],
    control_traceability: list[dict[str, Any]],
) -> dict[str, Any]:
    exceptions = exceptions_payload["exceptions"]
    return {
        "active_exceptions": sum(1 for item in exceptions if item.get("status") == "active"),
        "blocking_findings": len(release_decision["blocking_finding_ids"]),
        "closed_findings": sum(1 for item in records if item.get("consumer_status") == "closed"),
        "conditional_findings": len(release_decision["conditional_finding_ids"]),
        "control_coverage": {
            "complete_traceability": sum(1 for item in control_traceability if item["complete"]),
            "incomplete_traceability": sum(
                1 for item in control_traceability if not item["complete"]
            ),
            "percentage": metrics_payload["metrics"]["control_coverage_percentage"],
        },
        "due_soon_findings": metrics_payload["metrics"]["due_soon_findings"],
        "expired_exceptions": sum(1 for item in exceptions if item.get("status") == "expired"),
        "false_positives": sum(
            1 for item in records if item.get("consumer_status") == "false_positive"
        ),
        "findings_by_domain": _counter(records, "security_domain"),
        "findings_by_lifecycle_status": _nullable_counter(records, "lifecycle_status"),
        "findings_by_owner": _counter(records, "remediation_owner"),
        "findings_by_priority": _counter(records, "priority"),
        "findings_by_severity": dict(
            sorted(Counter(item["normalised_severity"] for item in records).items())
        ),
        "findings_by_source_tool": dict(
            sorted(Counter(tool for item in records for tool in item["source_tools"]).items())
        ),
        "findings_by_squad": dict(sorted(Counter(item["squad"] for item in records).items())),
        "overdue_findings": sum(1 for item in records if item.get("overdue") is True),
        "record_count": len(records),
        "release_decision": release_decision["decision"],
        "risk_accepted_findings": sum(
            1 for item in records if item.get("consumer_status") == "risk_accepted"
        ),
        "schema_version": PRODUCER_SCHEMA_VERSION,
        "source_metrics_reference": "outputs/security/evidence/security-metrics.json",
        "suppressed_findings": sum(1 for item in records if item.get("suppression_status")),
        "total_exported_findings": len(records),
        "unowned_findings": sum(1 for item in records if not item.get("remediation_owner")),
        "verified_findings": sum(
            1 for item in records if item.get("consumer_status") == "verified"
        ),
        "verification_records": len(verifications_payload["verifications"]),
        "vulnerability_records": len(lifecycle_payload["vulnerabilities"]),
        "warning_findings": len(release_decision["warning_finding_ids"]),
    }


def _data_quality(
    records: list[dict[str, Any]], lineage_edges: list[dict[str, str]], metrics: dict[str, Any]
) -> dict[str, Any]:
    export_ids = [item["export_record_id"] for item in records]
    finding_ids = [item["finding_id"] for item in records]
    checks = {
        "all_records_have_export_ids": all(export_ids),
        "lineage_edges_present": len(lineage_edges) >= len(records),
        "metrics_reconcile": metrics["total_exported_findings"] == len(records),
        "unique_export_ids": len(export_ids) == len(set(export_ids)),
        "unique_finding_ids": len(finding_ids) == len(set(finding_ids)),
    }
    return {
        "checks": checks,
        "record_count": len(records),
        "schema_version": PRODUCER_SCHEMA_VERSION,
        "valid": all(checks.values()),
    }


def _counter(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get(field)) for item in records).items()))


def _nullable_counter(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get(field) or "not_recorded") for item in records).items()))


def _inputs() -> tuple[dict[str, str], dict[str, str]]:
    paths = {
        "appsec": ROOT / "outputs/security/appsec/evidence-manifest.json",
        "champions": ROOT / "outputs/security/champions/evidence-manifest.json",
        "consolidated": ROOT / "outputs/security/evidence/evidence-manifest.json",
        "findings": ROOT / "outputs/security/findings/evidence-manifest.json",
        "lifecycle": ROOT / "outputs/security/lifecycle/evidence-manifest.json",
        "release": ROOT / "outputs/security/release/evidence-manifest.json",
    }
    manifests = {
        domain: str(path.relative_to(ROOT)).replace("\\", "/") for domain, path in paths.items()
    }
    checksums = {domain: sha256_file(path) for domain, path in paths.items()}
    return manifests, checksums
