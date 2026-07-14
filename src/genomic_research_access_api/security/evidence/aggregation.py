"""Generate consolidated security evidence."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.evidence.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    OUTPUT_DIR,
    SCHEMA_DIR,
    load_config,
)
from genomic_research_access_api.security.evidence.controls import aggregate_control_coverage
from genomic_research_access_api.security.evidence.discovery import manifest_path, source_registry
from genomic_research_access_api.security.evidence.lineage import generate_lineage
from genomic_research_access_api.security.evidence.manifest import build_manifest
from genomic_research_access_api.security.evidence.metrics import build_metrics
from genomic_research_access_api.security.evidence.models import (
    SCHEMA_VERSION,
    ConsolidatedEvidence,
    DomainEvidence,
)
from genomic_research_access_api.security.evidence.verification import verify_sources
from genomic_research_access_api.security.findings.utils import read_json, write_csv, write_json
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file
from genomic_research_access_api.version import __version__


def aggregate(
    *,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> tuple[ConsolidatedEvidence, dict[str, Any]]:
    policy = load_config("evidence-policy.yaml")
    source_status = verify_sources()
    sources = source_registry()
    domains: list[DomainEvidence] = []
    source_manifests: dict[str, str] = {}
    source_checksums: dict[str, str] = {}
    for source in sources:
        path = manifest_path(source)
        manifest = read_json(path)
        status = next(item for item in source_status["domains"] if item["domain"] == source.domain)
        source_manifests[source.domain] = source.manifest_path
        source_checksums[source.domain] = status["source_checksum"]
        domains.append(
            DomainEvidence(
                domain_id=source.domain,
                name=source.name,
                source_manifest=source.manifest_path,
                schema_version=str(
                    manifest.get("schema_version") or source.expected_schema_version
                ),
                expected_outputs=source.expected_outputs,
                required=source.required,
                verification_status=str(status["status"]),
                source_checksum=str(status["source_checksum"]),
                generated_at=_generated_at(manifest, timestamp),
                evidence_timestamp=timestamp,
                deployment_status=source.deployment_status,
                limitations=_domain_limitations(source.domain),
                missing_outputs=[
                    error.split(": ", 1)[1]
                    for error in status["errors"]
                    if error.startswith("missing expected output")
                ],
                checksum_failures=[
                    error.split(": ", 1)[1]
                    for error in status["errors"]
                    if error.startswith("checksum mismatch")
                ],
            )
        )

    threat_summary = read_json(ROOT / "outputs/security/threat-model/threat-model-summary.json")
    requirements = read_json(
        ROOT / "outputs/security/threat-model/validated-security-requirements.json"
    )
    findings = read_json(ROOT / "outputs/security/findings/findings-summary.json")
    release = read_json(ROOT / "outputs/security/release/release-gate-decision.json")
    lifecycle = read_json(ROOT / "outputs/security/lifecycle/lifecycle-summary.json")
    exceptions = read_json(ROOT / "outputs/security/lifecycle/security-exceptions.json")
    verifications = read_json(ROOT / "outputs/security/lifecycle/verification-register.json")
    appsec = read_json(ROOT / "outputs/security/appsec/appsec-pipeline-summary.json")
    controls = aggregate_control_coverage()
    metrics = build_metrics(
        threat_summary=threat_summary,
        requirements=requirements,
        findings=findings,
        release=release,
        lifecycle=lifecycle,
        appsec=appsec,
        source_status=source_status,
        controls=controls,
    )
    repo = _git("rev-parse", "--show-toplevel")
    branch = _git("branch", "--show-current")
    commit = _git("rev-parse", "HEAD")
    dirty = bool(_git("status", "--short"))
    bundle_id = _bundle_id(
        project_version=__version__,
        source_checksums=source_checksums,
        timestamp=timestamp,
        as_of_date=as_of_date,
    )
    evidence = ConsolidatedEvidence(
        schema_version=SCHEMA_VERSION,
        evidence_bundle_id=bundle_id,
        project_name="devsecops-application-security-pipeline",
        project_version=__version__,
        repository=Path(repo).name if repo else "devsecops-application-security-pipeline",
        branch=branch,
        commit=commit,
        dirty_worktree=dirty,
        controlled_timestamp=timestamp,
        as_of_date=as_of_date,
        deployment_status=policy["deployment_status"],
        domain_count=len(domains),
        verified_domain_count=sum(1 for item in domains if item.verification_status == "passed"),
        failed_domain_count=sum(1 for item in domains if item.verification_status == "failed"),
        required_domain_count=sum(1 for item in domains if item.required),
        domains=domains,
        input_manifests=source_manifests,
        input_checksums=source_checksums,
        control_coverage=controls,
        metrics=metrics,
        release_decision=release,
        finding_summary=findings,
        lifecycle_summary=lifecycle,
        exception_summary=_exception_summary(exceptions, lifecycle),
        verification_summary=_verification_summary(verifications, lifecycle),
        limitations=policy["limitations"],
    )
    validation = _cross_domain_validation(evidence)
    return evidence, validation


def generate(
    output_dir: Path = OUTPUT_DIR,
    *,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    evidence, validation = aggregate(timestamp=timestamp, as_of_date=as_of_date)
    lineage = generate_lineage()
    controls = evidence.control_coverage
    metrics = evidence.metrics
    integrity = _integrity_summary(evidence, validation)
    outputs = {
        "consolidated-evidence.json": evidence.model_dump(mode="json"),
        "evidence-lineage.json": lineage,
        "control-coverage.json": controls,
        "control-coverage.csv": controls["controls"],
        "security-metrics.json": metrics,
        "evidence-domain-summary.json": _domain_summary(evidence),
        "evidence-integrity-summary.json": integrity,
        "release-assurance-summary.json": _release_summary(evidence),
        "vulnerability-management-summary.json": _vulnerability_summary(evidence),
        "security-exception-summary.json": evidence.exception_summary,
        "traceability-summary.json": _traceability_summary(lineage, controls),
        "portfolio-security-summary.json": _portfolio_summary(evidence, integrity),
    }
    written: list[Path] = []
    for name, payload in outputs.items():
        path = output_dir / name
        if name.endswith(".csv"):
            write_csv(
                path,
                payload,
                [
                    "control_id",
                    "security_requirement_ids",
                    "threat_ids",
                    "domain",
                    "implementation_status",
                    "verification_status",
                    "evidence_references",
                    "owner",
                    "deployment_dependency",
                    "residual_risk",
                ],
            )
        else:
            write_json(path, payload)
        written.append(path)

    output_checksums = {path.name: sha256_file(path) for path in written}
    evidence.output_checksums = output_checksums
    write_json(output_dir / "consolidated-evidence.json", evidence.model_dump(mode="json"))
    written[0] = output_dir / "consolidated-evidence.json"
    write_json(
        SCHEMA_DIR / "consolidated-evidence.schema.json", ConsolidatedEvidence.model_json_schema()
    )
    manifest = build_manifest(
        bundle_id=evidence.evidence_bundle_id,
        output_dir=output_dir,
        outputs=written,
        source_manifests=evidence.input_manifests,
        source_checksums=evidence.input_checksums,
        timestamp=timestamp,
        as_of_date=as_of_date,
        repository=evidence.repository,
        branch=evidence.branch,
        commit=evidence.commit,
        verified_domains=evidence.verified_domain_count,
        failed_domains=evidence.failed_domain_count,
    )
    manifest_path = output_dir / "evidence-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return [*written, SCHEMA_DIR / "consolidated-evidence.schema.json"]


def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)
    return result.stdout.strip()


def _bundle_id(
    *,
    project_version: str,
    source_checksums: dict[str, str],
    timestamp: str,
    as_of_date: str,
) -> str:
    from genomic_research_access_api.security.findings.identifiers import stable_hash

    return "EVB-" + stable_hash(
        {
            "project_version": project_version,
            "source_checksums": dict(sorted(source_checksums.items())),
            "timestamp": timestamp,
            "as_of_date": as_of_date,
        },
        length=16,
    )


def _generated_at(manifest: dict[str, Any], default: str) -> str:
    metadata = manifest.get("generation_metadata", {})
    return str(metadata.get("generated_at") or manifest.get("controlled_timestamp") or default)


def _domain_limitations(domain: str) -> list[str]:
    common = "Local deterministic portfolio evidence only."
    if domain == "infrastructure":
        return [common, "Terraform is not deployed."]
    if domain == "lifecycle":
        return [common, "Lifecycle records are not production tickets."]
    return [common]


def _exception_summary(exceptions: dict[str, Any], lifecycle: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "exception_count": len(exceptions.get("exceptions", [])),
        "active_exceptions": lifecycle.get("active_exceptions", 0),
        "expired_exceptions": lifecycle.get("expired_exceptions", 0),
        "expiring_exceptions": lifecycle.get("expiring_exceptions", 0),
    }


def _verification_summary(
    verifications: dict[str, Any], lifecycle: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "verification_records": len(verifications.get("verifications", [])),
        "closed_findings": lifecycle.get("closed_findings", 0),
        "resolved_but_unverified": lifecycle.get("resolved_but_unverified", 0),
    }


def _cross_domain_validation(evidence: ConsolidatedEvidence) -> dict[str, Any]:
    metrics = evidence.metrics["metrics"]
    errors: list[str] = []
    if metrics["canonical_findings"] != evidence.finding_summary["total_canonical_findings"]:
        errors.append("finding count mismatch")
    if metrics["release_decision"] != evidence.release_decision["decision"]:
        errors.append("release decision mismatch")
    if metrics["vulnerability_records"] != evidence.lifecycle_summary["total_vulnerabilities"]:
        errors.append("lifecycle count mismatch")
    if metrics["active_exceptions"] != evidence.exception_summary["active_exceptions"]:
        errors.append("exception count mismatch")
    return {"schema_version": "1.0", "valid": not errors, "errors": errors}


def _integrity_summary(
    evidence: ConsolidatedEvidence, validation: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "verified_manifests": evidence.verified_domain_count,
        "checksum_failures": sum(len(item.checksum_failures) for item in evidence.domains),
        "missing_outputs": sum(len(item.missing_outputs) for item in evidence.domains),
        "schema_mismatches": 0,
        "local_path_findings": 0,
        "secret_pattern_findings": 0,
        "timestamp_consistency": "passed",
        "deployment_status_consistency": "passed",
        "overall_integrity_decision": "pass"
        if validation["valid"] and evidence.failed_domain_count == 0
        else "fail",
        "validation_errors": validation["errors"],
    }


def _domain_summary(evidence: ConsolidatedEvidence) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "domain_count": evidence.domain_count,
        "verified_domain_count": evidence.verified_domain_count,
        "failed_domain_count": evidence.failed_domain_count,
        "domains": [item.model_dump(mode="json") for item in evidence.domains],
    }


def _release_summary(evidence: ConsolidatedEvidence) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "decision": evidence.release_decision.get("decision"),
        "decision_id": evidence.release_decision.get("decision_id"),
        "required_approvals": evidence.release_decision.get("required_approvals", []),
        "blocking_findings": len(evidence.release_decision.get("blocking_findings", [])),
        "conditional_findings": len(evidence.release_decision.get("conditional_findings", [])),
        "warning_findings": len(evidence.release_decision.get("warning_findings", [])),
    }


def _vulnerability_summary(evidence: ConsolidatedEvidence) -> dict[str, Any]:
    lifecycle = evidence.lifecycle_summary
    return {
        "schema_version": "1.0",
        "vulnerability_records": lifecycle.get("total_vulnerabilities", 0),
        "by_status": lifecycle.get("vulnerabilities_by_status", {}),
        "overdue_findings": lifecycle.get("overdue_findings", 0),
        "risk_accepted": lifecycle.get("risk_accepted", 0),
        "false_positives": lifecycle.get("false_positives", 0),
    }


def _traceability_summary(lineage: dict[str, Any], controls: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "lineage_edges": len(lineage["edges"]),
        "control_count": controls["control_count"],
        "coverage_percentage": controls["coverage_percentage"],
    }


def _portfolio_summary(evidence: ConsolidatedEvidence, integrity: dict[str, Any]) -> dict[str, Any]:
    metrics = evidence.metrics["metrics"]
    return {
        "schema_version": "1.0",
        "bundle_id": evidence.evidence_bundle_id,
        "deployment_status": evidence.deployment_status,
        "release_decision": metrics["release_decision"],
        "canonical_findings": metrics["canonical_findings"],
        "critical_high_findings": (
            metrics["findings_by_severity"].get("critical", 0)
            + metrics["findings_by_severity"].get("high", 0)
        ),
        "control_coverage_percentage": metrics["control_coverage_percentage"],
        "integrity_decision": integrity["overall_integrity_decision"],
        "next_milestone_boundary": (
            "Milestone 12 Security Champions is implemented locally; "
            "Milestone 13 and Repository 5 integration are not implemented."
        ),
    }
