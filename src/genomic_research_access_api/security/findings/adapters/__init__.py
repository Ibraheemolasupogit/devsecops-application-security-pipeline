"""Tool-specific adapters for Milestone 7 findings normalisation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.config import DEFAULT_AS_OF_DATE
from genomic_research_access_api.security.findings.enums import (
    Confidence,
    FindingStatus,
    FindingType,
    Severity,
    SourceType,
)
from genomic_research_access_api.security.findings.identifiers import (
    finding_id,
    normalise_path,
    source_record_hash,
)
from genomic_research_access_api.security.findings.models import Finding, SourceEvidence
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.threat_model.io import ROOT


def _severity(value: str | None) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
        "info": Severity.INFORMATIONAL,
    }
    return mapping.get((value or "").lower(), Severity.UNKNOWN)


def _evidence(
    path: Path, pointer: str, record: Any, summary: str | None = None
) -> list[SourceEvidence]:
    return [
        SourceEvidence(
            path=normalise_path(str(path)) or str(path),
            record_pointer=pointer,
            record_hash=source_record_hash(record),
            summary=summary,
        )
    ]


def _base(
    *,
    source_tool: str,
    source_type: SourceType,
    finding_type: FindingType,
    domain: str,
    source_id: str,
    title: str,
    description: str,
    severity: str | None,
    key: dict[str, Any],
    record: Any,
    path: Path,
    pointer: str,
    as_of_date: str,
    **kwargs: Any,
) -> Finding:
    normalised = _severity(severity)
    return Finding(
        finding_id=finding_id(domain, key),
        source_finding_id=source_id,
        source_tool=source_tool,
        source_type=source_type,
        finding_type=finding_type,
        security_domain=domain,
        title=title[:240],
        description=(description or title)[:2000],
        severity=severity,
        normalised_severity=normalised,
        confidence=kwargs.pop("confidence", Confidence.MEDIUM),
        first_detected=as_of_date,
        last_detected=as_of_date,
        source_record_hash=source_record_hash(record),
        source_evidence=_evidence(path, pointer, record, title),
        deduplication_key=kwargs.pop(
            "deduplication_key", "|".join(str(value) for value in key.values())
        ),
        **kwargs,
    )


def threat_model_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "docs" / "threat-model" / "residual-risk-register.yaml"
    records = read_json(path)
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.get("residual_rating") in {"medium", "high", "critical"}:
            source_id = record["risk_id"]
            domain = "Secure Design"
            findings.append(
                _base(
                    source_tool="threat-model",
                    source_type=SourceType.THREAT_MODEL,
                    finding_type=FindingType.THREAT_MODEL,
                    domain=domain,
                    source_id=source_id,
                    title=f"Residual design risk {source_id}",
                    description=record["description"],
                    severity=record.get("residual_rating"),
                    key={"tool": "threat-model", "risk": source_id},
                    record=record,
                    path=path,
                    pointer=f"/{index}",
                    as_of_date=as_of_date,
                    threat_ids=record.get("related_threat_ids", []),
                    security_requirement_ids=[],
                    asset_id="AST-APP-FASTAPI",
                    component="threat-model",
                    resource=source_id,
                    status=FindingStatus.ACTIVE,
                    metadata={
                        "risk_kind": "residual risk",
                        "treatment": record.get("treatment"),
                        "planned_milestone": record.get("planned_milestone"),
                        "control_limitations": record.get("control_limitations", []),
                    },
                )
            )
    return findings


def gitleaks_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "gitleaks.json"
    records = read_json(path)
    if not isinstance(records, list):
        raise ValueError("gitleaks output must be a list")
    findings: list[Finding] = []
    for index, record in enumerate(records):
        rule = record.get("RuleID") or record.get("rule") or "secret"
        file_path = normalise_path(record.get("File"))
        findings.append(
            _base(
                source_tool="gitleaks",
                source_type=SourceType.SECRET_SCAN,
                finding_type=FindingType.SECRET,
                domain="Secret",
                source_id=f"{rule}:{file_path}:{record.get('StartLine')}",
                title=f"Gitleaks secret finding {rule}",
                description=record.get("Description") or "Secret material detected by Gitleaks.",
                severity="critical",
                key={
                    "tool": "gitleaks",
                    "rule": rule,
                    "file": file_path,
                    "line": record.get("StartLine"),
                },
                record=record,
                path=path,
                pointer=f"/{index}",
                as_of_date=as_of_date,
                file=file_path,
                line=record.get("StartLine"),
                asset_id="AST-CI"
                if file_path and file_path.startswith(".github")
                else "AST-APP-FASTAPI",
                remediation_guidance="Remove the secret and rotate affected credentials.",
                deduplication_key=f"secret|{rule}|{file_path}",
            )
        )
    return findings


def semgrep_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "semgrep.json"
    payload = read_json(path)
    findings: list[Finding] = []
    for index, record in enumerate(payload.get("results", [])):
        check_id = record.get("check_id", "semgrep")
        file_path = normalise_path(record.get("path"))
        line = record.get("start", {}).get("line")
        extra = record.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe = None
        cwe_values = metadata.get("cwe") or []
        if cwe_values:
            cwe = str(cwe_values[0]).split(":")[0]
        findings.append(
            _base(
                source_tool="semgrep",
                source_type=SourceType.STATIC_ANALYSIS,
                finding_type=FindingType.SAST,
                domain="SAST",
                source_id=check_id,
                title=extra.get("message", check_id),
                description=extra.get("message", check_id),
                severity=metadata.get("impact") or extra.get("severity"),
                key={"tool": "semgrep", "rule": check_id, "file": file_path, "line": line},
                record=record,
                path=path,
                pointer=f"/results/{index}",
                as_of_date=as_of_date,
                file=file_path,
                line=line,
                cwe=cwe,
                asset_id="AST-APP-FASTAPI",
                remediation_guidance=(
                    "Review the Semgrep rule guidance and replace the unsafe code pattern."
                ),
                deduplication_key=f"sast|{cwe}|{file_path}|{line}|{check_id}",
            )
        )
    return findings


def bandit_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "bandit.json"
    payload = read_json(path)
    findings: list[Finding] = []
    for index, record in enumerate(payload.get("results", [])):
        test_id = record.get("test_id", "bandit")
        file_path = normalise_path(record.get("filename"))
        line = record.get("line_number")
        cwe = record.get("issue_cwe", {}).get("id")
        cwe_value = f"CWE-{cwe}" if cwe else None
        findings.append(
            _base(
                source_tool="bandit",
                source_type=SourceType.STATIC_ANALYSIS,
                finding_type=FindingType.SAST,
                domain="SAST",
                source_id=test_id,
                title=record.get("test_name", test_id),
                description=record.get("issue_text", test_id),
                severity=record.get("issue_severity"),
                key={"tool": "bandit", "rule": test_id, "file": file_path, "line": line},
                record=record,
                path=path,
                pointer=f"/results/{index}",
                as_of_date=as_of_date,
                file=file_path,
                line=line,
                cwe=cwe_value,
                asset_id="AST-APP-FASTAPI",
                confidence=_severity(record.get("issue_confidence")).value
                if record.get("issue_confidence")
                else Confidence.MEDIUM,
                remediation_guidance=record.get("more_info"),
                deduplication_key=f"sast|{cwe_value}|{file_path}|{line}|{test_id}",
            )
        )
    return findings


def pip_audit_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "pip-audit.json"
    payload = read_json(path)
    findings: list[Finding] = []
    for dep_index, dependency in enumerate(payload.get("dependencies", [])):
        for vuln_index, vuln in enumerate(dependency.get("vulns", [])):
            cve = vuln.get("id")
            findings.append(
                _base(
                    source_tool="pip-audit",
                    source_type=SourceType.DEPENDENCY_SCAN,
                    finding_type=FindingType.SCA,
                    domain="SCA",
                    source_id=cve,
                    title=f"{dependency.get('name')} {cve}",
                    description=vuln.get("description") or cve,
                    severity="unknown",
                    key={"tool": "pip-audit", "cve": cve, "package": dependency.get("name")},
                    record=vuln,
                    path=path,
                    pointer=f"/dependencies/{dep_index}/vulns/{vuln_index}",
                    as_of_date=as_of_date,
                    package_name=dependency.get("name"),
                    installed_version=dependency.get("version"),
                    fixed_version=",".join(vuln.get("fix_versions", [])) or None,
                    cve=cve,
                    asset_id="AST-DEPS-PYTHON",
                    remediation_guidance="Upgrade to a fixed package version when available.",
                    deduplication_key=f"cve|{cve}|{dependency.get('name')}",
                )
            )
    return findings


def checkov_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "checkov.json"
    payload = read_json(path)
    results: list[dict[str, Any]] = []
    if isinstance(payload, list):
        for section in payload:
            results.extend(section.get("results", {}).get("failed_checks", []))
    else:
        results.extend(payload.get("results", {}).get("failed_checks", []))
    findings: list[Finding] = []
    for index, record in enumerate(results):
        check_id = record.get("check_id", "checkov")
        file_path = normalise_path(record.get("file_path"))
        resource = record.get("resource")
        findings.append(
            _base(
                source_tool="checkov",
                source_type=SourceType.IAC_SCAN,
                finding_type=FindingType.IAC,
                domain="IaC",
                source_id=check_id,
                title=record.get("check_name", check_id),
                description=record.get("guideline") or record.get("check_name", check_id),
                severity="high",
                key={"tool": "checkov", "rule": check_id, "resource": resource, "file": file_path},
                record=record,
                path=path,
                pointer=f"/results/failed_checks/{index}",
                as_of_date=as_of_date,
                file=file_path,
                resource=resource,
                cloud_provider="aws",
                asset_id="AST-TERRAFORM",
                remediation_guidance=record.get("guideline"),
                deduplication_key=f"iac|{check_id}|{resource}|{file_path}",
            )
        )
    return findings


def trivy_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "appsec" / "raw" / "trivy.json"
    payload = read_json(path)
    findings: list[Finding] = []
    for result_index, result in enumerate(payload.get("Results", [])):
        for vuln_index, vuln in enumerate(result.get("Vulnerabilities", [])):
            cve = vuln.get("VulnerabilityID")
            package = vuln.get("PkgName")
            fixed = vuln.get("FixedVersion")
            findings.append(
                _base(
                    source_tool="trivy",
                    source_type=SourceType.CONTAINER_SCAN,
                    finding_type=FindingType.CONTAINER,
                    domain="Container",
                    source_id=cve,
                    title=f"{package} {cve}",
                    description=vuln.get("Description") or vuln.get("Title") or cve,
                    severity=vuln.get("Severity"),
                    key={"tool": "trivy", "cve": cve, "package": package},
                    record=vuln,
                    path=path,
                    pointer=f"/Results/{result_index}/Vulnerabilities/{vuln_index}",
                    as_of_date=as_of_date,
                    package_name=package,
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=fixed,
                    cve=cve,
                    asset_id="AST-CONTAINER",
                    component=result.get("Target"),
                    remediation_guidance=(
                        "Rebuild on an updated base image or apply a compensating control "
                        "when no fix exists."
                    ),
                    deduplication_key=f"cve|{cve}|{package}",
                    metadata={
                        "fix_available": bool(fixed),
                        "data_source": vuln.get("DataSource", {}).get("Name"),
                    },
                )
            )
    return findings


def schemathesis_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "dynamic" / "schemathesis-summary.json"
    record = read_json(path)
    if record.get("failed_count", 0) == 0:
        return []
    return [
        _base(
            source_tool="schemathesis",
            source_type=SourceType.DYNAMIC_SCAN,
            finding_type=FindingType.API_SECURITY,
            domain="API Security",
            source_id="schemathesis-failures",
            title="Schemathesis API contract failures",
            description="Schema-based dynamic API testing reported failures.",
            severity="high",
            key={"tool": "schemathesis", "status": "failed"},
            record=record,
            path=path,
            pointer="/",
            as_of_date=as_of_date,
            asset_id="AST-OPENAPI",
            security_requirement_ids=["SR-API-001"],
            deduplication_key="api-schema|schemathesis",
        )
    ]


def zap_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "dynamic" / "raw" / "zap-report.json"
    payload = read_json(path)
    findings: list[Finding] = []
    alerts = payload.get("site", [{}])[0].get("alerts", [])
    for index, alert in enumerate(alerts):
        risk = str(alert.get("riskdesc", "unknown")).split(" ")[0]
        uri = None
        if alert.get("instances"):
            uri = alert["instances"][0].get("uri")
        findings.append(
            _base(
                source_tool="zap",
                source_type=SourceType.DYNAMIC_SCAN,
                finding_type=FindingType.DAST,
                domain="DAST",
                source_id=alert.get("pluginid") or alert.get("alertRef") or alert.get("name"),
                title=alert.get("name") or alert.get("alert"),
                description=alert.get("desc") or alert.get("alert"),
                severity=risk,
                key={"tool": "zap", "plugin": alert.get("pluginid"), "uri": uri},
                record=alert,
                path=path,
                pointer=f"/site/0/alerts/{index}",
                as_of_date=as_of_date,
                cwe=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                resource=uri,
                asset_id="AST-APP-FASTAPI",
                remediation_guidance=alert.get("solution"),
                deduplication_key=f"dast|{alert.get('pluginid')}|{uri}",
                metadata={"riskcode": alert.get("riskcode"), "confidence": alert.get("confidence")},
            )
        )
    return findings


def dynamic_pytest_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    path = ROOT / "outputs" / "security" / "dynamic" / "raw" / "pytest-dynamic.json"
    payload = read_json(path)
    findings: list[Finding] = []
    for index, record in enumerate(payload.get("tests", [])):
        if record.get("outcome") != "passed":
            nodeid = record.get("nodeid", "dynamic-pytest")
            findings.append(
                _base(
                    source_tool="dynamic-pytest",
                    source_type=SourceType.TEST_RESULT,
                    finding_type=FindingType.API_SECURITY,
                    domain="API Security",
                    source_id=nodeid,
                    title=f"Dynamic security test failed: {nodeid}",
                    description="A dynamic API security boundary test failed.",
                    severity="high",
                    key={"tool": "dynamic-pytest", "nodeid": nodeid},
                    record=record,
                    path=path,
                    pointer=f"/tests/{index}",
                    as_of_date=as_of_date,
                    file=normalise_path(nodeid.split("::", 1)[0]),
                    asset_id="AST-APP-FASTAPI",
                    deduplication_key=f"dynamic-test|{nodeid}",
                )
            )
    return findings


def suppression_findings(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    paths = [
        ROOT / "security" / "config" / "suppressions.yaml",
        ROOT / "security" / "dynamic" / "suppressions.yaml",
    ]
    findings: list[Finding] = []
    for path in paths:
        payload = read_json(path)
        for index, record in enumerate(payload.get("suppressions", [])):
            tool = record.get("tool", "suppression")
            rule = record.get("rule_or_advisory_id", record.get("id", "suppression"))
            resource = normalise_path(record.get("resource_or_path") or record.get("resource"))
            severity = (
                "critical"
                if tool == "gitleaks"
                else "high"
                if tool in {"trivy", "checkov"}
                else "medium"
            )
            ftype = (
                FindingType.SECRET
                if tool == "gitleaks"
                else FindingType.CONTAINER
                if tool == "trivy"
                else FindingType.IAC
            )
            asset = (
                "AST-CONTAINER"
                if tool == "trivy"
                else "AST-TERRAFORM"
                if tool == "checkov"
                else "AST-APP-FASTAPI"
            )
            findings.append(
                _base(
                    source_tool=tool,
                    source_type=SourceType.MANUAL_FIXTURE,
                    finding_type=ftype,
                    domain="Suppression Governance",
                    source_id=record["suppression_id"],
                    title=f"Suppressed {tool} finding {rule}",
                    description=record.get("reason", "Governed suppression remains visible."),
                    severity=severity,
                    key={
                        "tool": tool,
                        "suppression": record["suppression_id"],
                        "rule": rule,
                        "resource": resource,
                    },
                    record=record,
                    path=path,
                    pointer=f"/suppressions/{index}",
                    as_of_date=as_of_date,
                    resource=resource,
                    package_name=resource if tool == "trivy" else None,
                    cve=rule if str(rule).startswith("CVE-") else None,
                    asset_id=asset,
                    status=FindingStatus.SUPPRESSED,
                    suppression_id=record["suppression_id"],
                    suppression_status=record.get("status"),
                    suppression_expiry=record.get("expiry_date"),
                    suppression_reason=record.get("reason"),
                    compensating_control=record.get("compensating_control"),
                    remediation_guidance=(
                        "Review suppression before expiry; remediate if compensating control "
                        "is no longer valid."
                    ),
                    deduplication_key=f"suppression|{tool}|{rule}|{resource}",
                    metadata={
                        "approved_by": record.get("approved_by"),
                        "review_date": record.get("review_date"),
                    },
                )
            )
    return findings


ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {
    "threat-model": threat_model_findings,
    "gitleaks": gitleaks_findings,
    "semgrep": semgrep_findings,
    "bandit": bandit_findings,
    "pip-audit": pip_audit_findings,
    "checkov": checkov_findings,
    "trivy": trivy_findings,
    "schemathesis": schemathesis_findings,
    "zap": zap_findings,
    "dynamic-pytest": dynamic_pytest_findings,
    "suppressions": suppression_findings,
}


def load_all(as_of_date: str = DEFAULT_AS_OF_DATE) -> list[Finding]:
    findings: list[Finding] = []
    for name in sorted(ADAPTERS):
        findings.extend(ADAPTERS[name](as_of_date))
    return sorted(
        findings, key=lambda item: (item.source_tool, item.source_finding_id, item.finding_id)
    )
