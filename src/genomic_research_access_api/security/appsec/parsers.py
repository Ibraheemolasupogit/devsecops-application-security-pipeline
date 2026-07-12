"""Parsers for native scanner output summaries."""

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.appsec.config import (
    RAW_DIR,
    load_json_yaml,
    validate_suppressions,
)


def _load_raw(filename: str) -> Any | None:
    path = RAW_DIR / filename
    if not path.exists():
        return None
    return load_json_yaml(path)


def _missing(tool: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "execution_status": "not_run",
        "finding_count": 0,
        "blocking_count": 0,
        "suppressed_count": 0,
        "policy_decision": "not_evaluated",
        "limitations": "raw scanner output not present",
    }


def gitleaks_summary() -> dict[str, Any]:
    data = _load_raw("gitleaks.json")
    if data is None:
        return _missing("gitleaks")
    findings = data if isinstance(data, list) else data.get("findings", [])
    return {
        "tool": "gitleaks",
        "execution_status": "completed",
        "finding_count": len(findings),
        "blocking_count": len(findings),
        "suppressed_count": 0,
        "policy_decision": "block" if findings else "pass",
        "limitations": "",
    }


def semgrep_summary() -> dict[str, Any]:
    data = _load_raw("semgrep.json")
    if data is None:
        return _missing("semgrep")
    findings = data.get("results", [])
    blocking = [item for item in findings if item.get("extra", {}).get("severity") == "ERROR"]
    return {
        "tool": "semgrep",
        "execution_status": "completed",
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "suppressed_count": 0,
        "policy_decision": "block" if blocking else "pass",
        "limitations": "",
    }


def bandit_summary() -> dict[str, Any]:
    data = _load_raw("bandit.json")
    if data is None:
        return _missing("bandit")
    findings = data.get("results", [])
    blocking = [
        item
        for item in findings
        if item.get("issue_severity") == "HIGH" and item.get("issue_confidence") == "HIGH"
    ]
    return {
        "tool": "bandit",
        "execution_status": "completed",
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "suppressed_count": 0,
        "policy_decision": "block" if blocking else "pass",
        "limitations": "",
    }


def pip_audit_summary() -> dict[str, Any]:
    data = _load_raw("pip-audit.json")
    if data is None:
        return _missing("pip-audit")
    dependencies = data.get("dependencies", [])
    vulns = [vuln for dep in dependencies for vuln in dep.get("vulns", [])]
    blocking = [vuln for vuln in vulns if vuln.get("fix_versions")]
    return {
        "tool": "pip-audit",
        "execution_status": "completed",
        "finding_count": len(vulns),
        "blocking_count": len(blocking),
        "suppressed_count": 0,
        "policy_decision": "block" if blocking else "pass",
        "limitations": "",
    }


def checkov_summary() -> dict[str, Any]:
    data = _load_raw("checkov.json")
    if data is None:
        return _missing("checkov")
    summary = data.get("summary", {})
    failed = int(summary.get("failed", 0))
    return {
        "tool": "checkov",
        "execution_status": "completed",
        "finding_count": failed,
        "blocking_count": failed,
        "suppressed_count": int(summary.get("skipped", 0)),
        "policy_decision": "block" if failed else "pass",
        "limitations": "",
    }


def trivy_summary() -> dict[str, Any]:
    data = _load_raw("trivy.json")
    if data is None:
        return _missing("trivy")
    suppressions = {
        (item.rule_or_advisory_id, item.resource_or_path)
        for item in validate_suppressions()
        if item.tool == "trivy" and item.status == "active"
    }
    results = data.get("Results", [])
    findings = []
    for result in results:
        findings.extend(result.get("Vulnerabilities", []))
        findings.extend(result.get("Secrets", []))
        findings.extend(result.get("Misconfigurations", []))
    suppressed = [
        item
        for item in findings
        if (item.get("VulnerabilityID", item.get("ID", "")), item.get("PkgName", ""))
        in suppressions
    ]
    blocking = [
        item
        for item in findings
        if item not in suppressed
        and (
            item.get("Severity") == "CRITICAL"
            or (item.get("Severity") == "HIGH" and bool(item.get("FixedVersion")))
            or item.get("Class") == "secret"
            or (item.get("Class") == "config" and item.get("Severity") == "CRITICAL")
        )
    ]
    return {
        "tool": "trivy",
        "execution_status": "completed",
        "finding_count": len(findings),
        "blocking_count": len(blocking),
        "suppressed_count": len(suppressed),
        "policy_decision": "block" if blocking else "pass",
        "limitations": "",
    }


def validate_cyclonedx(path: Path) -> dict[str, Any]:
    data = load_json_yaml(path)
    components = data.get("components", [])
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM must use CycloneDX format")
    if not any(component.get("name") == "genomic-research-access-api" for component in components):
        raise ValueError("SBOM must include project component")
    serialized = path.read_text(encoding="utf-8")
    if "/Users/" in serialized or "/private/" in serialized:
        raise ValueError("SBOM must not contain absolute local paths")
    return {
        "component_count": len(components),
        "dependency_count": len(data.get("dependencies", [])),
    }
