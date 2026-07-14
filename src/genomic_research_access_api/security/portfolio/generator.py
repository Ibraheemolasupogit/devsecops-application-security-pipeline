"""Generate deterministic portfolio readiness artefacts."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

from genomic_research_access_api.security.findings.utils import read_json, relative, write_json
from genomic_research_access_api.security.portfolio.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    OUTPUT_DIR,
    PACKAGE_DIR,
    PORTFOLIO_DOCS_DIR,
    REPORT_DIR,
    config_files,
    load_config,
)
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

PORTFOLIO_VERSION = "1.0"

EVIDENCE_PATHS = [
    "outputs/security/threat-model/evidence-manifest.json",
    "outputs/security/api-security/evidence-manifest.json",
    "outputs/security/infrastructure/evidence-manifest.json",
    "outputs/security/appsec/evidence-manifest.json",
    "outputs/security/dynamic/evidence-manifest.json",
    "outputs/security/findings/evidence-manifest.json",
    "outputs/security/release/evidence-manifest.json",
    "outputs/security/lifecycle/evidence-manifest.json",
    "outputs/security/evidence/evidence-manifest.json",
    "outputs/security/champions/evidence-manifest.json",
    "outputs/security/integration/integration-manifest.json",
]

REPORT_PATHS = [
    "reports/portfolio/final-project-report.md",
    "reports/portfolio/final-security-assurance-report.md",
    "reports/portfolio/final-architecture-report.md",
    "reports/portfolio/final-testing-report.md",
    "reports/portfolio/final-evidence-report.md",
    "reports/portfolio/final-limitations-report.md",
    "reports/portfolio/final-portfolio-readiness-report.md",
    "reports/security/executive-security-summary.md",
    "reports/security/security-evidence-report.md",
    "reports/security/portfolio-assurance-report.md",
    "reports/security/product-security-export-report.md",
    "reports/security/vulnerability-lifecycle-report.md",
    "reports/security/release-gate-report.md",
    "reports/security/appsec-pipeline-report.md",
    "reports/security/dynamic-security-report.md",
]


def generate(
    timestamp: str = DEFAULT_TIMESTAMP, as_of_date: str = DEFAULT_AS_OF_DATE
) -> dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    policy = load_config("portfolio-policy.yaml")
    criteria = load_config("readiness-criteria.yaml")
    capability_policy = load_config("capability-mapping.yaml")
    metrics = build_metrics()
    milestone_completion = build_milestones()
    capability_matrix = build_capability_matrix(capability_policy)
    evidence_index = build_index(EVIDENCE_PATHS, "evidence")
    report_index = build_index(REPORT_PATHS, "report")
    readiness = evaluate_readiness(
        metrics, milestone_completion, evidence_index, report_index, criteria
    )
    bundle_id = stable_bundle_id(metrics, milestone_completion, capability_matrix, evidence_index)
    summary = {
        "schema_version": PORTFOLIO_VERSION,
        "portfolio_id": bundle_id,
        "project_name": policy["project_name"],
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "readiness_status": readiness["status"],
        "readiness_limitations": readiness["limitations"],
        "release_decision": metrics["release_decision"],
        "deployment_status": "not_deployed",
        "milestones_completed": milestone_completion["completed_count"],
        "capability_count": capability_matrix["capability_count"],
        "canonical_findings": metrics["canonical_findings"],
        "source_findings": metrics["source_findings"],
        "evidence_sources": len(evidence_index["items"]),
        "reports_indexed": len(report_index["items"]),
        "portfolio_package": relative(PACKAGE_DIR),
    }
    outputs: dict[str, Any] = {
        "portfolio-summary.json": summary,
        "portfolio-metrics.json": {"schema_version": PORTFOLIO_VERSION, "metrics": metrics},
        "milestone-completion.json": milestone_completion,
        "security-capability-matrix.json": capability_matrix,
        "evidence-index.json": evidence_index,
        "report-index.json": report_index,
        "portfolio-readiness.json": readiness,
    }
    for name, payload in outputs.items():
        write_json(OUTPUT_DIR / name, payload)
    manifest = build_manifest(bundle_id, timestamp, as_of_date, outputs)
    write_json(OUTPUT_DIR / "portfolio-manifest.json", manifest)
    write_portfolio_package(summary, evidence_index, report_index, manifest)
    return summary


def build_metrics() -> dict[str, Any]:
    consolidated = read_json(ROOT / "outputs/security/evidence/security-metrics.json")
    findings = read_json(ROOT / "outputs/security/findings/findings-summary.json")
    integration = read_json(ROOT / "outputs/security/integration/integration-summary.json")
    champions = read_json(ROOT / "outputs/security/champions/champion-metrics.json")
    workflows = len(list((ROOT / ".github" / "workflows").glob("*.yml")))
    docs = len([path for path in (ROOT / "docs").rglob("*.md")])
    security_champion_assets = len([path for path in (ROOT / "security-champions").rglob("*.md")])
    metrics = cast(dict[str, Any], consolidated["metrics"])
    return {
        "canonical_findings": metrics["canonical_findings"],
        "source_findings": findings["total_source_findings"],
        "suppressed_findings": findings["suppressed_findings"],
        "vulnerability_records": metrics["vulnerability_records"],
        "evidence_domains": metrics["verified_evidence_domains"],
        "control_coverage_percentage": metrics["control_coverage_percentage"],
        "security_requirements": metrics["security_requirements"],
        "implemented_requirements": metrics["implemented_requirements"],
        "release_decision": metrics["release_decision"],
        "integration_export_records": integration["export_record_count"],
        "integration_lineage_edges": integration["lineage_edge_count"],
        "champion_coverage_percentage": champions["champion_coverage_percentage"],
        "ci_workflow_count": workflows,
        "markdown_document_count": docs,
        "security_champion_asset_count": security_champion_assets,
        "scanner_tools_executed": metrics["scanner_tools_executed"],
        "overdue_findings": metrics["overdue_findings"],
        "unowned_findings": metrics["unowned_findings"],
    }


def build_milestones() -> dict[str, Any]:
    milestone_dir = ROOT / "docs" / "milestones"
    items = []
    for number in range(1, 15):
        path = milestone_dir / f"milestone-{number}.md"
        items.append(
            {
                "milestone": number,
                "status": "completed" if path.exists() else "missing",
                "evidence": relative(path) if path.exists() else "",
            }
        )
    completed = [item for item in items if item["status"] == "completed"]
    return {
        "schema_version": PORTFOLIO_VERSION,
        "required_count": 14,
        "completed_count": len(completed),
        "missing_milestones": [
            item["milestone"] for item in items if item["status"] != "completed"
        ],
        "milestones": items,
    }


def build_capability_matrix(policy: dict[str, Any]) -> dict[str, Any]:
    capabilities = cast(list[dict[str, Any]], policy["capabilities"])
    enriched = []
    for item in capabilities:
        evidence = [path for path in cast(list[str], item["evidence"]) if (ROOT / path).exists()]
        enriched.append(
            {
                **item,
                "status": "implemented" if len(evidence) == len(item["evidence"]) else "partial",
                "evidence_present": len(evidence),
            }
        )
    return {
        "schema_version": PORTFOLIO_VERSION,
        "capability_count": len(enriched),
        "implemented_count": len([item for item in enriched if item["status"] == "implemented"]),
        "capabilities": enriched,
    }


def build_index(paths: list[str], index_type: str) -> dict[str, Any]:
    items = []
    missing = []
    for item in paths:
        path = ROOT / item
        if not path.exists():
            missing.append(item)
            continue
        items.append(
            {
                "type": index_type,
                "path": item,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return {
        "schema_version": PORTFOLIO_VERSION,
        "index_type": index_type,
        "items": items,
        "missing_paths": missing,
        "valid": not missing,
    }


def evaluate_readiness(
    metrics: dict[str, Any],
    milestones: dict[str, Any],
    evidence: dict[str, Any],
    reports: dict[str, Any],
    criteria: dict[str, Any],
) -> dict[str, Any]:
    failures = []
    limitations = list(cast(list[str], criteria["known_limitations"]))
    if milestones["completed_count"] != milestones["required_count"]:
        failures.append("not all milestones have documented completion evidence")
    if not evidence["valid"]:
        failures.append("portfolio evidence index has missing paths")
    if not reports["valid"]:
        failures.append("portfolio report index has missing paths")
    if metrics["overdue_findings"] != 0:
        failures.append("overdue findings remain")
    if metrics["unowned_findings"] != 0:
        failures.append("unowned findings remain")
    status = "not_ready" if failures else "ready_with_limitations"
    return {
        "schema_version": PORTFOLIO_VERSION,
        "status": status,
        "failures": failures,
        "limitations": limitations,
        "criteria_version": criteria["criteria_version"],
    }


def stable_bundle_id(
    metrics: dict[str, Any],
    milestones: dict[str, Any],
    capability_matrix: dict[str, Any],
    evidence_index: dict[str, Any],
) -> str:
    payload = {
        "version": PORTFOLIO_VERSION,
        "metrics": metrics,
        "milestones": milestones,
        "capabilities": capability_matrix,
        "evidence": evidence_index,
    }
    digest = hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()[:16]
    return f"PF-{digest}"


def build_manifest(
    bundle_id: str, timestamp: str, as_of_date: str, generated: dict[str, Any]
) -> dict[str, Any]:
    output_files = {}
    for path in sorted(OUTPUT_DIR.glob("*.json")):
        if path.name == "portfolio-manifest.json":
            continue
        output_files[path.name] = {
            "path": relative(path),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    git = git_metadata()
    return {
        "schema_version": PORTFOLIO_VERSION,
        "portfolio_id": bundle_id,
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "git": git,
        "input_files": {
            relative(path): {"path": relative(path), "sha256": sha256_file(path)}
            for path in config_files()
        },
        "output_files": output_files,
        "generated_artifacts": sorted(generated),
        "deterministic_archive_created": False,
        "archive_limitation": (
            "No archive is created to avoid platform-specific tar metadata drift."
        ),
    }


def git_metadata() -> dict[str, str]:
    def run(args: list[str]) -> str:
        result = subprocess.run(args, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            return "unknown"
        return result.stdout.strip() or "unknown"

    return {
        "branch": run(["git", "branch", "--show-current"]),
        "commit": run(["git", "rev-parse", "--short=12", "HEAD"]),
        "dirty": "true" if run(["git", "status", "--short"]) else "false",
    }


def write_portfolio_package(
    summary: dict[str, Any],
    evidence_index: dict[str, Any],
    report_index: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    for existing in PACKAGE_DIR.glob("*"):
        if existing.is_file():
            existing.unlink()
        elif existing.is_dir():
            shutil.rmtree(existing)
    write_json(PACKAGE_DIR / "portfolio-summary.json", summary)
    write_json(PACKAGE_DIR / "evidence-index.json", evidence_index)
    write_json(PACKAGE_DIR / "report-index.json", report_index)
    write_json(PACKAGE_DIR / "portfolio-manifest.json", manifest)
    docs_dir = PACKAGE_DIR / "docs"
    reports_dir = PACKAGE_DIR / "reports"
    docs_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    for source in [
        PORTFOLIO_DOCS_DIR / "project-case-study.md",
        PORTFOLIO_DOCS_DIR / "portfolio-evidence-index.md",
        ROOT / "README.md",
    ]:
        if source.exists():
            shutil.copy2(source, docs_dir / source.name)
    for item in cast(list[dict[str, Any]], report_index["items"])[:5]:
        source = ROOT / str(item["path"])
        shutil.copy2(source, reports_dir / source.name)
    (PACKAGE_DIR / "README.md").write_text(
        "# Portfolio Package\n\n"
        "Deterministic portfolio summary package generated from committed security evidence. "
        "No deployment credentials, raw scanner secrets, or external service outputs are "
        "included.\n",
        encoding="utf-8",
        newline="\n",
    )


MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def display_path(path: Path) -> str:
    try:
        return relative(path)
    except ValueError:
        return path.name


def markdown_links(paths: list[Path]) -> list[str]:
    broken = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                broken.append(f"{display_path(path)} links outside repository: {target}")
                continue
            if not resolved.exists():
                broken.append(f"{display_path(path)} has broken link: {target}")
    return broken
