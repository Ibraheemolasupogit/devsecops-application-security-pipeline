"""Generate deterministic Milestone 7 findings evidence."""

from __future__ import annotations

import argparse
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.findings.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    OUTPUT_DIR,
    SCHEMA_DIR,
    all_config_files,
)
from genomic_research_access_api.security.findings.enrichment import asset_inventory
from genomic_research_access_api.security.findings.models import Finding, FindingsDocument
from genomic_research_access_api.security.findings.normalizer import build, source_tool_names
from genomic_research_access_api.security.findings.utils import relative, write_csv, write_json
from genomic_research_access_api.security.findings.verify import validate_findings, verify_manifest
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file
from genomic_research_access_api.version import __version__

FINDING_COLUMNS = [
    "finding_id",
    "source_finding_id",
    "source_tool",
    "finding_type",
    "security_domain",
    "title",
    "normalised_severity",
    "priority",
    "risk_score",
    "asset_id",
    "technical_owner",
    "remediation_owner",
    "due_date",
    "suppression_id",
    "suppression_status",
    "cve",
    "cwe",
    "file",
    "package_name",
    "fixed_version",
]


def finding_rows(findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding.model_dump(mode="json") for finding in findings]


def generate(
    output_dir: Path = OUTPUT_DIR,
    *,
    timestamp: str = DEFAULT_TIMESTAMP,
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> list[Path]:
    source_findings, deduped_findings, source_map = build(as_of_date)
    validate_findings(source_findings, as_of_date)
    validate_findings(deduped_findings, as_of_date)
    output_dir.mkdir(parents=True, exist_ok=True)
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)

    schema_path = SCHEMA_DIR / "canonical-finding.schema.json"
    write_json(schema_path, FindingsDocument.model_json_schema())

    normalised = FindingsDocument(findings=source_findings).model_dump(mode="json")
    deduped = FindingsDocument(findings=deduped_findings).model_dump(mode="json")
    write_json(output_dir / "normalised-findings.json", normalised)
    write_json(output_dir / "deduplicated-findings.json", deduped)
    write_json(output_dir / "finding-source-map.json", source_map)
    write_json(
        output_dir / "asset-inventory.json", {"schema_version": "1.0", "assets": asset_inventory()}
    )

    write_csv(
        output_dir / "normalised-findings.csv", finding_rows(source_findings), FINDING_COLUMNS
    )
    write_csv(
        output_dir / "unowned-findings.csv",
        [row for row in finding_rows(deduped_findings) if row.get("technical_owner") == "unowned"],
        FINDING_COLUMNS,
    )
    write_csv(
        output_dir / "suppressed-findings.csv",
        [row for row in finding_rows(source_findings) if row.get("suppression_id")],
        FINDING_COLUMNS,
    )
    write_csv(
        output_dir / "expired-suppressions.csv",
        _expired_suppressions(source_findings, as_of_date),
        FINDING_COLUMNS,
    )

    summaries = _summaries(source_findings, deduped_findings, source_map)
    for name, payload in summaries.items():
        write_json(output_dir / name, payload)

    output_files = sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file() and path.name != "evidence-manifest.json"
    )
    input_files = _input_files()
    manifest = {
        "schema_version": "1.0",
        "project_version": __version__,
        "controlled_timestamp": timestamp,
        "as_of_date": as_of_date,
        "deployment_status": "not deployed",
        "input_files": {
            relative(path): {"path": relative(path), "sha256": sha256_file(path)}
            for path in input_files
            if path.exists()
        },
        "output_files": {
            path.name: {"path": _path_ref(path), "sha256": sha256_file(path)}
            for path in output_files
        },
        "adapter_versions": {name: "1.0" for name in [*source_tool_names(), "suppressions"]},
        "policy_config_versions": {relative(path): "1.0" for path in all_config_files()},
        "normalisation_count": len(source_findings),
        "deduplication_count": len(source_findings) - len(deduped_findings),
    }
    write_json(output_dir / "evidence-manifest.json", manifest)
    return [*output_files, output_dir / "evidence-manifest.json", schema_path]


def verify(output_dir: Path = OUTPUT_DIR) -> None:
    verify_manifest(output_dir)
    manifest = output_dir / "evidence-manifest.json"
    with tempfile.TemporaryDirectory() as tmp:
        payload = __import__("json").loads(manifest.read_text(encoding="utf-8"))
        generate(
            Path(tmp), timestamp=payload["controlled_timestamp"], as_of_date=payload["as_of_date"]
        )
        for name, details in payload["output_files"].items():
            if sha256_file(Path(tmp) / name) != details["sha256"]:
                raise ValueError(f"non-deterministic findings evidence: {name}")


def _input_files() -> list[Path]:
    return [
        *all_config_files(),
        ROOT / "docs" / "threat-model" / "residual-risk-register.yaml",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "gitleaks.json",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "semgrep.json",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "bandit.json",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "pip-audit.json",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "checkov.json",
        ROOT / "outputs" / "security" / "appsec" / "raw" / "trivy.json",
        ROOT / "outputs" / "security" / "dynamic" / "raw" / "zap-report.json",
        ROOT / "outputs" / "security" / "dynamic" / "raw" / "pytest-dynamic.json",
        ROOT / "outputs" / "security" / "dynamic" / "schemathesis-summary.json",
        ROOT / "security" / "config" / "suppressions.yaml",
        ROOT / "security" / "dynamic" / "suppressions.yaml",
    ]


def _path_ref(path: Path) -> str:
    try:
        return relative(path)
    except ValueError:
        return path.name


def _summaries(
    source_findings: list[Finding],
    deduped_findings: list[Finding],
    source_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    rows = finding_rows(source_findings)
    dedup_rows = finding_rows(deduped_findings)
    summary = {
        "schema_version": "1.0",
        "total_source_findings": len(source_findings),
        "total_canonical_findings": len(deduped_findings),
        "deduplicated_count": len(source_findings) - len(deduped_findings),
        "findings_by_source_tool": _count(rows, "source_tool", include=source_tool_names()),
        "findings_by_type": _count(rows, "finding_type"),
        "findings_by_severity": _count(dedup_rows, "normalised_severity"),
        "findings_by_priority": _count(dedup_rows, "priority"),
        "findings_by_owner": _count(dedup_rows, "technical_owner"),
        "findings_by_asset": _count(dedup_rows, "asset_id"),
        "findings_by_environment": _count(dedup_rows, "environment"),
        "suppressed_findings": sum(1 for row in rows if row.get("suppression_id")),
        "expired_suppressions": len(_expired_suppressions(source_findings, DEFAULT_AS_OF_DATE)),
        "unowned_findings": sum(1 for row in dedup_rows if row.get("technical_owner") == "unowned"),
        "findings_with_fixes_available": sum(1 for row in rows if row.get("fixed_version")),
        "findings_without_fixes": sum(1 for row in rows if not row.get("fixed_version")),
    }
    return {
        "findings-summary.json": summary,
        "ownership-summary.json": {
            "owners": summary["findings_by_owner"],
            "unowned_findings": summary["unowned_findings"],
        },
        "risk-summary.json": {
            "formula": (
                "30% severity + 20% exploitability + 15% internet exposure + "
                "15% asset criticality + 10% data sensitivity + 5% privilege "
                "required + 5% age/recurrence"
            ),
            "by_priority": summary["findings_by_priority"],
            "highest_risk": sorted(
                [
                    {
                        "finding_id": row["finding_id"],
                        "risk_score": row["risk_score"],
                        "priority": row["priority"],
                        "title": row["title"],
                    }
                    for row in dedup_rows
                ],
                key=lambda item: (-float(item["risk_score"] or 0), item["finding_id"]),
            )[:10],
        },
        "sla-summary.json": {
            "portfolio_notice": (
                "Demonstration values for this repository; not Genomics England policy."
            ),
            "by_due_date": _count(dedup_rows, "due_date"),
            "overdue_or_expired_suppressions": _expired_suppressions(
                source_findings, DEFAULT_AS_OF_DATE
            ),
        },
        "deduplication-summary.json": {
            "deduplicated_count": summary["deduplicated_count"],
            "groups": list(source_map.values()),
        },
    }


def _count(
    rows: list[dict[str, Any]], key: str, include: list[str] | None = None
) -> dict[str, int]:
    counter = Counter(str(row.get(key) or "unknown") for row in rows)
    if include:
        for value in include:
            counter.setdefault(value, 0)
    return dict(sorted(counter.items()))


def _expired_suppressions(findings: list[Finding], as_of_date: str) -> list[dict[str, Any]]:
    return [
        finding.model_dump(mode="json")
        for finding in findings
        if finding.suppression_expiry
        and finding.suppression_status == "active"
        and finding.suppression_expiry < as_of_date
    ]


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
