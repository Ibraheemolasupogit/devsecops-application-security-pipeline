from __future__ import annotations

from pathlib import Path

from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.portfolio.config import OUTPUT_DIR
from genomic_research_access_api.security.portfolio.generator import (
    build_capability_matrix,
    build_index,
    build_metrics,
    build_milestones,
    evaluate_readiness,
    generate,
    markdown_links,
    stable_bundle_id,
)
from genomic_research_access_api.security.portfolio.reporting import generate_reports
from genomic_research_access_api.security.portfolio.validator import validate_manifest, verify
from genomic_research_access_api.security.threat_model.io import ROOT


def test_policy_validation_and_capability_matrix() -> None:
    policy = read_json(Path("config/portfolio/capability-mapping.yaml"))
    matrix = build_capability_matrix(policy)
    assert matrix["capability_count"] == 25
    assert matrix["implemented_count"] == 25
    assert {item["id"] for item in matrix["capabilities"]} >= {"CAP-01", "CAP-25"}


def test_milestone_inventory_and_missing_milestone_detection() -> None:
    inventory = build_milestones()
    assert inventory["required_count"] == 14
    assert inventory["completed_count"] == 14
    altered = dict(inventory)
    altered["completed_count"] = 13
    readiness = evaluate_readiness(
        build_metrics(),
        altered,
        {"valid": True, "items": [], "missing_paths": []},
        {"valid": True, "items": [], "missing_paths": []},
        read_json(Path("config/portfolio/readiness-criteria.yaml")),
    )
    assert readiness["status"] == "not_ready"


def test_evidence_and_report_indexes_validate_paths() -> None:
    generate()
    generate_reports()
    generate()
    evidence = read_json(OUTPUT_DIR / "evidence-index.json")
    reports = read_json(OUTPUT_DIR / "report-index.json")
    assert evidence["valid"] is True
    assert reports["valid"] is True
    assert all((ROOT / item["path"]).exists() for item in evidence["items"])
    assert all((ROOT / item["path"]).exists() for item in reports["items"])


def test_stable_bundle_id_and_ready_with_limitations() -> None:
    metrics = build_metrics()
    milestones = build_milestones()
    matrix = build_capability_matrix(read_json(Path("config/portfolio/capability-mapping.yaml")))
    evidence = build_index(["outputs/security/evidence/evidence-manifest.json"], "evidence")
    assert stable_bundle_id(metrics, milestones, matrix, evidence) == stable_bundle_id(
        metrics, milestones, matrix, evidence
    )
    readiness = evaluate_readiness(
        metrics,
        milestones,
        evidence,
        build_index(["reports/security/security-evidence-report.md"], "report"),
        read_json(Path("config/portfolio/readiness-criteria.yaml")),
    )
    assert readiness["status"] == "ready_with_limitations"
    assert readiness["limitations"]


def test_missing_evidence_and_broken_link_detection(tmp_path: Path) -> None:
    missing = build_index(["outputs/security/not-present.json"], "evidence")
    assert missing["valid"] is False
    doc = tmp_path / "doc.md"
    doc.write_text("[missing](missing.md)\n", encoding="utf-8")
    assert markdown_links([doc])


def test_metric_reconciliation_with_current_repository() -> None:
    metrics = build_metrics()
    assert metrics["canonical_findings"] == 44
    assert metrics["source_findings"] == 46
    assert metrics["integration_export_records"] == 44
    assert metrics["integration_lineage_edges"] == 178
    assert metrics["overdue_findings"] == 0
    assert metrics["unowned_findings"] == 0


def test_git_metadata_is_safe_and_manifest_verifies() -> None:
    generate()
    manifest = read_json(OUTPUT_DIR / "portfolio-manifest.json")
    assert "@" not in manifest["git"]["commit"]
    assert "/" not in manifest["git"]["commit"]
    assert validate_manifest(manifest) == []


def test_manifest_tamper_rejection() -> None:
    generate()
    manifest = read_json(OUTPUT_DIR / "portfolio-manifest.json")
    manifest["output_files"]["portfolio-summary.json"]["sha256"] = "0" * 64
    assert validate_manifest(manifest) == ["checksum mismatch: portfolio-summary.json"]


def test_report_generation_and_current_repository_generation() -> None:
    generate()
    reports = generate_reports()
    summary = generate()
    result = verify()
    assert summary["readiness_status"] == "ready_with_limitations"
    assert result["valid"] is True
    assert {path.name for path in reports} >= {
        "final-project-report.md",
        "final-portfolio-readiness-report.md",
    }
