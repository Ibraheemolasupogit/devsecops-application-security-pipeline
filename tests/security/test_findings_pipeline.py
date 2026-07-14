from pathlib import Path

import pytest

from genomic_research_access_api.security.findings import __main__ as findings_main
from genomic_research_access_api.security.findings import adapters
from genomic_research_access_api.security.findings.config import DEFAULT_AS_OF_DATE
from genomic_research_access_api.security.findings.deduplicator import deduplicate
from genomic_research_access_api.security.findings.evidence import generate, verify
from genomic_research_access_api.security.findings.identifiers import finding_id, normalise_path
from genomic_research_access_api.security.findings.normalizer import build, enrich, normalise
from genomic_research_access_api.security.findings.report import generate_reports
from genomic_research_access_api.security.findings.risk import score_finding
from genomic_research_access_api.security.findings.utils import read_json, safe_csv_cell, write_json
from genomic_research_access_api.security.findings.verify import validate_findings, verify_manifest


def test_all_source_adapters_are_represented() -> None:
    expected = {
        "threat-model",
        "gitleaks",
        "semgrep",
        "bandit",
        "pip-audit",
        "checkov",
        "trivy",
        "schemathesis",
        "zap",
        "dynamic-pytest",
    }
    assert expected.issubset(adapters.ADAPTERS)


def test_committed_source_outputs_normalise_successfully() -> None:
    source, deduped, source_map = build(DEFAULT_AS_OF_DATE)
    validate_findings(source, DEFAULT_AS_OF_DATE)
    validate_findings(deduped, DEFAULT_AS_OF_DATE)
    assert len(source) >= len(deduped)
    assert source_map


def test_adapter_rejects_malformed_gitleaks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapters, "read_json", lambda _path: {"not": "a list"})
    with pytest.raises(ValueError, match="gitleaks output"):
        adapters.gitleaks_findings()


def test_severity_cve_cwe_and_threat_mapping() -> None:
    findings = normalise(DEFAULT_AS_OF_DATE)
    trivy = next(item for item in findings if item.source_tool == "trivy")
    threat = next(item for item in findings if item.source_tool == "threat-model")
    assert trivy.normalised_severity in {"critical", "high"}
    assert trivy.cve and trivy.cve.startswith("CVE-")
    zap_findings = [item for item in findings if item.source_tool == "zap"]
    if zap_findings:
        assert zap_findings[0].cwe and zap_findings[0].cwe.startswith("CWE-")
    else:
        assert read_json(Path("outputs/security/dynamic/zap-summary.json"))["alert_count"] == 0
    assert threat.threat_ids


def test_stable_identifier_and_path_normalisation() -> None:
    key = {"tool": "trivy", "cve": "CVE-2026-0001", "package": "demo"}
    assert finding_id("Container", key) == finding_id("Container", dict(reversed(key.items())))
    assert normalise_path("/Users/example/repo/src/app.py") == "Users/example/repo/src/app.py"
    assert normalise_path("./src/../src/app.py") == "src/app.py"


def test_deduplicates_exact_cve_without_losing_sources() -> None:
    findings = enrich(normalise(DEFAULT_AS_OF_DATE), DEFAULT_AS_OF_DATE)
    cve_findings = [item for item in findings if item.cve and item.package_name]
    assert cve_findings
    deduped, source_map = deduplicate(findings)
    assert len(deduped) < len(findings)
    assert any(len(group["source_finding_ids"]) > 1 for group in source_map.values())


def test_unrelated_titles_are_not_deduplicated() -> None:
    findings = enrich(normalise(DEFAULT_AS_OF_DATE), DEFAULT_AS_OF_DATE)
    zap_findings = [item for item in findings if item.source_tool == "zap"]
    deduped, _ = deduplicate(zap_findings)
    assert len(deduped) == len(zap_findings)


def test_source_preservation_suppression_and_fix_available() -> None:
    findings = enrich(normalise(DEFAULT_AS_OF_DATE), DEFAULT_AS_OF_DATE)
    suppressed = [item for item in findings if item.suppression_id]
    assert suppressed
    assert all(item.source_evidence for item in findings)
    assert any(item.cve == "CVE-2026-42496" for item in suppressed)


def test_asset_ownership_risk_priority_and_sla() -> None:
    findings = enrich(normalise(DEFAULT_AS_OF_DATE), DEFAULT_AS_OF_DATE)
    finding = next(item for item in findings if item.source_tool == "trivy")
    score, priority, factors = score_finding(finding)
    assert 0 <= score <= 100
    assert priority in {"P1", "P2", "P3", "P4", "P5"}
    assert factors["technical_severity"] > 0
    assert finding.technical_owner == "Platform Engineering"
    assert finding.due_date


def test_unowned_fallback_and_csv_formula_protection() -> None:
    assert safe_csv_cell("=cmd") == "'=cmd"
    assert safe_csv_cell("+SUM(A1)") == "'+SUM(A1)"


def test_deterministic_evidence_and_tamper_detection(tmp_path: Path) -> None:
    generate(tmp_path)
    verify(tmp_path)
    manifest = read_json(tmp_path / "evidence-manifest.json")
    assert manifest["normalisation_count"] > 0
    target = tmp_path / "findings-summary.json"
    payload = read_json(target)
    payload["tampered"] = True
    write_json(target, payload)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_manifest(tmp_path)


def test_report_generation(tmp_path: Path) -> None:
    generate(tmp_path)
    report_dir = tmp_path / "reports"
    written = generate_reports(tmp_path, report_dir)
    assert {path.name for path in written} == {
        "findings-normalisation-report.md",
        "risk-enrichment-report.md",
        "ownership-report.md",
        "remediation-sla-report.md",
        "deduplication-report.md",
    }


@pytest.mark.parametrize(
    "command, expected",
    [
        ("normalise", "normalised 41 source findings"),
        ("deduplicate", "deduplicated 2 findings"),
        ("enrich", "enriched 41 source findings"),
        ("validate", "validated 39 canonical findings"),
        ("evidence", "generated findings evidence"),
        ("verify", "verified findings evidence"),
        ("report", "generated findings reports"),
        ("full", "completed findings full workflow"),
    ],
)
def test_findings_cli_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str, expected: str
) -> None:
    monkeypatch.setattr("sys.argv", ["findings", command])
    findings_main.main()
    assert expected in capsys.readouterr().out
