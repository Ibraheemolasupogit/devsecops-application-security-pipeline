"""Markdown AppSec reports generated from evidence summaries."""

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.appsec.config import (
    APPSEC_OUTPUT_DIR,
    REPORT_DIR,
    load_json_yaml,
)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def _summary(name: str) -> dict[str, Any]:
    payload = load_json_yaml(APPSEC_OUTPUT_DIR / name)
    if not isinstance(payload, dict):
        raise ValueError(f"expected object summary for {name}")
    return payload


def _report(title: str, summary: dict[str, Any]) -> str:
    return (
        f"# {title}\n\n"
        + _table(
            ["Field", "Value"],
            [
                ["Tool", str(summary["tool"])],
                ["Execution status", str(summary["execution_status"])],
                ["Finding count", str(summary["finding_count"])],
                ["Blocking count", str(summary["blocking_count"])],
                ["Suppressed count", str(summary["suppressed_count"])],
                ["Policy decision", str(summary["policy_decision"])],
                ["Limitations", str(summary["limitations"] or "None")],
            ],
        )
        + "\n"
    )


def generate_reports(report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    reports = {
        "secret-scanning-report.md": _report(
            "Secret Scanning Report", _summary("secret-scan-summary.json")
        ),
        "sast-report.md": _report("SAST Report", _summary("sast-summary.json")),
        "dependency-security-report.md": _report(
            "Dependency Security Report", _summary("dependency-scan-summary.json")
        ),
        "iac-security-report.md": _report("IaC Security Report", _summary("iac-scan-summary.json")),
        "container-security-report.md": _report(
            "Container Security Report", _summary("container-scan-summary.json")
        ),
        "appsec-pipeline-report.md": "# AppSec Pipeline Report\n\n"
        + _table(
            ["Field", "Value"],
            [
                ["Scanner count", str(_summary("appsec-pipeline-summary.json")["scanner_count"])],
                ["Blocking count", str(_summary("appsec-pipeline-summary.json")["blocking_count"])],
                [
                    "Not run",
                    ", ".join(_summary("appsec-pipeline-summary.json")["not_run"]) or "None",
                ],
                ["Policy decision", _summary("appsec-pipeline-summary.json")["policy_decision"]],
            ],
        )
        + "\n",
        "sbom-report.md": (
            "# SBOM Report\n\nCycloneDX JSON SBOM: `outputs/security/appsec/sbom.cdx.json`.\n"
        ),
    }
    written = []
    for filename, content in sorted(reports.items()):
        path = report_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def main() -> None:
    generate_reports()


if __name__ == "__main__":
    main()
