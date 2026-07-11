"""Markdown report generation from machine-readable threat-model data."""

from pathlib import Path

from genomic_research_access_api.security.threat_model.evidence import build_summary
from genomic_research_access_api.security.threat_model.io import REPORT_DIR, normalise_model
from genomic_research_access_api.security.threat_model.validation import validate_threat_model


def _table(headers: list[str], rows: list[list[str]]) -> str:
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def generate_reports(report_dir: Path = REPORT_DIR) -> list[Path]:
    model = validate_threat_model()
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(model)

    reports = {
        "threat-model-report.md": "# Threat Model Report\n\n"
        + _table(
            ["Metric", "Value"],
            [
                ["Total threats", str(summary["total_threats"])],
                ["Validation status", summary["validation_status"]],
                ["Orphaned threats", ", ".join(summary["orphaned_threats"]) or "None"],
                ["Orphaned requirements", ", ".join(summary["orphaned_requirements"]) or "None"],
            ],
        )
        + "\n\n"
        + _table(
            ["Threat", "STRIDE", "Risk"],
            [
                [threat.threat_id, threat.stride_category, threat.inherent_risk]
                for threat in model.threats
            ],
        )
        + "\n",
        "security-requirements-report.md": "# Security Requirements Report\n\n"
        + _table(
            ["Requirement", "Category", "Status", "Planned Milestone"],
            [
                [
                    requirement.requirement_id,
                    requirement.category,
                    requirement.implementation_status,
                    requirement.planned_milestone,
                ]
                for requirement in model.requirements
            ],
        )
        + "\n",
        "control-traceability-report.md": "# Control Traceability Report\n\n"
        + _table(
            ["Threat", "Requirements", "Residual Risk"],
            [
                [
                    link.threat_id,
                    ", ".join(link.requirement_ids),
                    link.residual_risk_id,
                ]
                for link in model.traceability
            ],
        )
        + "\n",
        "residual-risk-report.md": "# Residual Risk Report\n\n"
        + _table(
            ["Risk", "Rating", "Treatment", "Threats"],
            [
                [
                    risk.risk_id,
                    risk.residual_rating,
                    risk.treatment,
                    ", ".join(risk.related_threat_ids),
                ]
                for risk in model.residual_risks
            ],
        )
        + "\n",
    }
    written = []
    for filename, content in sorted(reports.items()):
        path = report_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)

    # Keep mypy honest that model data remains serialisable for report consumers.
    normalise_model(model.requirements)
    return written


def main() -> None:
    generate_reports()


if __name__ == "__main__":
    main()
