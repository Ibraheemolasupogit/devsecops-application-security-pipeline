"""Markdown report generation for Milestone 3 API security evidence."""

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.api_security.evidence import (
    audit_control_summary,
    authentication_control_summary,
    authorisation_matrix,
    build_summary,
    endpoint_security_inventory,
    negative_test_summary,
)
from genomic_research_access_api.security.threat_model.io import REPORT_DIR


def _table(headers: list[str], rows: list[list[str]]) -> str:
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def _as_csv(values: list[str]) -> str:
    return ", ".join(values) if values else "None"


def generate_reports(report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary()
    authn = authentication_control_summary()
    matrix = authorisation_matrix()
    endpoints = endpoint_security_inventory()
    negative = negative_test_summary()
    audit = audit_control_summary()

    reports: dict[str, str] = {
        "api-security-report.md": "# API Security Report\n\n"
        + _table(
            ["Metric", "Value"],
            [
                ["Authentication", summary["authentication_status"]],
                ["Authorisation", summary["authorisation_status"]],
                ["Protected API routes", str(summary["protected_api_route_count"])],
                ["Roles", str(summary["role_count"])],
                ["Negative security tests", str(summary["negative_security_test_count"])],
            ],
        )
        + "\n\n"
        + _endpoint_table(endpoints)
        + "\n",
        "authentication-report.md": "# Authentication Report\n\n"
        + _table(
            ["Control", "Value"],
            [
                ["Accepted algorithms", _as_csv(authn["algorithm_policy"]["accepted_algorithms"])],
                [
                    "None algorithm allowed",
                    str(authn["algorithm_policy"]["none_algorithm_allowed"]),
                ],
                [
                    "Arbitrary algorithms allowed",
                    str(authn["algorithm_policy"]["arbitrary_algorithms_allowed"]),
                ],
                ["Claim validation", _as_csv(authn["claim_validation"])],
                [
                    "Accepted identity source",
                    authn["identity_source_policy"]["accepted_identity_source"],
                ],
            ],
        )
        + "\n",
        "authorisation-report.md": "# Authorisation Report\n\n"
        + _table(
            ["Role", "Permissions"],
            [[role, _as_csv(permissions)] for role, permissions in matrix.items()],
        )
        + "\n\n"
        + _endpoint_table(endpoints)
        + "\n",
        "negative-security-testing-report.md": "# Negative Security Testing Report\n\n"
        + _table(
            ["Category", "Value"],
            [
                ["Test file", negative["test_file"]],
                ["Covered cases", _as_csv(negative["covered_cases"])],
                [
                    "Expected statuses",
                    _status_summary(negative["expected_statuses"]),
                ],
                ["Security audit events", _as_csv(audit["security_event_types"])],
            ],
        )
        + "\n",
    }
    written = []
    for filename, content in sorted(reports.items()):
        path = report_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written


def _endpoint_table(endpoints: list[dict[str, Any]]) -> str:
    return _table(
        ["Method", "Path", "Permissions", "Object Rule"],
        [
            [
                endpoint["method"],
                endpoint["path"],
                _as_csv(endpoint["required_permissions"]),
                endpoint["object_authorisation"],
            ]
            for endpoint in endpoints
        ],
    )


def _status_summary(statuses: dict[str, int]) -> str:
    return ", ".join(f"{name}: {status}" for name, status in sorted(statuses.items()))


def main() -> None:
    generate_reports()


if __name__ == "__main__":
    main()
