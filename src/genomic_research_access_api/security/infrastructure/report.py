"""Markdown reports from Milestone 4 infrastructure evidence."""

from pathlib import Path

from genomic_research_access_api.security.infrastructure.evidence import (
    architecture_inventory,
    build_summary,
    encryption_control_summary,
    iam_policy_summary,
    iam_role_inventory,
    logging_and_audit_summary,
    network_security_summary,
    provider_constraints,
    terraform_validation_summary,
)
from genomic_research_access_api.security.threat_model.io import REPORT_DIR


def _table(headers: list[str], rows: list[list[str]]) -> str:
    header = "| " + " | ".join(headers) + " |"
    divider = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header, divider, *body])


def generate_reports(report_dir: Path = REPORT_DIR) -> list[Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    architecture = architecture_inventory()
    iam_roles = iam_role_inventory()
    iam_policy = iam_policy_summary()
    network = network_security_summary()
    encryption = encryption_control_summary()
    logging = logging_and_audit_summary()
    validation = terraform_validation_summary()
    summary = build_summary()

    reports = {
        "aws-architecture-report.md": "# AWS Architecture Report\n\n"
        + _table(
            ["Area", "Configured Value"],
            [
                ["Deployment status", architecture["deployment_status"]],
                ["Compute", architecture["compute"]],
                ["Edge", architecture["edge"]],
                ["Datastore", architecture["datastore"]],
                ["Network", ", ".join(architecture["network"])],
                ["Supporting services", ", ".join(architecture["supporting_services"])],
            ],
        )
        + "\n",
        "terraform-security-report.md": "# Terraform Security Report\n\n"
        + _table(
            ["Control", "Value"],
            [
                ["Terraform constraint", provider_constraints()["terraform"]],
                ["AWS provider constraint", provider_constraints()["aws"]],
                ["Deployment status", summary["deployment_status"]],
                ["State created", str(summary["terraform_state_created"])],
                ["Terraform validation mode", validation["local_validation_mode"]],
                ["Network ECS public IP", network["ecs_assign_public_ip"]],
                ["KMS rotation", encryption["kms_rotation"]],
            ],
        )
        + "\n",
        "iam-security-report.md": "# IAM Security Report\n\n"
        + _table(
            ["Control", "Value"],
            [
                ["Deployment role", iam_roles["deployment_role"]],
                ["Task execution role", iam_roles["task_execution_role"]],
                ["Runtime role", iam_roles["runtime_role"]],
                ["Static AWS keys", iam_roles["static_aws_keys"]],
                ["Wildcard actions", str(iam_policy["wildcard_actions"])],
                [
                    "GitHub OIDC audience restricted",
                    str(iam_policy["github_oidc_restricted_by_audience"]),
                ],
                [
                    "GitHub OIDC subject restricted",
                    str(iam_policy["github_oidc_restricted_by_subject"]),
                ],
            ],
        )
        + "\n",
        "infrastructure-validation-report.md": "# Infrastructure Validation Report\n\n"
        + _table(
            ["Control", "Value"],
            [
                ["Policy tests", validation["policy_tests"]],
                ["AWS resources created", str(summary["aws_resources_created"])],
                ["Deployment commands run", str(validation["deployment_commands_run"])],
                ["CloudTrail multi-region", str(logging["cloudtrail_multi_region"])],
                ["CloudTrail log validation", str(logging["cloudtrail_log_validation"])],
                ["Audit bucket TLS policy", str(logging["audit_bucket_tls_policy"])],
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


def main() -> None:
    generate_reports()


if __name__ == "__main__":
    main()
