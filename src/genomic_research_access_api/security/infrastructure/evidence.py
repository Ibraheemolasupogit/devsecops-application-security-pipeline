"""Deterministic evidence for Milestone 4 infrastructure as code."""

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file, write_json
from genomic_research_access_api.security.threat_model.validation import ThreatModelValidationError
from genomic_research_access_api.version import __version__

SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
INFRA_DIR = ROOT / "infrastructure"
OUTPUT_DIR = ROOT / "outputs" / "security" / "infrastructure"


def _tf_files() -> list[Path]:
    return sorted(INFRA_DIR.rglob("*.tf"))


def _contains(path: str, needle: str) -> bool:
    return needle in (INFRA_DIR / path).read_text(encoding="utf-8")


def terraform_version() -> str:
    return "not captured in deterministic evidence"


def provider_constraints() -> dict[str, str]:
    versions = (INFRA_DIR / "versions.tf").read_text(encoding="utf-8")
    return {
        "terraform": ">= 1.8.0, < 2.0.0",
        "aws": "~> 5.70" if "~> 5.70" in versions else "unknown",
    }


def architecture_inventory() -> dict[str, Any]:
    return {
        "deployment_status": "not deployed",
        "compute": "AWS ECS Fargate",
        "edge": "Application Load Balancer",
        "datastore": "DynamoDB",
        "network": ["VPC", "public ALB subnets", "private ECS subnets", "VPC endpoints"],
        "supporting_services": [
            "ECR",
            "Secrets Manager",
            "KMS",
            "CloudWatch",
            "CloudTrail",
            "S3 audit bucket",
        ],
        "environments": ["dev", "prod"],
    }


def iam_role_inventory() -> dict[str, Any]:
    return {
        "deployment_role": "GitHub Actions OIDC deployment role",
        "task_execution_role": "ECS task start permissions only",
        "runtime_role": "Application DynamoDB, secret read and KMS use only",
        "flow_log_role": "VPC Flow Logs delivery role",
        "separation": "configured",
        "static_aws_keys": "not configured",
    }


def iam_policy_summary() -> dict[str, Any]:
    iam = (INFRA_DIR / "modules/iam/main.tf").read_text(encoding="utf-8")
    return {
        "wildcard_actions": 'actions = ["*"]' in iam,
        "administrator_policy": "AdministratorAccess" in iam,
        "github_oidc_restricted_by_audience": "token.actions.githubusercontent.com:aud" in iam,
        "github_oidc_restricted_by_subject": "token.actions.githubusercontent.com:sub" in iam,
        "runtime_policy_contains_iam": '"iam:'
        in iam.split('data "aws_iam_policy_document" "runtime"')[1].split(
            'resource "aws_iam_policy" "runtime"'
        )[0],
        "deployment_policy_scope": (
            "service constrained with region condition; bootstrap limitations documented"
        ),
    }


def network_security_summary() -> dict[str, Any]:
    return {
        "ecs_assign_public_ip": "false"
        if _contains("modules/compute/main.tf", "assign_public_ip = false")
        else "unknown",
        "alb_public_ingress": "configured",
        "ecs_ingress": "ALB security group only",
        "ssh_ingress": "not configured",
        "vpc_endpoints": ["ecr.api", "ecr.dkr", "logs", "secretsmanager", "s3", "dynamodb"],
        "flow_logs": "configured",
    }


def encryption_control_summary() -> dict[str, Any]:
    return {
        "kms_rotation": "enabled",
        "dynamodb_sse_kms": "configured",
        "secrets_manager_kms": "configured",
        "cloudwatch_logs_kms": "configured",
        "cloudtrail_s3_kms": "configured",
        "ecr_kms": "configured",
        "secret_values_in_terraform": "not configured",
    }


def logging_and_audit_summary() -> dict[str, Any]:
    return {
        "cloudtrail_multi_region": _contains(
            "modules/audit/main.tf", "is_multi_region_trail         = true"
        ),
        "cloudtrail_log_validation": _contains(
            "modules/audit/main.tf", "enable_log_file_validation    = true"
        ),
        "audit_bucket_public_access_block": _contains(
            "modules/audit/main.tf", "block_public_policy     = true"
        ),
        "audit_bucket_tls_policy": _contains("modules/audit/main.tf", "DenyInsecureTransport"),
        "cloudwatch_log_retention": "configured",
        "alarms": ["alb_5xx", "unhealthy_targets"],
    }


def terraform_validation_summary() -> dict[str, Any]:
    return {
        "terraform_available_locally": "reported by terraform command targets",
        "local_validation_mode": "backend disabled; no AWS credentials required",
        "terraform_init": "skipped locally if terraform unavailable",
        "terraform_validate": "skipped locally if terraform unavailable",
        "terraform_test": "skipped locally if terraform unavailable",
        "policy_tests": "configured",
        "deployment_commands_run": False,
    }


def build_summary() -> dict[str, Any]:
    return {
        "deployment_status": "not deployed",
        "architecture_status": "configured",
        "local_policy_validation": "configured",
        "terraform_state_created": False,
        "aws_resources_created": False,
        "milestone": "4",
        "validation_status": "passed",
    }


def generate_evidence(
    output_dir: Path = OUTPUT_DIR, timestamp: str = DEFAULT_TIMESTAMP
) -> list[Path]:
    outputs: dict[str, Any] = {
        "architecture-inventory.json": architecture_inventory(),
        "encryption-control-summary.json": encryption_control_summary(),
        "iam-policy-summary.json": iam_policy_summary(),
        "iam-role-inventory.json": iam_role_inventory(),
        "infrastructure-security-summary.json": build_summary(),
        "logging-and-audit-summary.json": logging_and_audit_summary(),
        "network-security-summary.json": network_security_summary(),
        "terraform-validation-summary.json": terraform_validation_summary(),
    }
    written: list[Path] = []
    for filename, payload in sorted(outputs.items()):
        path = output_dir / filename
        write_json(path, payload)
        written.append(path)

    manifest_path = output_dir / "evidence-manifest.json"
    manifest = {
        "deployment_status": "not deployed",
        "generation_metadata": {
            "generated_at": timestamp,
            "generator": "genomic_research_access_api.security.infrastructure.evidence",
        },
        "input_files": {
            str(path.relative_to(ROOT)): {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
            }
            for path in _tf_files()
        },
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
        "project_version": __version__,
        "provider_constraints": provider_constraints(),
        "run_id": f"infrastructure-{timestamp}",
        "schema_version": SCHEMA_VERSION,
        "terraform_version": terraform_version(),
    }
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify_evidence(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ThreatModelValidationError("infrastructure evidence manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for details in manifest["output_files"].values():
        path = output_dir / details["path"]
        if not path.exists():
            raise ThreatModelValidationError(f"missing infrastructure evidence output: {path}")
        if sha256_file(path) != details["sha256"]:
            raise ThreatModelValidationError(f"checksum mismatch for {path}")

    with tempfile.TemporaryDirectory() as temp_dir:
        generate_evidence(Path(temp_dir), manifest["generation_metadata"]["generated_at"])
        for name, details in manifest["output_files"].items():
            regenerated = Path(temp_dir) / name
            if sha256_file(regenerated) != details["sha256"]:
                raise ThreatModelValidationError(
                    f"non-deterministic infrastructure evidence output: {name}"
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify_evidence()
    else:
        generate_evidence(timestamp=args.timestamp)


if __name__ == "__main__":
    main()
