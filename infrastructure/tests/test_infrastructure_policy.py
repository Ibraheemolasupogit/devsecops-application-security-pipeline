"""Local policy tests for Milestone 4 Terraform configuration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INFRA = ROOT / "infrastructure"


def read(path: str) -> str:
    return (INFRA / path).read_text(encoding="utf-8")


def all_tf() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in INFRA.rglob("*.tf"))


def test_ecs_tasks_have_no_public_ip_and_narrow_ingress() -> None:
    compute = read("modules/compute/main.tf")
    network = read("modules/networking/main.tf")
    assert "assign_public_ip = false" in compute
    assert "security_groups  = [var.ecs_tasks_security_group_id]" in compute
    assert 'description     = "Application port from ALB only"' in network
    assert "security_groups = [aws_security_group.alb.id]" in network
    assert "from_port   = 22" not in all_tf()


def test_runtime_and_execution_roles_are_separate_and_runtime_lacks_iam_admin() -> None:
    iam = read("modules/iam/main.tf")
    assert 'resource "aws_iam_role" "task_execution"' in iam
    assert 'resource "aws_iam_role" "runtime"' in iam
    runtime_policy = iam.split('data "aws_iam_policy_document" "runtime"')[1].split(
        'resource "aws_iam_policy" "runtime"'
    )[0]
    assert "iam:" not in runtime_policy
    assert "s3:" not in runtime_policy
    assert "ec2:" not in runtime_policy


def test_no_wildcard_administrative_policy_or_static_credentials() -> None:
    source = all_tf()
    assert 'actions = ["*"]' not in source
    assert "AdministratorAccess" not in source
    assert "PowerUserAccess" not in source
    assert "aws_access_key_id" not in source
    assert "aws_secret_access_key" not in source


def test_dynamodb_encryption_pitr_and_prod_deletion_protection() -> None:
    datastore = read("modules/datastore/main.tf")
    prod = read("environments/prod/main.tf")
    assert "server_side_encryption" in datastore
    assert "kms_key_arn = var.kms_key_arn" in datastore
    assert "point_in_time_recovery" in datastore
    assert "Production DynamoDB tables must enable point-in-time recovery." in datastore
    assert "Production DynamoDB tables must enable deletion protection." in datastore
    assert "deletion_protection  = true" in prod


def test_ecr_controls_are_enabled() -> None:
    ecr = read("modules/ecr/main.tf")
    assert 'image_tag_mutability = "IMMUTABLE"' in ecr
    assert "scan_on_push = true" in ecr
    assert 'encryption_type = "KMS"' in ecr
    assert 'resource "aws_ecr_repository_policy" "this"' in ecr


def test_cloudtrail_and_audit_bucket_are_secure() -> None:
    audit = read("modules/audit/main.tf")
    assert "is_multi_region_trail         = true" in audit
    assert "enable_log_file_validation    = true" in audit
    assert "block_public_policy     = true" in audit
    assert "restrict_public_buckets = true" in audit
    assert "DenyInsecureTransport" in audit
    assert 'sse_algorithm     = "aws:kms"' in audit


def test_logs_and_kms_rotation_are_configured() -> None:
    observability = read("modules/observability/main.tf")
    kms = read("modules/kms/main.tf")
    assert "retention_in_days = var.log_retention_days" in observability
    assert "kms_key_id        = var.kms_key_arn" in observability
    assert "enable_key_rotation     = true" in kms


def test_container_hardening_and_image_controls() -> None:
    compute = read("modules/compute/main.tf")
    prod_vars = read("environments/prod/variables.tf")
    assert 'user                   = "10001"' in compute
    assert "readonlyRootFilesystem = true" in compute
    assert "privileged             = false" in compute
    assert 'drop = ["ALL"]' in compute
    assert '!endswith(var.container_image, ":latest")' in compute
    assert "@sha256" in prod_vars


def test_production_https_requirement_and_oidc_restriction() -> None:
    compute = read("modules/compute/main.tf")
    prod_vars = read("environments/prod/variables.tf")
    iam = read("modules/iam/main.tf")
    assert "Production must not use HTTP-only listener configuration." in compute
    assert "Production requires a real ACM certificate ARN." in prod_vars
    assert "token.actions.githubusercontent.com:aud" in iam
    assert "token.actions.githubusercontent.com:sub" in iam
    assert "repo:${var.github_repository}:${var.github_ref}" in iam
    assert 'identifiers = ["*"]' not in iam


def test_secrets_have_no_secret_payloads() -> None:
    secrets = read("modules/secrets/main.tf")
    assert 'resource "aws_secretsmanager_secret" "application_config"' in secrets
    assert "aws_secretsmanager_secret_version" not in all_tf()
    assert "SecretValueManagedOutsideTerraform" in secrets
