"""Offline structural controls for GitHub federation and private runners."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infrastructure" / "terraform"


def read(relative: str) -> str:
    return (TF / relative).read_text(encoding="utf-8")


def test_oidc_provider_and_trust_are_exact_repository_and_audience() -> None:
    provider = read("modules/github-oidc/main.tf")
    role = read("modules/github-actions-role/main.tf")
    variables = read("modules/github-actions-role/variables.tf")
    assert 'url            = "https://token.actions.githubusercontent.com"' in provider
    assert 'client_id_list = ["sts.amazonaws.com"]' in provider
    assert "token.actions.githubusercontent.com:aud" in role
    assert "token.actions.githubusercontent.com:sub" in role
    assert "values   = [var.subject]" in role
    assert '!strcontains(var.subject, "*")' in variables
    assert "repo:Ibraheemolasupogit/devsecops-application-security-pipeline" not in role
    assert (
        "repo:${var.github_owner}/${var.github_repository}:environment:${local.github_environment}"
        in read("modules/platform/main.tf")
    )


def test_qa_production_and_publisher_roles_have_distinct_contracts() -> None:
    platform = read("modules/platform/main.tf")
    artifacts = read("artifacts/main.tf")
    assert 'var.environment == "nonprod" ? "qa" : "production"' in platform
    assert 'role_kind         = "deployer"' in platform
    assert 'role_kind         = "publisher"' in artifacts
    publisher_subject = (
        'subject           = "repo:${var.github_owner}/${var.github_repository}:'
        'ref:refs/heads/main"'
    )
    assert publisher_subject in artifacts
    assert "eks:DescribeCluster" in read("modules/github-actions-role/main.tf")
    assert "resources = [var.cluster_arn]" in read("modules/github-actions-role/main.tf")
    assert "AdministratorAccess" not in platform + artifacts


def test_environment_states_create_or_reuse_account_local_oidc_provider() -> None:
    provider_input = 'variable "github_oidc_provider_arn" {'
    for environment in ("nonprod", "prod"):
        variables = read(f"environments/{environment}/variables.tf")
        block = variables.split(provider_input, 1)[1].split("\n}", 1)[0]
        assert "default     = null" in block
        assert "nullable    = true" in block
        assert "Create only once per AWS account" in block
    artifacts = read("artifacts/main.tf")
    assert 'source                = "../modules/github-oidc"' in artifacts
    assert "github_oidc_provider_arn" in artifacts
    platform = read("modules/platform/main.tf")
    assert 'source                = "../github-oidc"' in platform
    assert "existing_provider_arn = var.github_oidc_provider_arn" in platform


def test_publisher_permissions_are_one_repository_with_only_required_global_token() -> None:
    source = read("modules/github-actions-role/main.tf")
    assert 'actions   = ["ecr:GetAuthorizationToken"]' in source
    assert 'resources = ["*"]' in source
    assert 'variable = "aws:RequestedRegion"' in source
    assert "resources = [var.repository_arn]" in source
    assert '"ecr:PutImage"' in source
    assert '"ecr:*"' not in source
    variables = read("modules/github-actions-role/variables.tf")
    assert "Publisher role requires one exact ECR repository ARN" in variables
    assert "Deployer role requires one exact EKS cluster ARN" in variables


def test_codebuild_runner_is_one_job_private_and_separate_from_deploy_role() -> None:
    runner = read("modules/codebuild-runner/main.tf")
    platform = read("modules/platform/main.tf")
    assert 'pattern = "WORKFLOW_JOB_QUEUED"' in runner
    assert "private_subnet_ids    = module.networking.private_subnet_ids" in platform
    assert "api_client_security_group_ids = setunion(" in platform
    assert "security_group_ids = [aws_security_group.runner.id]" in runner
    assert 'resource "aws_security_group_rule" "ingress"' not in runner
    assert 'resource "aws_security_group" "runner"' in runner
    assert 'pattern = "WORKFLOW_JOB_QUEUED"' in runner
    assert 'Principal = { Service = "codebuild.amazonaws.com" }' in runner
    assert "sts:AssumeRole" not in runner.split('resource "aws_iam_role_policy" "service"')[1]
    assert "var.github_connection_arn == null ? 0 : 1" in platform


def test_codebuild_service_role_is_not_granted_ci_deployment_permissions() -> None:
    runner = read("modules/codebuild-runner/main.tf")
    assert '"logs:CreateLogStream", "logs:PutLogEvents"' in runner
    assert '"ec2:CreateNetworkInterface"' in runner
    assert 'variable = "ec2:Subnet"' in runner
    assert 'variable = "ec2:SecurityGroup"' in runner
    for forbidden in ("eks:DescribeCluster", "ecr:PutImage", "iam:PassRole", "AdministratorAccess"):
        assert forbidden not in runner


def test_codebuild_runner_logs_are_kms_encrypted_and_retained_for_one_year() -> None:
    runner = read("modules/codebuild-runner/main.tf")
    platform = read("modules/platform/main.tf")
    assert "retention_in_days = 365" in runner
    assert "kms_key_id        = var.kms_key_arn" in runner
    assert "kms_key_arn           = module.kms.key_arn" in platform
    assert "aws/codebuild/${local.runner_project_name}" in platform


def test_eks_deployer_access_entry_maps_to_group_without_managed_admin_policy() -> None:
    eks = read("modules/eks/main.tf")
    assert 'resource "aws_eks_access_entry" "deployer"' in eks
    assert "kubernetes_groups = [var.deployment_kubernetes_group]" in eks
    assert 'resource "aws_eks_access_policy_association" "deployer"' not in eks
    assert (
        "AmazonEKSClusterAdminPolicy" in eks
    )  # only the pre-existing platform administrator entry
    assert "deployment_role_arn" in read("modules/eks/variables.tf")


def test_no_static_credentials_or_wildcard_repository_trust_in_ci_files() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = workflow.read_text(encoding="utf-8").lower()
        assert "aws_access_key_id" not in text
        assert "aws_secret_access_key" not in text
    terraform = "\n".join(path.read_text(encoding="utf-8") for path in TF.rglob("*.tf"))
    assert "repo:${var.github_owner}/*" not in terraform
    assert "aws_access_key_id" not in terraform.lower()
    assert "aws_secret_access_key" not in terraform.lower()
