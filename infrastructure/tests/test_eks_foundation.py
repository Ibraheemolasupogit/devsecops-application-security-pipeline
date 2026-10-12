"""Policy boundaries beyond the mock-provider resource assertions (no AWS calls)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EKS = ROOT / "infrastructure" / "terraform"


def source(path: str) -> str:
    return (EKS / path).read_text()


def test_environment_separation_and_minimal_capacity() -> None:
    nonprod = source("environments/nonprod/main.tf")
    prod = source("environments/prod/main.tf")
    for environment, text, cidr in (
        ("nonprod", nonprod, "10.20.0.0/16"),
        ("prod", prod, "10.30.0.0/16"),
    ):
        assert 'source                        = "../../modules/platform"' in text
        assert f'"graa-{environment}"' in text
        assert cidr in text
        backend = source(f"environments/{environment}/backend.hcl.example")
        assert f'key = "eks/{environment}/terraform.tfstate"' in backend
        assert "use_lockfile = true" in backend
    assert re.search(r"nat_strategy\s*=\s*\"single\"", nonprod)
    assert re.search(r"nat_strategy\s*=\s*\"per_az\"", prod)
    assert re.search(r"deletion_protection\s*=\s*true", prod)
    assert re.search(
        r"subnet_ids\s*=\s*module.networking.private_subnet_ids",
        source("modules/platform/main.tf"),
    )
    assert nonprod.count('module "') == prod.count('module "') == 1


def test_node_role_does_not_inherit_cni_or_application_permissions() -> None:
    iam = source("modules/iam/main.tf")
    node = iam.split('resource "aws_iam_role_policy_attachment" "node"')[1].split(
        'resource "aws_iam_role" "cni"'
    )[0]
    assert "AmazonEKSWorkerNodePolicy" in node
    assert "AmazonEC2ContainerRegistryPullOnly" in node
    assert "AmazonEKS_CNI_Policy" not in node
    assert "secretsmanager:" not in iam
    assert "dynamodb:" not in iam
    assert "eks-cluster-name" in iam
    assert "kubernetes-namespace" in iam
    assert "kubernetes-service-account" in iam
    assert "AmazonEKS_CNI_Policy" in iam.split('resource "aws_iam_role_policy_attachment" "cni"')[1]


def test_no_foundation_ci_admin_or_application_implementation() -> None:
    files = [p for p in EKS.rglob("*.tf") if ".terraform" not in p.parts]
    text = "\n".join(p.read_text() for p in files)
    forbidden = (
        "AdministratorAccess",
        "PowerUserAccess",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_secretsmanager_secret_version",
        'resource "kubernetes_',
        'resource "helm_',
        'resource "aws_eks_fargate_profile"',
    )
    assert all(value not in text for value in forbidden)
    assert (
        'resource "aws_iam_openid_connect_provider"'
        in (EKS / "modules" / "github-oidc" / "main.tf").read_text()
    )
    assert len(re.findall(r'resource "aws_eks_cluster"', text)) == 1
    assert len(re.findall(r'resource "aws_eks_node_group"', text)) == 1
    assert "sts:AssumeRoleWithWebIdentity" in text  # Exact-subject M5 trust is modeled.


def test_tagging_and_scoped_log_key_policy() -> None:
    platform = source("modules/platform/main.tf")
    artifact = source("artifacts/main.tf")
    for text in (platform, artifact):
        for tag in ("Environment", "Project", "Platform", "ManagedBy"):
            assert tag in text
    for env in ("nonprod", "prod"):
        text = source(f"environments/{env}/main.tf")
        assert "CostCenter" in text and "Owner" in text
    key = source("modules/kms/main.tf")
    assert "kms:EncryptionContext:aws:logs:arn" in key
    assert "var.log_group_arns" in key
    assert "enable_key_rotation" in key
    assert 'identifiers = ["*"]' not in key


def test_mock_tests_cannot_execute_live_provider_or_apply() -> None:
    tests = list(EKS.rglob("*.tftest.hcl"))
    assert len(tests) == 10
    for path in tests:
        text = path.read_text()
        assert 'mock_provider "aws"' in text
        runs = len(re.findall(r'^run "', text, re.MULTILINE))
        assert len(re.findall(r"command\s*=\s*plan", text)) == runs
        assert "command = apply" not in text
    assert sum(p.read_text().count("expect_failures") for p in tests) >= 7
