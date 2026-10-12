mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-role" } }
  mock_resource "aws_eks_access_entry" {
    defaults = {
      principal_arn     = "arn:aws:iam::000000000000:role/qa-deployer"
      kubernetes_groups = ["github:qa-deployer"]
      type              = "STANDARD"
    }
  }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:mock-log" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
variables {
  name                          = "mock-cluster"
  kubernetes_version            = "1.36"
  subnet_ids                    = ["subnet-00000000000000001", "subnet-00000000000000002"]
  vpc_id                        = "vpc-00000000000000000"
  cluster_role_arn              = "arn:aws:iam::000000000000:role/test-cluster"
  node_role_arn                 = "arn:aws:iam::000000000000:role/test-node"
  cni_role_arn                  = "arn:aws:iam::000000000000:role/test-cni"
  kms_key_arn                   = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000"
  instance_types                = ["t3.medium"]
  capacity                      = { min = 1, desired = 1, max = 2 }
  deletion_protection           = false
  administrator_role_arns       = ["arn:aws:iam::000000000000:role/test-admin"]
  api_client_security_group_ids = ["sg-00000000000000000"]
  deployment_role_arn           = "arn:aws:iam::000000000000:role/qa-deployer"
  deployment_kubernetes_group   = "github:qa-deployer"
  addon_versions                = { "vpc-cni" = "v1.20.0-eksbuild.1", "kube-proxy" = "v1.36.0-eksbuild.1", "coredns" = "v1.13.0-eksbuild.1", "eks-pod-identity-agent" = "v1.3.0-eksbuild.1" }
  tags                          = { Environment = "mock", ManagedBy = "Terraform" }
}
run "private_encrypted_logged_cluster" {
  command = plan
  assert {
    condition     = !aws_eks_cluster.this.vpc_config[0].endpoint_public_access && aws_eks_cluster.this.vpc_config[0].endpoint_private_access && aws_eks_cluster.this.access_config[0].authentication_mode == "API" && !aws_eks_cluster.this.access_config[0].bootstrap_cluster_creator_admin_permissions
    error_message = "Private API and explicit access entries are mandatory."
  }
  assert {
    condition     = toset(aws_eks_cluster.this.enabled_cluster_log_types) == toset(["api", "audit", "authenticator", "controllerManager", "scheduler"]) && aws_eks_cluster.this.encryption_config[0].provider[0].key_arn == var.kms_key_arn
    error_message = "All control-plane logs and CMK encryption must remain enabled."
  }
  assert {
    condition     = toset(aws_eks_node_group.general.subnet_ids) == toset(var.subnet_ids) && aws_launch_template.nodes.metadata_options[0].http_tokens == "required" && aws_launch_template.nodes.metadata_options[0].http_put_response_hop_limit == 1 && aws_launch_template.nodes.block_device_mappings[0].ebs[0].encrypted
    error_message = "Private nodes, IMDSv2/hop isolation and encrypted root disks are required."
  }
  assert {
    condition     = alltrue([for rule in aws_security_group.nodes.ingress : try(length(rule.cidr_blocks), 0) == 0 && try(length(rule.ipv6_cidr_blocks), 0) == 0])
    error_message = "No worker ingress may originate from public CIDRs."
  }
}
run "reject_unrecoverable_access" {
  command = plan
  variables { administrator_role_arns = [] }
  expect_failures = [aws_eks_cluster.this]
}
run "reject_invalid_capacity" {
  command = plan
  variables { capacity = { min = 2, desired = 1, max = 1 } }
  expect_failures = [aws_eks_node_group.general]
}
