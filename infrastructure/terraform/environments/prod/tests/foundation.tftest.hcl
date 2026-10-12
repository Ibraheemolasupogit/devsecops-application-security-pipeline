mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-role" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:mock-log" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
# Synthetic provider fixtures only; add-on strings are NOT deployment approvals.
variables {
  region                        = "eu-west-2"
  availability_zones            = ["eu-west-2a", "eu-west-2b"]
  administrator_role_arns       = ["arn:aws:iam::000000000000:role/test-platform-admin"]
  api_client_security_group_ids = ["sg-00000000000000000"]
  cost_center                   = "mock-only"
  artifact_repository_url       = "000000000000.dkr.ecr.eu-west-2.amazonaws.com/test-api"
  github_oidc_provider_arn      = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
  addon_versions                = { "vpc-cni" = "v1.20.0-eksbuild.1", "kube-proxy" = "v1.36.0-eksbuild.1", "coredns" = "v1.13.0-eksbuild.1", "eks-pod-identity-agent" = "v1.3.0-eksbuild.1" }
}
run "environment_contract" {
  command = plan
  assert {
    condition     = output.cluster_name == "graa-prod" && output.region == "eu-west-2" && output.ecr_repository_url == var.artifact_repository_url
    error_message = "Environment identity/shared artifact contract changed."
  }
}
run "production_oidc_and_runner_boundaries" {
  command = plan
  assert {
    condition     = output.production_kubernetes_group == "github:production-deployer" && output.production_codebuild_runner_project_name == null && output.production_runner_security_group_id == null
    error_message = "Production has a distinct protected-environment role/access group and runner stays disabled until bootstrap."
  }
}
run "reject_wrong_region_az" {
  command = plan
  variables { availability_zones = ["us-east-1a", "us-east-1b"] }
  expect_failures = [var.availability_zones]
}
run "reject_missing_addon_pin" {
  command = plan
  variables { addon_versions = { "vpc-cni" = "v1.20.0-eksbuild.1" } }
  expect_failures = [var.addon_versions]
}
