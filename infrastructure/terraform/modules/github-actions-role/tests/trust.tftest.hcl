mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-github-role" } }
  mock_resource "aws_iam_role_policy" {}
}

variables {
  role_name         = "test-deployer"
  role_kind         = "deployer"
  oidc_provider_arn = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
  subject           = "repo:Ibraheemolasupogit/devsecops-application-security-pipeline:environment:qa"
  region            = "eu-west-2"
  cluster_arn       = "arn:aws:eks:eu-west-2:000000000000:cluster/graa-nonprod"
  tags              = { Environment = "test" }
}

run "qa_deployer_has_exact_trust_and_cluster" {
  command = plan
  assert {
    condition     = aws_iam_role.github.name == "test-deployer" && aws_iam_role_policy.github.name == "test-deployer-permissions"
    error_message = "A named, separately scoped GitHub role policy is expected."
  }
}

run "reject_wildcard_subject" {
  command = plan
  variables { subject = "repo:Ibraheemolasupogit/*:environment:qa" }
  expect_failures = [var.subject]
}

run "reject_non_environment_deployer_subject" {
  command = plan
  variables { subject = "repo:Ibraheemolasupogit/devsecops-application-security-pipeline:ref:refs/heads/main" }
  expect_failures = [var.subject]
}
