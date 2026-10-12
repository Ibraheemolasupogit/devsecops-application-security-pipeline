mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-role" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:mock-log" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
variables {
  region      = "eu-west-2"
  cost_center = "mock-only"
}
run "shared_artifact_contract" {
  command = plan
  assert {
    condition     = output.region == "eu-west-2"
    error_message = "Artifact stack region must be explicit."
  }
}
run "reject_wildcard_pull_principal" {
  command = plan
  variables { pull_role_arns = ["*"] }
  expect_failures = [var.pull_role_arns]
}
