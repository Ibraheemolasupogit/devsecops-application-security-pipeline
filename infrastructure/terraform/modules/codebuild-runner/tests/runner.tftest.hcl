mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_resource "aws_security_group" { defaults = { id = "sg-0123456789abcdef0", arn = "arn:aws:ec2:eu-west-2:000000000000:security-group/sg-0123456789abcdef0" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-runner" } }
  mock_resource "aws_iam_role_policy" {}
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:/aws/codebuild/test-runner" } }
  mock_resource "aws_codebuild_project" { defaults = { arn = "arn:aws:codebuild:eu-west-2:000000000000:project/test-runner" } }
  mock_resource "aws_codebuild_webhook" {}
}

variables {
  project_name          = "test-runner"
  environment           = "nonprod"
  region                = "eu-west-2"
  kms_key_arn           = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000"
  vpc_id                = "vpc-0123456789abcdef0"
  vpc_cidr              = "10.20.0.0/16"
  private_subnet_ids    = ["subnet-00000000000000001", "subnet-00000000000000002"]
  subnet_arns           = ["arn:aws:ec2:eu-west-2:000000000000:subnet/subnet-00000000000000001"]
  github_owner          = "Ibraheemolasupogit"
  github_repository     = "devsecops-application-security-pipeline"
  github_connection_arn = "arn:aws:codeconnections:eu-west-2:000000000000:connection/00000000-0000-0000-0000-000000000000"
  workflow_name         = "deploy-qa"
  tags                  = { Environment = "nonprod" }
}

run "ephemeral_private_runner_contract" {
  command = plan
  assert {
    condition     = aws_codebuild_project.runner.vpc_config[0].vpc_id == var.vpc_id && toset(aws_codebuild_project.runner.vpc_config[0].subnets) == toset(var.private_subnet_ids)
    error_message = "CodeBuild runner must use only the target VPC private subnets."
  }
  assert {
    condition     = aws_codebuild_webhook.runner.build_type == "BUILD"
    error_message = "Runner webhook must enqueue independent ephemeral CodeBuild builds."
  }
}
