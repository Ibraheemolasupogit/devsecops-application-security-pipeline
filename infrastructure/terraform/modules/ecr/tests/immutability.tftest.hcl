mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-role" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:mock-log" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
variables {
  name        = "mock-artifacts"
  kms_key_arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000"
  tags        = { Environment = "shared-artifacts", ManagedBy = "Terraform" }
}
run "immutable_encrypted_scanned_artifact" {
  command = plan
  assert {
    condition     = aws_ecr_repository.this.image_tag_mutability == "IMMUTABLE" && aws_ecr_repository.this.encryption_configuration[0].encryption_type == "KMS" && aws_ecr_repository.this.image_scanning_configuration[0].scan_on_push && !aws_ecr_repository.this.force_delete
    error_message = "Supply-chain repository controls cannot be relaxed."
  }
  assert {
    condition     = jsondecode(aws_ecr_lifecycle_policy.untagged.policy).rules[0].selection.tagStatus == "untagged"
    error_message = "Lifecycle must preserve tagged deployment/rollback images."
  }
}
