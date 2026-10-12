mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/test"
      user_id    = "test"
    }
  }

  # The provider normally renders this policy document from the HCL data
  # source. Terraform's generic mock string is not JSON, so provide a
  # structurally faithful document for the KMS resource and assertions.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Sid      = "EnableAccountIAMPermissions"
          Effect   = "Allow"
          Action   = ["kms:*"]
          Resource = ["*"]
          Principal = {
            AWS = ["arn:aws:iam::123456789012:root"]
          }
        }]
      })
    }
  }
}

variables {
  region            = "eu-west-2"
  state_bucket_name = "graa-test-terraform-state"
  tags = {
    CostCenter = "test"
    Owner      = "platform-security"
  }
}

run "state_storage_is_protected_and_recoverable" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.force_destroy == false
    error_message = "State bucket must refuse force deletion."
  }

  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "State bucket versions are required for recovery."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.state.block_public_acls && aws_s3_bucket_public_access_block.state.block_public_policy && aws_s3_bucket_public_access_block.state.ignore_public_acls && aws_s3_bucket_public_access_block.state.restrict_public_buckets
    error_message = "All public access paths must be blocked."
  }

  assert {
    condition = alltrue([
      for rule in aws_s3_bucket_server_side_encryption_configuration.state.rule : anytrue([
        for encryption in rule.apply_server_side_encryption_by_default : encryption.sse_algorithm == "aws:kms"
      ])
    ])
    error_message = "Terraform state must use KMS encryption."
  }

  assert {
    condition     = aws_kms_key.state.enable_key_rotation && aws_kms_key.state.deletion_window_in_days >= 30
    error_message = "State KMS key rotation and recovery window are required."
  }

  assert {
    condition = (
      jsondecode(aws_kms_key.state.policy).Version == "2012-10-17" &&
      length(jsondecode(aws_kms_key.state.policy).Statement) == 1
    )
    error_message = "The KMS key policy must be valid JSON with the expected policy version and a single scoped delegation statement."
  }

  assert {
    condition = (
      jsondecode(aws_kms_key.state.policy).Statement[0].Sid == "EnableAccountIAMPermissions" &&
      jsondecode(aws_kms_key.state.policy).Statement[0].Effect == "Allow" &&
      contains(jsondecode(aws_kms_key.state.policy).Statement[0].Action, "kms:*") &&
      jsondecode(aws_kms_key.state.policy).Statement[0].Resource == ["*"] &&
      jsondecode(aws_kms_key.state.policy).Statement[0].Principal.AWS == ["arn:aws:iam::123456789012:root"]
    )
    error_message = "KMS key administration and usage delegation must remain scoped to this account root; wildcard resource applies only to the attached key policy."
  }
}
