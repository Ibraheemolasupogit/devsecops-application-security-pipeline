resource "aws_dynamodb_table" "access_governance" {
  name                        = "${var.name_prefix}-access-governance"
  billing_mode                = var.billing_mode
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = var.deletion_protection_enabled

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "S"
  }

  global_secondary_index {
    name            = "gsi1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = var.point_in_time_recovery_enabled
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name    = "${var.name_prefix}-access-governance"
    Purpose = "access-requests-entitlements-audit-index"
  })

  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.point_in_time_recovery_enabled
      error_message = "Production DynamoDB tables must enable point-in-time recovery."
    }
    precondition {
      condition     = var.environment != "prod" || var.deletion_protection_enabled
      error_message = "Production DynamoDB tables must enable deletion protection."
    }
  }
}
