data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = var.account_id != "" ? var.account_id : data.aws_caller_identity.current.account_id

  key_admin_arns = [
    "arn:aws:iam::${local.account_id}:role/${var.deployment_role_name}",
  ]
}

data "aws_iam_policy_document" "application_data" {
  statement {
    sid       = "EnableAccountRootMetadataAccess"
    actions   = ["kms:DescribeKey", "kms:GetKeyPolicy"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowDeploymentKeyAdministration"
    actions   = ["kms:CreateAlias", "kms:Describe*", "kms:EnableKeyRotation", "kms:Get*", "kms:List*", "kms:PutKeyPolicy", "kms:TagResource", "kms:UntagResource"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.key_admin_arns
    }
  }

  statement {
    sid       = "AllowRuntimeDataKeyUsage"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${local.account_id}:role/${var.runtime_role_name}",
      ]
    }
  }
}

data "aws_iam_policy_document" "secrets" {
  source_policy_documents = [data.aws_iam_policy_document.application_data.json]

  statement {
    sid       = "AllowTaskStartSecretDecrypt"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${local.account_id}:role/${var.execution_role_name}",
      ]
    }
  }
}

data "aws_iam_policy_document" "audit" {
  source_policy_documents = [data.aws_iam_policy_document.application_data.json]

  statement {
    sid       = "AllowCloudTrailUse"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com", "logs.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "application_data" {
  description             = "Application data key for ${var.name_prefix}"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.application_data.json
  tags                    = merge(var.tags, { Name = "${var.name_prefix}-application-data-key" })
}

resource "aws_kms_alias" "application_data" {
  name          = "alias/${var.name_prefix}-application-data"
  target_key_id = aws_kms_key.application_data.key_id
}

resource "aws_kms_key" "secrets" {
  description             = "Secrets Manager key for ${var.name_prefix}"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.secrets.json
  tags                    = merge(var.tags, { Name = "${var.name_prefix}-secrets-key" })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_kms_key" "audit" {
  description             = "Audit and logging key for ${var.name_prefix}"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.audit.json
  tags                    = merge(var.tags, { Name = "${var.name_prefix}-audit-key" })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${var.name_prefix}-audit"
  target_key_id = aws_kms_key.audit.key_id
}
