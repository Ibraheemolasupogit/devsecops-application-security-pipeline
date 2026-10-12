data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:AWS-recommended account-root IAM delegation in this key's attached policy; explicit account principal only. IAM administration is separately governed; no wildcard principal.
  #checkov:skip=CKV_AWS_111:Attached KMS key policy Resource=* identifies only this key; account root delegates administration/use to separately authorised IAM principals.
  #checkov:skip=CKV_AWS_356:KMS key policies use Resource=* for their own key, not an IAM policy granting access to every key.
  statement {
    sid       = "EnableAccountIAMPermissions"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  dynamic "statement" {
    for_each = length(var.log_group_arns) > 0 ? [1] : []
    content {
      sid       = "ScopedCloudWatchEncryption"
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = ["logs.${var.region}.amazonaws.com"]
      }
      condition {
        test     = "ArnEquals"
        variable = "kms:EncryptionContext:aws:logs:arn"
        values   = var.log_group_arns
      }
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["logs.${var.region}.amazonaws.com"]
      }
    }
  }
}
resource "aws_kms_key" "this" {
  description             = "Platform encryption for ${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
  tags                    = var.tags
}
resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}
