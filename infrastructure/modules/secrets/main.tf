resource "aws_secretsmanager_secret" "application_config" {
  name                    = "${var.name_prefix}/application-config"
  description             = "Application configuration metadata. Secret value populated outside Terraform."
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = merge(var.tags, { SecretValueManagedOutsideTerraform = "true" })
}

resource "aws_secretsmanager_secret" "jwt_public_key" {
  name                    = "${var.name_prefix}/jwt-public-key"
  description             = "JWT public key or key reference. Secret value populated outside Terraform."
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = merge(var.tags, { SecretValueManagedOutsideTerraform = "true" })
}
