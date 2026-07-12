output "application_data_key_arn" {
  value = aws_kms_key.application_data.arn
}
output "secrets_key_arn" {
  value = aws_kms_key.secrets.arn
}
output "audit_key_arn" {
  value = aws_kms_key.audit.arn
}
