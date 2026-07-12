output "application_config_secret_arn" {
  value = aws_secretsmanager_secret.application_config.arn
}
output "jwt_public_key_secret_arn" {
  value = aws_secretsmanager_secret.jwt_public_key.arn
}
output "secret_arns" {
  value = [
    aws_secretsmanager_secret.application_config.arn,
    aws_secretsmanager_secret.jwt_public_key.arn,
  ]
}
