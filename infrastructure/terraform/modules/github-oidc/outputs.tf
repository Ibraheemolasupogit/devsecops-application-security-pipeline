output "provider_arn" {
  value = var.existing_provider_arn != null ? var.existing_provider_arn : aws_iam_openid_connect_provider.github[0].arn
}
