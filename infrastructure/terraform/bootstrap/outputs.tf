output "state_bucket_name" {
  value       = aws_s3_bucket.state.id
  description = "S3 bucket name; configure separately in each backend.hcl."
}

output "state_kms_key_arn" {
  value       = aws_kms_key.state.arn
  description = "State encryption key ARN; configure separately in each backend.hcl."
}

output "account_id" {
  value       = data.aws_caller_identity.current.account_id
  description = "AWS account identity resolved by the configured provider."
}

