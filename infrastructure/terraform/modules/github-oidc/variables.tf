variable "tags" {
  type = map(string)
}

variable "existing_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Optional GitHub OIDC provider already owned by another Terraform state in this AWS account."
  validation {
    condition     = var.existing_provider_arn == null || can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_provider_arn))
    error_message = "Existing provider must be the exact GitHub Actions OIDC provider ARN."
  }
}
