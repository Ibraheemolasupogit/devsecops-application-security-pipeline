variable "name" {
  type = string
}
variable "environment" {
  type = string
}
variable "region" {
  type = string
}
variable "vpc_cidr" {
  type = string
}
variable "availability_zones" {
  type = list(string)
}
variable "nat_strategy" {
  type = string
}
variable "capacity" {
  type = object({ min = number, desired = number, max = number })
}
variable "retention_days" {
  type = number
}
variable "deletion_protection" {
  type = bool
}
variable "kubernetes_version" {
  type = string
}
variable "instance_types" {
  type = list(string)
}
variable "administrator_role_arns" {
  type = set(string)
}
variable "addon_versions" {
  type = map(string)
}
variable "tags" {
  type = map(string)
}

variable "api_client_security_group_ids" {
  type = set(string)
}

variable "github_owner" { type = string }
variable "github_repository" { type = string }
variable "github_oidc_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Reuse the existing account-local provider ARN, or create one in this environment state when null. Create only once per AWS account."
  validation {
    condition     = var.github_oidc_provider_arn == null || can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "Supply the exact account-local GitHub Actions OIDC provider ARN or null to create it."
  }
}
variable "github_connection_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Optional already-bootstrapped regional AWS CodeConnections GitHub App connection. Null disables runner project creation; no OAuth/PAT credentials are managed here."
  validation {
    condition     = var.github_connection_arn == null || can(regex("^arn:[^:]+:(codeconnections|codestar-connections):[^:]+:[0-9]{12}:connection/.+$", var.github_connection_arn))
    error_message = "Supply the exact ARN of a bootstrapped AWS CodeConnections GitHub connection or null."
  }
}
