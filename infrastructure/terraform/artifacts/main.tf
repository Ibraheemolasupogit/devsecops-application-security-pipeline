provider "aws" { region = var.region }
variable "region" { type = string }
variable "cost_center" { type = string }
variable "github_owner" {
  type    = string
  default = "Ibraheemolasupogit"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_owner))
    error_message = "GitHub owner must be exact and contain no wildcard."
  }
}
variable "github_repository" {
  type    = string
  default = "devsecops-application-security-pipeline"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "GitHub repository must be exact and contain no wildcard."
  }
}
variable "github_oidc_provider_arn" {
  type        = string
  default     = null
  nullable    = true
  description = "Reuse an existing provider in this account or create one in this stack."
  validation {
    condition     = var.github_oidc_provider_arn == null || can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "Supply the exact GitHub Actions OIDC provider ARN or null."
  }
}
variable "pull_role_arns" {
  type        = set(string)
  default     = []
  description = "Existing nonprod/prod node-role ARNs, required for cross-account pulls; populate after platform creation and before image use."
  validation {
    condition     = alltrue([for arn in var.pull_role_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", arn))])
    error_message = "Repository principals must be explicit IAM role ARNs."
  }
}
locals { tags = { Environment = "shared-artifacts", Project = "devsecops-application-security-pipeline", Platform = "EKS", ManagedBy = "Terraform", CostCenter = var.cost_center, Owner = "platform-security" } }
module "kms" {
  source = "../modules/kms"
  name   = "graa-artifacts"
  region = var.region
  tags   = local.tags
}
module "ecr" {
  source         = "../modules/ecr"
  name           = "genomic-research-access-api"
  kms_key_arn    = module.kms.key_arn
  pull_role_arns = var.pull_role_arns
  tags           = local.tags
}
module "github_oidc" {
  source                = "../modules/github-oidc"
  existing_provider_arn = var.github_oidc_provider_arn
  tags                  = local.tags
}
module "publisher_identity" {
  source            = "../modules/github-actions-role"
  role_name         = "graa-artifact-publisher"
  role_kind         = "publisher"
  oidc_provider_arn = module.github_oidc.provider_arn
  subject           = "repo:${var.github_owner}/${var.github_repository}:ref:refs/heads/main"
  region            = var.region
  repository_arn    = module.ecr.repository_arn
  tags              = local.tags
}
output "ecr_repository_url" { value = module.ecr.repository_url }
output "ecr_repository_arn" { value = module.ecr.repository_arn }
output "kms_key_arn" { value = module.kms.key_arn }
output "region" { value = var.region }
output "github_oidc_provider_arn" { value = module.github_oidc.provider_arn }
output "artifact_publisher_role_arn" { value = module.publisher_identity.role_arn }
