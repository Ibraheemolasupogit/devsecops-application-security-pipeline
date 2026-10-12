provider "aws" { region = var.region }
variable "region" { type = string }
variable "cost_center" { type = string }
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
output "ecr_repository_url" { value = module.ecr.repository_url }
output "ecr_repository_arn" { value = module.ecr.repository_arn }
output "kms_key_arn" { value = module.kms.key_arn }
output "region" { value = var.region }
