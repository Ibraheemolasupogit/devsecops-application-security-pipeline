variable "region" {
  type        = string
  description = "Approved AWS region; no region/account inferred from the workstation."
}
variable "availability_zones" {
  type        = list(string)
  description = "Two or three distinct, region-local AZs, confirmed available before an authorised plan."
  validation {
    condition     = length(var.availability_zones) >= 2 && length(var.availability_zones) <= 3 && alltrue([for az in var.availability_zones : startswith(az, var.region)])
    error_message = "Supply two or three AZs in the selected region."
  }
}
variable "administrator_role_arns" {
  type        = set(string)
  description = "Existing short-lived platform operator IAM roles, never the routine publisher/deployer."
  validation {
    condition     = length(var.administrator_role_arns) > 0 && alltrue([for arn in var.administrator_role_arns : can(regex("^arn:[^:]+:iam::[0-9]{12}:role/.+$", arn))])
    error_message = "At least one IAM role ARN is required."
  }
}
variable "addon_versions" {
  type        = map(string)
  description = "Explicit approved versions compatible with Kubernetes version/architecture/Pod Identity; discover in separately authorised preflight."
  validation {
    condition     = toset(keys(var.addon_versions)) == toset(["vpc-cni", "kube-proxy", "coredns", "eks-pod-identity-agent"]) && alltrue([for v in values(var.addon_versions) : can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+-eksbuild\\.[0-9]+$", v))])
    error_message = "Pin exactly the four supported AWS-managed essential add-ons."
  }
}
variable "kubernetes_version" {
  type    = string
  default = "1.36"
  validation {
    condition     = contains(["1.35", "1.36"], var.kubernetes_version)
    error_message = "Use EKS 1.36 for the standard-support runway; verify regional availability before applying."
  }
}
variable "instance_types" {
  type        = list(string)
  default     = ["t3.medium"]
  description = "x86_64 general-purpose instances compatible with the AL2023 AMI; validate regional supply and workload capacity."
  validation {
    condition     = length(var.instance_types) > 0 && alltrue([for t in var.instance_types : can(regex("^(t3|t3a|m6i|m7i|m5)\\.", t))])
    error_message = "Use compatible x86 general-purpose node families."
  }
}
variable "artifact_repository_url" {
  type        = string
  description = "Shared artifact stack output; no ECR duplicate or live data lookup in cluster states."
  validation {
    condition     = can(regex("\\.dkr\\.ecr\\..+\\.amazonaws\\.com(\\.cn)?/.+$", var.artifact_repository_url))
    error_message = "Supply the private shared ECR repository URL."
  }
}
variable "github_oidc_provider_arn" {
  type        = string
  default     = null
  description = "Optional existing GitHub federation provider ARN, inventoried only; no CI deployment role in M3."
  validation {
    condition     = var.github_oidc_provider_arn == null ? true : can(regex("^arn:[^:]+:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "Use the existing exact GitHub OIDC provider ARN or null."
  }
}
variable "cost_center" {
  type        = string
  description = "Named budget/cost allocation owner."
  validation {
    condition     = length(trimspace(var.cost_center)) > 0
    error_message = "Cost ownership is required."
  }
}

variable "api_client_security_group_ids" {
  default     = []
  type        = set(string)
  description = "Optional controlled operator/runner security groups in this VPC or established peering topology. Empty during foundation bootstrap; M5 must provision and authorise the private access path before cluster use."
  validation {
    condition     = alltrue([for id in var.api_client_security_group_ids : can(regex("^sg-[0-9a-f]+$", id))])
    error_message = "Any supplied API client must be an explicit security group; public CIDR access is not supported."
  }
}
