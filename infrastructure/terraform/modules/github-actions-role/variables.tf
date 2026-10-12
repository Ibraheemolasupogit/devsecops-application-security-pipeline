variable "role_name" {
  type = string
}

variable "role_kind" {
  type = string
  validation {
    condition     = contains(["publisher", "deployer"], var.role_kind)
    error_message = "role_kind must be publisher or deployer."
  }
}

variable "oidc_provider_arn" {
  type = string
}

variable "subject" {
  type = string
  validation {
    condition = (
      can(regex("^repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:(ref:refs/heads/[A-Za-z0-9_./-]+|environment:(qa|production))$", var.subject)) &&
      !strcontains(var.subject, "*") &&
      (var.role_kind == "publisher" ? can(regex(":ref:refs/heads/", var.subject)) : can(regex(":environment:(qa|production)$", var.subject)))
    )
    error_message = "Trust subject must identify this exact repository and use a branch for publisher or qa/production GitHub Environment for deployer."
  }
}

variable "region" {
  type = string
}

variable "repository_arn" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = var.role_kind == "publisher" ? var.repository_arn != null && can(regex("^arn:[^:]+:ecr:[^:]+:[0-9]{12}:repository/[A-Za-z0-9._/-]+$", var.repository_arn)) && !strcontains(var.repository_arn, "*") : var.repository_arn == null
    error_message = "Publisher role requires one exact ECR repository ARN; deployer roles must not receive ECR repository scope."
  }
}

variable "cluster_arn" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = var.role_kind == "deployer" ? var.cluster_arn != null && can(regex("^arn:[^:]+:eks:[^:]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+$", var.cluster_arn)) : var.cluster_arn == null
    error_message = "Deployer role requires one exact EKS cluster ARN; publisher roles must not receive EKS cluster scope."
  }
}

variable "tags" {
  type = map(string)
}
