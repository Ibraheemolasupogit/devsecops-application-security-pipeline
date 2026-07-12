variable "project_name" {
  type        = string
  description = "Short project name used for consistent resource naming."
  default     = "genomic-research-access-api"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.project_name))
    error_message = "project_name must be lowercase kebab-case."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment."

  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region for the reference architecture."

  validation {
    condition     = length(var.aws_region) > 0
    error_message = "aws_region must be non-empty."
  }
}

variable "owner" {
  type        = string
  description = "Owning team or role."
  default     = "platform-engineering"
}

variable "data_classification" {
  type        = string
  description = "Data classification tag applied to resources."
  default     = "synthetic-sensitive"
}
