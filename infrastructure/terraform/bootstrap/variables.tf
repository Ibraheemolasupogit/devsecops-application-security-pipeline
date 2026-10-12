variable "region" {
  type        = string
  description = "Approved single AWS region for the platform state bucket and key."
}

variable "state_bucket_name" {
  type        = string
  description = "Globally unique, approved S3 bucket name. Never use a placeholder at apply time."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.state_bucket_name)) && !can(regex("^[0-9]{12}$", var.state_bucket_name))
    error_message = "Use a valid globally unique lowercase S3 bucket name."
  }
}

variable "tags" {
  type        = map(string)
  description = "Approved cost-owner and environment tags for bootstrap resources."
  validation {
    condition     = contains(keys(var.tags), "CostCenter") && contains(keys(var.tags), "Owner")
    error_message = "Bootstrap resources require CostCenter and Owner tags."
  }
}
