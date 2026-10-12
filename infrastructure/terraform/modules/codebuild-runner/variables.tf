variable "project_name" { type = string }
variable "environment" { type = string }
variable "region" { type = string }
variable "kms_key_arn" { type = string }
variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "subnet_arns" { type = list(string) }
variable "github_owner" { type = string }
variable "github_repository" { type = string }
variable "github_connection_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:[^:]+:(codeconnections|codestar-connections):${var.region}:[0-9]{12}:connection/.+$", var.github_connection_arn))
    error_message = "GitHub CodeConnections ARN must be a connection in the runner's AWS region."
  }
}
variable "workflow_name" { type = string }
variable "tags" { type = map(string) }
