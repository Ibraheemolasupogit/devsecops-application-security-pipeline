variable "aws_region" {
  type = string
}
variable "project_name" {
  type    = string
  default = "genomic-research-access-api"
}
variable "environment" {
  type    = string
  default = "prod"
  validation {
    condition     = var.environment == "prod"
    error_message = "This environment composition is for prod only."
  }
}
variable "owner" {
  type    = string
  default = "platform-engineering"
}
variable "vpc_cidr" {
  type    = string
  default = "10.50.0.0/16"
}
variable "availability_zones" {
  type = list(string)
}
variable "public_subnet_cidrs" {
  type = list(string)
}
variable "private_app_subnet_cidrs" {
  type = list(string)
}
variable "container_image" {
  type        = string
  description = "Immutable application image URI. Do not use :latest."
  validation {
    condition     = !endswith(var.container_image, ":latest") && can(regex("@sha256:[a-f0-9]{64}$", var.container_image))
    error_message = "Production container_image must use an immutable sha256 digest and must not use latest."
  }
}
variable "certificate_arn" {
  type        = string
  description = "ACM certificate ARN. Required in production."
  validation {
    condition     = can(regex("^arn:aws:acm:[a-z0-9-]+:[0-9]{12}:certificate/.+", var.certificate_arn))
    error_message = "Production requires a real ACM certificate ARN."
  }
}
variable "github_repository" {
  type        = string
  description = "GitHub repository in owner/name form for OIDC trust."
}
variable "github_ref" {
  type        = string
  default     = "environment:production"
  description = "GitHub OIDC subject suffix, such as environment:production."
}
variable "alarm_sns_topic_arn" {
  type    = string
  default = ""
}
