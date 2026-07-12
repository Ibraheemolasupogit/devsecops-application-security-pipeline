variable "aws_region" {
  type = string
}
variable "project_name" {
  type    = string
  default = "genomic-research-access-api"
}
variable "environment" {
  type    = string
  default = "dev"
  validation {
    condition     = var.environment == "dev"
    error_message = "This environment composition is for dev only."
  }
}
variable "owner" {
  type    = string
  default = "platform-engineering"
}
variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
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
    condition     = !endswith(var.container_image, ":latest")
    error_message = "container_image must not use the latest tag."
  }
}
variable "certificate_arn" {
  type    = string
  default = ""
}
variable "github_repository" {
  type        = string
  description = "GitHub repository in owner/name form for OIDC trust."
}
variable "github_ref" {
  type        = string
  default     = "ref:refs/heads/main"
  description = "GitHub OIDC subject suffix, such as ref:refs/heads/main."
}
variable "alarm_sns_topic_arn" {
  type    = string
  default = ""
}
