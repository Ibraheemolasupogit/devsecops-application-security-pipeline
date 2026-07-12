variable "name_prefix" {
  type = string
}
variable "environment" {
  type = string
}
variable "aws_region" {
  type = string
}
variable "vpc_id" {
  type = string
}
variable "public_subnet_ids" {
  type = list(string)
}
variable "private_subnet_ids" {
  type = list(string)
}
variable "alb_security_group_id" {
  type = string
}
variable "ecs_tasks_security_group_id" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "task_execution_role_arn" {
  type = string
}
variable "runtime_role_arn" {
  type = string
}
variable "application_port" {
  type = number
}
variable "container_image" {
  type = string
}
variable "desired_count" {
  type = number
}
variable "cpu" {
  type = number
}
variable "memory" {
  type = number
}
variable "ecs_log_group_name" {
  type = string
}
variable "secret_arns" {
  type = list(string)
}
variable "certificate_arn" {
  type = string
}
variable "enable_http_listener" {
  type = bool
}
variable "enable_https_listener" {
  type = bool
}
variable "alb_access_logs_bucket" {
  type = string
}
variable "tags" {
  type = map(string)
}
