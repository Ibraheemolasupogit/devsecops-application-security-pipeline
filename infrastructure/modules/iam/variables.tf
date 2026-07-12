variable "name_prefix" {
  type = string
}
variable "aws_region" {
  type = string
}
variable "account_id" {
  type = string
}
variable "github_repository" {
  type = string
}
variable "github_ref" {
  type = string
}
variable "dynamodb_table_arn" {
  type = string
}
variable "secret_arns" {
  type = list(string)
}
variable "ecr_repository_arn" {
  type = string
}
variable "application_data_key_arn" {
  type = string
}
variable "secrets_key_arn" {
  type = string
}
variable "audit_key_arn" {
  type = string
}
variable "tags" {
  type = map(string)
}
