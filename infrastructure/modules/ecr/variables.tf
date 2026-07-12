variable "name_prefix" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "allowed_pull_role_arns" {
  type = list(string)
}
variable "tags" {
  type = map(string)
}
