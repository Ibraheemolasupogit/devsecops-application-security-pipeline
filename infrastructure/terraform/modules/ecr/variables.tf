variable "name" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "pull_role_arns" {
  type    = set(string)
  default = []
}
variable "tags" {
  type = map(string)
}
