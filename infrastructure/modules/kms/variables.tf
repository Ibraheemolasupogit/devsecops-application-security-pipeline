variable "name_prefix" {
  type = string
}
variable "environment" {
  type = string
}
variable "account_id" {
  type = string
}
variable "deployment_role_name" {
  type = string
}
variable "runtime_role_name" {
  type = string
}
variable "execution_role_name" {
  type = string
}
variable "deletion_window_in_days" {
  type = number
}
variable "tags" {
  type = map(string)
}
