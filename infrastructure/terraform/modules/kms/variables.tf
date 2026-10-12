variable "name" {
  type = string
}
variable "region" {
  type = string
}
variable "log_group_arns" {
  type    = list(string)
  default = []
}
variable "tags" {
  type = map(string)
}
