variable "name" {
  type = string
}
variable "region" {
  type = string
}
variable "vpc_cidr" {
  type = string
}
variable "availability_zones" {
  type = list(string)
}
variable "nat_strategy" {
  type = string
}
variable "flow_log_role_arn" {
  type = string
}
variable "flow_log_group_arn" {
  type = string
}
variable "tags" {
  type = map(string)
}
