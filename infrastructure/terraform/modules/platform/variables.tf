variable "name" {
  type = string
}
variable "environment" {
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
variable "capacity" {
  type = object({ min = number, desired = number, max = number })
}
variable "retention_days" {
  type = number
}
variable "deletion_protection" {
  type = bool
}
variable "kubernetes_version" {
  type = string
}
variable "instance_types" {
  type = list(string)
}
variable "administrator_role_arns" {
  type = set(string)
}
variable "addon_versions" {
  type = map(string)
}
variable "tags" {
  type = map(string)
}

variable "api_client_security_group_ids" {
  type = set(string)
}
