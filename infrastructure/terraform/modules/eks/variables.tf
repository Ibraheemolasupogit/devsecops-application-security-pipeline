variable "name" {
  type = string
}
variable "kubernetes_version" {
  type = string
}
variable "subnet_ids" {
  type = list(string)
}
variable "vpc_id" {
  type = string
}
variable "cluster_role_arn" {
  type = string
}
variable "node_role_arn" {
  type = string
}
variable "cni_role_arn" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "instance_types" {
  type = list(string)
}
variable "capacity" {
  type = object({ min = number, desired = number, max = number })
}
variable "deletion_protection" {
  type = bool
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
variable "deployment_role_arn" { type = string }
variable "deployment_kubernetes_group" { type = string }
