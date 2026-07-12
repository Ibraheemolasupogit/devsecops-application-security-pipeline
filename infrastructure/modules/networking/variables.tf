variable "name_prefix" {
  type = string
}
variable "environment" {
  type = string
}
variable "vpc_cidr" {
  type = string
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
variable "enable_nat_gateway" {
  type = bool
}
variable "application_port" {
  type = number
}
variable "vpc_flow_log_role_arn" {
  type = string
}
variable "vpc_flow_log_group_arn" {
  type = string
}
variable "tags" {
  type = map(string)
}

variable "enable_flow_logs" {
  type    = bool
  default = true
}
