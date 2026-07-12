variable "name_prefix" {
  type = string
}
variable "environment" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "billing_mode" {
  type = string
}
variable "deletion_protection_enabled" {
  type = bool
}
variable "point_in_time_recovery_enabled" {
  type = bool
}
variable "tags" {
  type = map(string)
}
