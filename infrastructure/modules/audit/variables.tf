variable "name_prefix" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "retention_days" {
  type = number
}
variable "log_retention_days" {
  type = number
}
variable "tags" {
  type = map(string)
}
