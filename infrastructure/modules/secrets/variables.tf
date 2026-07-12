variable "name_prefix" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "recovery_window_in_days" {
  type = number
}
variable "tags" {
  type = map(string)
}
