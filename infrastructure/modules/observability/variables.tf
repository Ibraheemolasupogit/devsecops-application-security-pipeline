variable "name_prefix" {
  type = string
}
variable "environment" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "log_retention_days" {
  type = number
}
variable "alarm_sns_topic_arn" {
  type = string
}
variable "alb_arn_suffix" {
  type = string
}
variable "target_group_arn_suffix" {
  type = string
}
variable "tags" {
  type = map(string)
}
