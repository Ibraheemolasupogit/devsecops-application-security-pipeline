output "vpc_id" {
  value = module.networking.vpc_id
}
output "private_subnet_ids" {
  value = module.networking.private_app_subnet_ids
}
output "alb_dns_name" {
  value = module.compute.alb_dns_name
}
output "ecs_cluster_name" {
  value = module.compute.ecs_cluster_name
}
output "ecs_service_name" {
  value = module.compute.ecs_service_name
}
output "ecr_repository_url" {
  value = module.ecr.repository_url
}
output "dynamodb_table_name" {
  value = module.datastore.table_name
}
output "cloudwatch_log_group_name" {
  value = module.observability.ecs_log_group_name
}
output "application_data_kms_key_arn" {
  value = module.kms.application_data_key_arn
}
output "runtime_role_arn" {
  value = module.iam.runtime_role_arn
}
output "deployment_role_arn" {
  value = module.iam.deployment_role_arn
}
