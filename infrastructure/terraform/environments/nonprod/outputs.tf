output "cluster_name" {
  value = module.platform.cluster_name
}
output "cluster_endpoint" {
  value = module.platform.cluster_endpoint
}
output "cluster_ca_data" {
  value = module.platform.cluster_ca_data
}
output "oidc_issuer_url" {
  value = module.platform.oidc_issuer_url
}
output "vpc_id" {
  value = module.platform.vpc_id
}
output "private_subnet_ids" {
  value = module.platform.private_subnet_ids
}
output "public_subnet_ids" {
  value = module.platform.public_subnet_ids
}
output "kms_key_arn" {
  value = module.platform.kms_key_arn
}
output "node_role_arn" {
  value = module.platform.node_role_arn
}
output "ecr_repository_url" { value = var.artifact_repository_url }
output "region" { value = var.region }
output "github_oidc_provider_arn" { value = var.github_oidc_provider_arn }
