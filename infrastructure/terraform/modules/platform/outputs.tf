output "cluster_name" {
  value = module.eks.cluster_name
}
output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}
output "cluster_ca_data" {
  value = module.eks.cluster_ca_data
}
output "oidc_issuer_url" {
  value = module.eks.oidc_issuer_url
}
output "vpc_id" {
  value = module.networking.vpc_id
}
output "private_subnet_ids" {
  value = module.networking.private_subnet_ids
}
output "public_subnet_ids" {
  value = module.networking.public_subnet_ids
}
output "kms_key_arn" {
  value = module.kms.key_arn
}
output "node_role_arn" {
  value = module.iam.node_role_arn
}
output "github_oidc_provider_arn" { value = module.github_oidc.provider_arn }
output "deployment_role_arn" { value = module.deployment_identity.role_arn }
output "deployment_kubernetes_group" { value = "github:${local.github_environment}-deployer" }
output "codebuild_runner_project_name" { value = length(module.codebuild_runner) == 0 ? null : module.codebuild_runner[0].project_name }
output "codebuild_runner_security_group_id" { value = length(module.codebuild_runner) == 0 ? null : module.codebuild_runner[0].security_group_id }
output "codebuild_runner_service_role_arn" { value = length(module.codebuild_runner) == 0 ? null : module.codebuild_runner[0].service_role_arn }
