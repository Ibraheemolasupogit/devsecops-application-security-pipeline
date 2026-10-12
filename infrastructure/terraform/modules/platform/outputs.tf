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
