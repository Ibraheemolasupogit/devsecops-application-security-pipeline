data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
locals {
  tags           = merge(var.tags, { Environment = var.environment, ManagedBy = "Terraform", Platform = "EKS", Project = "devsecops-application-security-pipeline" })
  log_group_arns = [for path in ["/aws/eks/${var.name}/cluster", "/aws/vpc/${var.name}/flow"] : "arn:${data.aws_partition.current.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${path}"]
}
module "kms" {
  source         = "../kms"
  name           = var.name
  region         = var.region
  log_group_arns = local.log_group_arns
  tags           = local.tags
}
module "logging" {
  source         = "../logging"
  name           = var.name
  kms_key_arn    = module.kms.key_arn
  retention_days = var.retention_days
  tags           = local.tags
}
module "networking" {
  depends_on         = [module.logging]
  source             = "../networking"
  name               = var.name
  region             = var.region
  vpc_cidr           = var.vpc_cidr
  availability_zones = var.availability_zones
  nat_strategy       = var.nat_strategy
  flow_log_group_arn = module.logging.flow_log_group_arn
  flow_log_role_arn  = module.logging.flow_log_role_arn
  tags               = local.tags
}
module "iam" {
  source = "../iam"
  name   = var.name
  tags   = local.tags
}
module "eks" {
  api_client_security_group_ids = var.api_client_security_group_ids
  source                        = "../eks"
  name                          = var.name
  kubernetes_version            = var.kubernetes_version
  subnet_ids                    = module.networking.private_subnet_ids
  vpc_id                        = module.networking.vpc_id
  cluster_role_arn              = module.iam.cluster_role_arn
  node_role_arn                 = module.iam.node_role_arn
  cni_role_arn                  = module.iam.cni_role_arn
  kms_key_arn                   = module.kms.key_arn
  instance_types                = var.instance_types
  capacity                      = var.capacity
  deletion_protection           = var.deletion_protection
  administrator_role_arns       = var.administrator_role_arns
  addon_versions                = var.addon_versions
  tags                          = local.tags
  depends_on                    = [module.iam, module.logging]
}
