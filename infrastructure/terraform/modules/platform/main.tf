data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
locals {
  tags                = merge(var.tags, { Environment = var.environment, ManagedBy = "Terraform", Platform = "EKS", Project = "devsecops-application-security-pipeline" })
  runner_project_name = "${var.name}-${var.environment == "nonprod" ? "qa" : "production"}-deploy-runner"
  log_group_paths     = concat(["/aws/eks/${var.name}/cluster", "/aws/vpc/${var.name}/flow"], var.github_connection_arn == null ? [] : ["/aws/codebuild/${local.runner_project_name}"])
  log_group_arns      = [for path in local.log_group_paths : "arn:${data.aws_partition.current.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${path}"]
  private_subnet_arns = [for id in module.networking.private_subnet_ids : "arn:${data.aws_partition.current.partition}:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:subnet/${id}"]
  github_environment  = var.environment == "nonprod" ? "qa" : "production"
  deployer_subject    = "repo:${var.github_owner}/${var.github_repository}:environment:${local.github_environment}"
  cluster_arn         = "arn:${data.aws_partition.current.partition}:eks:${var.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.name}"
}
module "github_oidc" {
  source                = "../github-oidc"
  existing_provider_arn = var.github_oidc_provider_arn
  tags                  = local.tags
}
module "deployment_identity" {
  source            = "../github-actions-role"
  role_name         = "${var.name}-github-${local.github_environment}-deployer"
  role_kind         = "deployer"
  oidc_provider_arn = module.github_oidc.provider_arn
  subject           = local.deployer_subject
  region            = var.region
  cluster_arn       = local.cluster_arn
  tags              = local.tags
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
module "codebuild_runner" {
  count  = var.github_connection_arn == null ? 0 : 1
  source = "../codebuild-runner"

  project_name          = local.runner_project_name
  environment           = var.environment
  region                = var.region
  kms_key_arn           = module.kms.key_arn
  vpc_id                = module.networking.vpc_id
  vpc_cidr              = var.vpc_cidr
  private_subnet_ids    = module.networking.private_subnet_ids
  subnet_arns           = local.private_subnet_arns
  github_owner          = var.github_owner
  github_repository     = var.github_repository
  github_connection_arn = var.github_connection_arn
  workflow_name         = var.environment == "nonprod" ? "deploy-qa" : "promote-production"
  tags                  = local.tags
}
module "iam" {
  source = "../iam"
  name   = var.name
  tags   = local.tags
}
module "eks" {
  api_client_security_group_ids = setunion(var.api_client_security_group_ids, [for runner in module.codebuild_runner : runner.security_group_id])
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
  deployment_role_arn           = module.deployment_identity.role_arn
  deployment_kubernetes_group   = "github:${local.github_environment}-deployer"
  addon_versions                = var.addon_versions
  tags                          = local.tags
  depends_on                    = [module.iam, module.logging]
}
