provider "aws" {
  region = var.aws_region
  default_tags { tags = local.common_tags }
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix          = "${var.project_name}-${var.environment}"
  account_id           = data.aws_caller_identity.current.account_id
  application_port     = 8000
  deletion_protection  = false
  enable_https         = var.certificate_arn != ""
  execution_role_name  = "${local.name_prefix}-ecs-execution"
  runtime_role_name    = "${local.name_prefix}-runtime"
  deployment_role_name = "${local.name_prefix}-github-oidc-deploy"
  ecr_repository_arn   = "arn:aws:ecr:${var.aws_region}:${local.account_id}:repository/${local.name_prefix}"
  common_tags = {
    Application        = "Genomic Research Access API"
    DataClassification = "synthetic-sensitive"
    Environment        = var.environment
    ManagedBy          = "Terraform"
    Milestone          = "4"
    Owner              = var.owner
    Project            = var.project_name
  }
}

module "kms" {
  source                  = "../../modules/kms"
  name_prefix             = local.name_prefix
  environment             = var.environment
  account_id              = local.account_id
  deployment_role_name    = local.deployment_role_name
  runtime_role_name       = local.runtime_role_name
  execution_role_name     = local.execution_role_name
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

module "secrets" {
  source                  = "../../modules/secrets"
  name_prefix             = local.name_prefix
  kms_key_arn             = module.kms.secrets_key_arn
  recovery_window_in_days = 7
  tags                    = local.common_tags
}

module "datastore" {
  source                         = "../../modules/datastore"
  name_prefix                    = local.name_prefix
  environment                    = var.environment
  kms_key_arn                    = module.kms.application_data_key_arn
  billing_mode                   = "PAY_PER_REQUEST"
  deletion_protection_enabled    = local.deletion_protection
  point_in_time_recovery_enabled = true
  tags                           = local.common_tags
}

module "iam" {
  source                   = "../../modules/iam"
  name_prefix              = local.name_prefix
  aws_region               = var.aws_region
  account_id               = local.account_id
  github_repository        = var.github_repository
  github_ref               = var.github_ref
  dynamodb_table_arn       = module.datastore.table_arn
  secret_arns              = module.secrets.secret_arns
  ecr_repository_arn       = local.ecr_repository_arn
  application_data_key_arn = module.kms.application_data_key_arn
  secrets_key_arn          = module.kms.secrets_key_arn
  audit_key_arn            = module.kms.audit_key_arn
  vpc_flow_log_group_arn   = module.observability.vpc_flow_log_group_arn
  tags                     = local.common_tags
}

module "ecr" {
  source                 = "../../modules/ecr"
  name_prefix            = local.name_prefix
  kms_key_arn            = module.kms.application_data_key_arn
  allowed_pull_role_arns = [module.iam.task_execution_role_arn]
  tags                   = local.common_tags
}

module "observability" {
  source                  = "../../modules/observability"
  name_prefix             = local.name_prefix
  environment             = var.environment
  kms_key_arn             = module.kms.audit_key_arn
  log_retention_days      = 365
  alarm_sns_topic_arn     = var.alarm_sns_topic_arn
  alb_arn_suffix          = local.name_prefix
  target_group_arn_suffix = local.name_prefix
  tags                    = local.common_tags
}

module "networking" {
  source                   = "../../modules/networking"
  name_prefix              = local.name_prefix
  environment              = var.environment
  vpc_cidr                 = var.vpc_cidr
  availability_zones       = var.availability_zones
  public_subnet_cidrs      = var.public_subnet_cidrs
  private_app_subnet_cidrs = var.private_app_subnet_cidrs
  enable_nat_gateway       = false
  application_port         = local.application_port
  vpc_flow_log_role_arn    = module.iam.vpc_flow_log_role_arn
  vpc_flow_log_group_arn   = module.observability.vpc_flow_log_group_arn
  tags                     = local.common_tags
}

module "compute" {
  source                      = "../../modules/compute"
  name_prefix                 = local.name_prefix
  environment                 = var.environment
  aws_region                  = var.aws_region
  vpc_id                      = module.networking.vpc_id
  public_subnet_ids           = module.networking.public_subnet_ids
  private_subnet_ids          = module.networking.private_app_subnet_ids
  alb_security_group_id       = module.networking.alb_security_group_id
  ecs_tasks_security_group_id = module.networking.ecs_tasks_security_group_id
  kms_key_arn                 = module.kms.audit_key_arn
  task_execution_role_arn     = module.iam.task_execution_role_arn
  runtime_role_arn            = module.iam.runtime_role_arn
  application_port            = local.application_port
  container_image             = var.container_image
  desired_count               = 1
  cpu                         = 512
  memory                      = 1024
  ecs_log_group_name          = "/ecs/${local.name_prefix}"
  secret_arns                 = module.secrets.secret_arns
  certificate_arn             = var.certificate_arn
  enable_http_listener        = true
  enable_https_listener       = local.enable_https
  alb_access_logs_bucket      = ""
  tags                        = local.common_tags
}

module "audit" {
  source             = "../../modules/audit"
  name_prefix        = local.name_prefix
  kms_key_arn        = module.kms.audit_key_arn
  retention_days     = 365
  log_retention_days = 365
  tags               = local.common_tags
}
