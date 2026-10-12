module "platform" {
  api_client_security_group_ids = var.api_client_security_group_ids
  source                        = "../../modules/platform"
  name                          = "graa-prod"
  environment                   = "prod"
  region                        = var.region
  vpc_cidr                      = "10.30.0.0/16"
  availability_zones            = var.availability_zones
  nat_strategy                  = "per_az"
  capacity                      = { min = 2, desired = 2, max = 3 }
  retention_days                = 90
  deletion_protection           = true
  kubernetes_version            = var.kubernetes_version
  instance_types                = var.instance_types
  administrator_role_arns       = var.administrator_role_arns
  addon_versions                = var.addon_versions
  tags                          = { CostCenter = var.cost_center, Owner = "platform-security" }
}
