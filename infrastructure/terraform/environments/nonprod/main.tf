module "platform" {
  api_client_security_group_ids = var.api_client_security_group_ids
  source                        = "../../modules/platform"
  name                          = "graa-nonprod"
  environment                   = "nonprod"
  region                        = var.region
  vpc_cidr                      = "10.20.0.0/16"
  availability_zones            = var.availability_zones
  nat_strategy                  = "single"
  capacity                      = { min = 1, desired = 1, max = 2 }
  retention_days                = 14
  deletion_protection           = false
  kubernetes_version            = var.kubernetes_version
  instance_types                = var.instance_types
  administrator_role_arns       = var.administrator_role_arns
  addon_versions                = var.addon_versions
  tags                          = { CostCenter = var.cost_center, Owner = "platform-security" }
}
