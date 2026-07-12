locals {
  name_prefix = "${var.project_name}-${var.environment}"

  common_tags = {
    Application        = "Genomic Research Access API"
    DataClassification = var.data_classification
    Environment        = var.environment
    ManagedBy          = "Terraform"
    Milestone          = "4"
    Owner              = var.owner
    Project            = var.project_name
  }
}
