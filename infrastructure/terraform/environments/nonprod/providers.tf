provider "aws" {
  region = var.region
  default_tags { tags = { Project = "devsecops-application-security-pipeline", ManagedBy = "Terraform", Platform = "EKS" } }
}
