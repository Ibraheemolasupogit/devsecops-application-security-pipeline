resource "aws_ecr_repository" "this" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }
  image_scanning_configuration { scan_on_push = true }
  tags = var.tags
  lifecycle { prevent_destroy = true }
}
resource "aws_ecr_lifecycle_policy" "untagged" {
  repository = aws_ecr_repository.this.name
  policy     = jsonencode({ rules = [{ rulePriority = 1, description = "Expire untagged images only after 30 days; retain tagged release/rollback candidates", selection = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 30 }, action = { type = "expire" } }] })
}
resource "aws_ecr_repository_policy" "pull" {
  count      = length(var.pull_role_arns) > 0 ? 1 : 0
  repository = aws_ecr_repository.this.name
  policy     = jsonencode({ Version = "2012-10-17", Statement = [{ Sid = "ApprovedCrossAccountPull", Effect = "Allow", Principal = { AWS = var.pull_role_arns }, Action = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"] }] })
}
