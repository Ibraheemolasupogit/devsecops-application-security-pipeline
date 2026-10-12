data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  project_arn = "arn:${data.aws_partition.current.partition}:codebuild:${var.region}:${data.aws_caller_identity.current.account_id}:project/${var.project_name}"
  log_group   = "/aws/codebuild/${var.project_name}"
}

resource "aws_security_group" "runner" {
  #checkov:skip=CKV_AWS_382:This ephemeral runner needs GitHub and AWS APIs with dynamic AWS-managed endpoints; egress is limited to TCP 443 and VPC DNS, and the VPC NAT/endpoint model is documented for review.
  name        = "${var.project_name}-private-runner"
  description = "Ephemeral CodeBuild GitHub runner egress; no inbound access"
  vpc_id      = var.vpc_id

  egress {
    description = "GitHub, AWS APIs, and pinned workflow tool downloads via the VPC NAT path"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "VPC DNS resolver"
    protocol    = "udp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "VPC DNS resolver over TCP"
    protocol    = "tcp"
    from_port   = 53
    to_port     = 53
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.project_name}-private-runner" })
}

resource "aws_iam_role" "service" {
  name = "${var.project_name}-codebuild-service"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "codebuild.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { RoleType = "codebuild-runner-service" })
}

data "aws_iam_policy_document" "service" {
  statement {
    sid       = "WriteProjectLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.runner.arn}:*"]
  }

  statement {
    sid = "DescribeVpcNetworkForEni"
    actions = [
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcs",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CreateAndManageProjectEni"
    actions   = ["ec2:CreateNetworkInterface"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ec2:Subnet"
      values   = var.subnet_arns
    }
    condition {
      test     = "ArnEquals"
      variable = "ec2:SecurityGroup"
      values   = [aws_security_group.runner.arn]
    }
  }

  statement {
    sid       = "DeleteOnlyRegionalNetworkInterfaces"
    actions   = ["ec2:DeleteNetworkInterface"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:network-interface/*"]
  }

  statement {
    sid       = "AllowCodeBuildToManageItsNetworkInterface"
    actions   = ["ec2:CreateNetworkInterfacePermission"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:network-interface/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:AuthorizedService"
      values   = ["codebuild.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "ec2:Subnet"
      values   = var.subnet_arns
    }
  }

  statement {
    sid       = "UseBootstrappedGitHubConnection"
    actions   = ["codeconnections:UseConnection", "codestar-connections:UseConnection"]
    resources = [var.github_connection_arn]
  }
}

resource "aws_iam_role_policy" "service" {
  name   = "${var.project_name}-runtime"
  role   = aws_iam_role.service.id
  policy = data.aws_iam_policy_document.service.json
}

resource "aws_cloudwatch_log_group" "runner" {
  name              = local.log_group
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_codebuild_project" "runner" {
  name                   = var.project_name
  description            = "Ephemeral GitHub Actions deployment runner for ${var.environment} private EKS"
  service_role           = aws_iam_role.service.arn
  build_timeout          = 60
  queued_timeout         = 10
  concurrent_build_limit = 2
  badge_enabled          = false

  artifacts { type = "NO_ARTIFACTS" }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = false
  }

  source {
    type            = "GITHUB"
    location        = "https://github.com/${var.github_owner}/${var.github_repository}.git"
    git_clone_depth = 1
    auth {
      type     = "CODECONNECTIONS"
      resource = var.github_connection_arn
    }
  }

  vpc_config {
    vpc_id             = var.vpc_id
    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.runner.id]
  }

  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = aws_cloudwatch_log_group.runner.name
      stream_name = "runner"
    }
    s3_logs { status = "DISABLED" }
  }

  tags = merge(var.tags, { Environment = var.environment, RunnerMode = "ephemeral-github-actions" })
}

resource "aws_codebuild_webhook" "runner" {
  project_name = aws_codebuild_project.runner.name
  build_type   = "BUILD"

  filter_group {
    filter {
      type    = "EVENT"
      pattern = "WORKFLOW_JOB_QUEUED"
    }
    filter {
      type    = "WORKFLOW_NAME"
      pattern = var.workflow_name
    }
  }
}
