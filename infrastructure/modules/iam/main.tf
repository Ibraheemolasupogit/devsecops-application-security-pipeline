data "aws_caller_identity" "current" {}

locals {
  account_id = var.account_id != "" ? var.account_id : data.aws_caller_identity.current.account_id
}

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "task_execution" {
  name               = "${var.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = merge(var.tags, { RoleType = "task-execution" })
}

data "aws_iam_policy_document" "task_execution" {
  statement {
    sid = "EcrPull"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [var.ecr_repository_arn]
  }

  statement {
    sid       = "EcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteContainerLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/ecs/${var.name_prefix}:*"]
  }

  statement {
    sid       = "ReadTaskStartSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = var.secret_arns
  }

  statement {
    sid       = "DecryptTaskStartSecrets"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.secrets_key_arn]
  }
}

resource "aws_iam_policy" "task_execution" {
  name   = "${var.name_prefix}-ecs-execution"
  policy = data.aws_iam_policy_document.task_execution.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = aws_iam_policy.task_execution.arn
}

resource "aws_iam_role" "runtime" {
  name               = "${var.name_prefix}-runtime"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
  tags               = merge(var.tags, { RoleType = "application-runtime" })
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid = "AccessApplicationTable"
    actions = [
      "dynamodb:BatchGetItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:ConditionCheckItem",
      "dynamodb:DeleteItem",
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [var.dynamodb_table_arn, "${var.dynamodb_table_arn}/index/*"]
  }

  statement {
    sid       = "ReadRuntimeConfigSecret"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = var.secret_arns
  }

  statement {
    sid       = "UseApplicationKeys"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.application_data_key_arn, var.secrets_key_arn]
  }
}

resource "aws_iam_policy" "runtime" {
  name   = "${var.name_prefix}-runtime"
  policy = data.aws_iam_policy_document.runtime.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "runtime" {
  role       = aws_iam_role.runtime.name
  policy_arn = aws_iam_policy.runtime.arn
}

data "aws_iam_policy_document" "github_oidc_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${local.account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:${var.github_ref}"]
    }
  }
}

resource "aws_iam_role" "github_actions_deployment" {
  name               = "${var.name_prefix}-github-oidc-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_assume.json
  tags               = merge(var.tags, { RoleType = "github-oidc-deployment" })
}

data "aws_iam_policy_document" "deployment" {
  statement {
    sid = "ManageMilestone4Services"
    actions = [
      "application-autoscaling:*",
      "cloudtrail:*",
      "cloudwatch:*",
      "dynamodb:*",
      "ec2:CreateTags",
      "ec2:Describe*",
      "ecr:*",
      "ecs:*",
      "elasticloadbalancing:*",
      "iam:AttachRolePolicy",
      "iam:CreatePolicy",
      "iam:CreateRole",
      "iam:DeletePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:Get*",
      "iam:List*",
      "iam:PassRole",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "kms:*",
      "logs:*",
      "s3:*",
      "secretsmanager:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
}

resource "aws_iam_policy" "deployment" {
  name   = "${var.name_prefix}-deployment"
  policy = data.aws_iam_policy_document.deployment.json
  tags   = var.tags
}

resource "aws_iam_role_policy_attachment" "github_actions_deployment" {
  role       = aws_iam_role.github_actions_deployment.name
  policy_arn = aws_iam_policy.deployment.arn
}

resource "aws_iam_role" "vpc_flow_logs" {
  name               = "${var.name_prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_logs_assume.json
  tags               = merge(var.tags, { RoleType = "vpc-flow-logs" })
}

data "aws_iam_policy_document" "vpc_flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs"
  role = aws_iam_role.vpc_flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "*"
    }]
  })
}
