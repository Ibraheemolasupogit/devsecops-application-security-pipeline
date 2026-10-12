data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [var.subject]
    }
  }
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "permissions" {
  dynamic "statement" {
    for_each = var.role_kind == "publisher" ? [1] : []
    content {
      sid       = "EcrAuthorizationToken"
      actions   = ["ecr:GetAuthorizationToken"]
      resources = ["*"]
      condition {
        test     = "StringEquals"
        variable = "aws:RequestedRegion"
        values   = [var.region]
      }
    }
  }

  dynamic "statement" {
    for_each = var.role_kind == "publisher" ? [1] : []
    content {
      sid = "PublishSingleApplicationRepository"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
      ]
      resources = [var.repository_arn]
    }
  }

  dynamic "statement" {
    for_each = var.role_kind == "deployer" ? [1] : []
    content {
      sid       = "DescribeOnlyTargetCluster"
      actions   = ["eks:DescribeCluster"]
      resources = [var.cluster_arn]
    }
  }
}

resource "aws_iam_role" "github" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags                 = merge(var.tags, { RoleType = "github-oidc-${var.role_kind}" })
}

resource "aws_iam_role_policy" "github" {
  name   = "${var.role_name}-permissions"
  role   = aws_iam_role.github.id
  policy = data.aws_iam_policy_document.permissions.json
}
