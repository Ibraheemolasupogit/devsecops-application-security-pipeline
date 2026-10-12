resource "aws_iam_openid_connect_provider" "github" {
  count          = var.existing_provider_arn == null ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  tags           = var.tags
}
