mock_provider "aws" {
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = {
      arn            = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
      url            = "https://token.actions.githubusercontent.com"
      client_id_list = ["sts.amazonaws.com"]
    }
  }
}

variables {
  tags                  = { ManagedBy = "Terraform" }
  existing_provider_arn = null
}

run "github_issuer_audience" {
  command = plan
  assert {
    condition     = aws_iam_openid_connect_provider.github[0].url == "https://token.actions.githubusercontent.com"
    error_message = "GitHub issuer and STS audience are required."
  }
}
