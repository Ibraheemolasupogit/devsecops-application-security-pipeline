mock_provider "aws" {
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_resource "aws_kms_key" { defaults = { arn = "arn:aws:kms:eu-west-2:000000000000:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" } }
  mock_resource "aws_iam_role" { defaults = { arn = "arn:aws:iam::000000000000:role/mock-role" } }
  mock_resource "aws_cloudwatch_log_group" { defaults = { arn = "arn:aws:logs:eu-west-2:000000000000:log-group:mock-log" } }
  mock_data "aws_caller_identity" { defaults = { account_id = "000000000000" } }
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}
variables {
  name               = "mock-network"
  region             = "eu-west-2"
  vpc_cidr           = "10.20.0.0/16"
  availability_zones = ["eu-west-2a", "eu-west-2b"]
  nat_strategy       = "single"
  flow_log_role_arn  = "arn:aws:iam::000000000000:role/test-flow"
  flow_log_group_arn = "arn:aws:logs:eu-west-2:000000000000:log-group:test"
  tags               = { Environment = "mock", ManagedBy = "Terraform" }
}
run "cost_conscious_private_network" {
  command = plan
  assert {
    condition     = length(aws_nat_gateway.this) == 1 && length(aws_subnet.private) == 2 && alltrue([for subnet in aws_subnet.private : !subnet.map_public_ip_on_launch && subnet.tags["kubernetes.io/role/internal-elb"] == "1"])
    error_message = "Nonprod must have private LB-discoverable subnets and one NAT."
  }
  assert {
    condition     = toset(keys(aws_vpc_endpoint.gateway)) == toset(["s3", "dynamodb"]) && aws_flow_log.this.traffic_type == "ALL"
    error_message = "Gateway endpoints and all-traffic flow logs are required."
  }
}
run "production_az_egress" {
  command = plan
  variables { nat_strategy = "per_az" }
  assert {
    condition     = length(aws_nat_gateway.this) == length(var.availability_zones)
    error_message = "Per-AZ strategy must avoid cross-AZ NAT dependency."
  }
}
run "reject_unverified_nat_free" {
  command = plan
  variables { nat_strategy = "none" }
  expect_failures = [aws_vpc.this]
}
