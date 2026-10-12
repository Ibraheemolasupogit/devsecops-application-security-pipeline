resource "aws_cloudwatch_log_group" "control_plane" {
  #checkov:skip=CKV_AWS_338:Portfolio operational control-plane logs use 14-day nonprod/90-day prod retention, distinct from long-lived release/audit evidence; documented budget/retention decision in eks-cost-controls.md.
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}
resource "aws_cloudwatch_log_group" "flow" {
  #checkov:skip=CKV_AWS_338:Portfolio network diagnostic logs use 14-day nonprod/90-day prod retention; not the canonical security-evidence archive. Review regulatory retention before actual deployment.
  name              = "/aws/vpc/${var.name}/flow"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}
resource "aws_iam_role" "flow" {
  name = "${var.name}-flow-logs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "vpc-flow-logs.amazonaws.com" } }]
  })
  tags = var.tags
}
resource "aws_iam_role_policy" "flow" {
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"], Resource = "${aws_cloudwatch_log_group.flow.arn}:*" }]
  })
}
