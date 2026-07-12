output "task_execution_role_arn" {
  value = aws_iam_role.task_execution.arn
}
output "task_execution_role_name" {
  value = aws_iam_role.task_execution.name
}
output "runtime_role_arn" {
  value = aws_iam_role.runtime.arn
}
output "runtime_role_name" {
  value = aws_iam_role.runtime.name
}
output "deployment_role_arn" {
  value = aws_iam_role.github_actions_deployment.arn
}
output "deployment_role_name" {
  value = aws_iam_role.github_actions_deployment.name
}
output "vpc_flow_log_role_arn" {
  value = aws_iam_role.vpc_flow_logs.arn
}
