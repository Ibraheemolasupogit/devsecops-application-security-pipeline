output "ecs_log_group_name" {
  value = aws_cloudwatch_log_group.ecs.name
}
output "ecs_log_group_arn" {
  value = aws_cloudwatch_log_group.ecs.arn
}
output "vpc_flow_log_group_arn" {
  value = aws_cloudwatch_log_group.vpc_flow.arn
}
