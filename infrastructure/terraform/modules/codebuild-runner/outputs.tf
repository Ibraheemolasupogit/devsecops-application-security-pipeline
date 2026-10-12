output "project_name" { value = aws_codebuild_project.runner.name }
output "security_group_id" { value = aws_security_group.runner.id }
output "service_role_arn" { value = aws_iam_role.service.arn }
