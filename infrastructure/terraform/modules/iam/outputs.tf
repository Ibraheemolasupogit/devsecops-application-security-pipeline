output "cluster_role_arn" {
  value = aws_iam_role.cluster.arn
}
output "node_role_arn" {
  value = aws_iam_role.node.arn
}
output "cni_role_arn" {
  value = aws_iam_role.cni.arn
}
