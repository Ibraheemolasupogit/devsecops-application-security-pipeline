data "aws_partition" "current" {}
resource "aws_eks_cluster" "this" {
  #checkov:skip=CKV_AWS_339:Checkov 3.2.281 predates EKS 1.36. AWS publishes EKS standard-support lifecycle separately; default 1.36 and STANDARD support policy are tested. Refresh scanner/version and verify current regional EKS lifecycle before deployment.
  bootstrap_self_managed_addons = false
  name                          = var.name
  version                       = var.kubernetes_version
  role_arn                      = var.cluster_role_arn
  deletion_protection           = var.deletion_protection
  enabled_cluster_log_types     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }
  upgrade_policy {
    support_type = "STANDARD"
  }
  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }
  encryption_config {
    resources = ["secrets"]
    provider { key_arn = var.kms_key_arn }
  }
  tags = var.tags
  lifecycle {
    precondition {
      condition     = length(var.administrator_role_arns) > 0
      error_message = "Explicit platform administrator role ARNs are required; creator administrator access is disabled."
    }
  }
}
resource "aws_eks_access_entry" "administrator" {
  for_each      = var.administrator_role_arns
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
  tags          = var.tags
}
resource "aws_eks_access_policy_association" "administrator" {
  for_each      = var.administrator_role_arns
  cluster_name  = aws_eks_cluster.this.name
  principal_arn = aws_eks_access_entry.administrator[each.key].principal_arn
  policy_arn    = "arn:${data.aws_partition.current.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}
resource "aws_security_group" "nodes" {
  name        = "${var.name}-private-nodes"
  description = "Private nodes: cluster and node traffic only"
  vpc_id      = var.vpc_id
  ingress {
    description = "Node to node CNI and DNS traffic"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    self        = true
  }
  ingress {
    description     = "Control plane to kubelet"
    protocol        = "tcp"
    from_port       = 10250
    to_port         = 10250
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }
  ingress {
    description     = "Control plane to admission webhooks"
    protocol        = "tcp"
    from_port       = 443
    to_port         = 443
    security_groups = [aws_eks_cluster.this.vpc_config[0].cluster_security_group_id]
  }
  egress {
    #checkov:skip=CKV_AWS_382:Private node bootstrap/CNI/Pod Identity and external dependencies require outbound access through NAT; no public node ingress. Egress policies are a later tested runtime boundary.
    description = "Private node outbound via NAT and gateway endpoints"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = var.tags
}
resource "aws_launch_template" "nodes" {
  name_prefix            = "${var.name}-"
  vpc_security_group_ids = [aws_security_group.nodes.id]
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }
  tag_specifications {
    resource_type = "instance"
    tags          = var.tags
  }
  tag_specifications {
    resource_type = "volume"
    tags          = var.tags
  }
  tags = var.tags
}
resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "general"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.subnet_ids
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = var.instance_types
  capacity_type   = "ON_DEMAND"
  launch_template {
    id      = aws_launch_template.nodes.id
    version = aws_launch_template.nodes.latest_version
  }
  scaling_config {
    min_size     = var.capacity.min
    desired_size = var.capacity.desired
    max_size     = var.capacity.max
  }
  update_config { max_unavailable = 1 }
  tags       = var.tags
  depends_on = [aws_eks_addon.before_nodes, aws_eks_pod_identity_association.cni, aws_vpc_security_group_ingress_rule.nodes_to_api]
  lifecycle {
    precondition {
      condition     = var.capacity.min >= 1 && var.capacity.min <= var.capacity.desired && var.capacity.desired <= var.capacity.max
      error_message = "Capacity must satisfy 1 <= min <= desired <= max."
    }
  }
}
resource "aws_eks_addon" "before_nodes" {
  for_each                    = { for name, version in var.addon_versions : name => version if name != "coredns" }
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = each.value
  resolve_conflicts_on_update = "PRESERVE"
  configuration_values        = each.key == "vpc-cni" ? jsonencode({ enableNetworkPolicy = "true" }) : null
  tags                        = var.tags
}
resource "aws_eks_pod_identity_association" "cni" {
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "aws-node"
  role_arn        = var.cni_role_arn
  tags            = var.tags
  depends_on      = [aws_eks_addon.before_nodes]
}
resource "aws_eks_addon" "dns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  addon_version               = lookup(var.addon_versions, "coredns", null)
  resolve_conflicts_on_update = "PRESERVE"
  tags                        = var.tags
  depends_on                  = [aws_eks_node_group.general]
}

resource "aws_vpc_security_group_ingress_rule" "nodes_to_api" {
  security_group_id            = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.nodes.id
  description                  = "Private nodes to API endpoint"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  tags                         = var.tags
}

resource "aws_vpc_security_group_ingress_rule" "operators_to_api" {
  for_each                     = var.api_client_security_group_ids
  security_group_id            = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = each.value
  description                  = "Controlled operator/runner to private API"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  tags                         = var.tags
}
