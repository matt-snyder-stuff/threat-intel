# ── Controller VPC (dedicated /28 — controller needs nothing else) ────────────

resource "aws_vpc" "controller" {
  cidr_block           = "10.255.0.0/28"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-controller-vpc" }
}

resource "aws_internet_gateway" "controller" {
  vpc_id = aws_vpc.controller.id
  tags   = { Name = "${var.name_prefix}-controller-igw" }
}

resource "aws_subnet" "controller" {
  vpc_id                  = aws_vpc.controller.id
  cidr_block              = "10.255.0.0/28"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-controller-subnet" }
}

resource "aws_route_table" "controller" {
  vpc_id = aws_vpc.controller.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.controller.id
  }

  tags = { Name = "${var.name_prefix}-controller-rt" }
}

resource "aws_route_table_association" "controller" {
  subnet_id      = aws_subnet.controller.id
  route_table_id = aws_route_table.controller.id
}

# ── Elastic IP ────────────────────────────────────────────────────────────────

resource "aws_eip" "controller" {
  domain = "vpc"
  tags   = { Name = "${var.name_prefix}-controller-eip" }
}

resource "aws_eip_association" "controller" {
  instance_id   = aws_instance.controller.id
  allocation_id = aws_eip.controller.id
}

# ── Security group ────────────────────────────────────────────────────────────
# HTTPS from your admin CIDR + inter-gateway communication.
# Update admin_cidr in variables to restrict controller UI access.

resource "aws_security_group" "controller" {
  name        = "${var.name_prefix}-controller-sg"
  description = "Aviatrix Controller — HTTPS admin access + gateway comms"
  vpc_id      = aws_vpc.controller.id

  ingress {
    description = "HTTPS admin UI"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  ingress {
    description = "Gateway keepalive (UDP)"
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "NAT-T (UDP)"
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-controller-sg" }
}

# ── IAM role the controller assumes to manage gateways ───────────────────────

resource "aws_iam_role" "aviatrix_gateway" {
  name = "${var.name_prefix}-aviatrix-gateway-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = { Name = "${var.name_prefix}-aviatrix-gateway-role" }
}

resource "aws_iam_role_policy" "aviatrix_gateway" {
  name = "${var.name_prefix}-aviatrix-gateway-policy"
  role = aws_iam_role.aviatrix_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Aviatrix requires broad EC2/VPC permissions to manage gateways.
        # Scope by resource tags in production if your security team requires it.
        Sid    = "AviatrixGatewayManagement"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:CreateVpc", "ec2:DeleteVpc",
          "ec2:CreateSubnet", "ec2:DeleteSubnet",
          "ec2:CreateInternetGateway", "ec2:AttachInternetGateway", "ec2:DeleteInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ReplaceRoute",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress", "ec2:RevokeSecurityGroupEgress",
          "ec2:RunInstances", "ec2:TerminateInstances", "ec2:StopInstances", "ec2:StartInstances",
          "ec2:CreateKeyPair", "ec2:DeleteKeyPair", "ec2:ImportKeyPair",
          "ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress",
          "ec2:CreateTags", "ec2:DeleteTags",
          "ec2:ModifyInstanceAttribute", "ec2:ModifySubnetAttribute", "ec2:ModifyVpcAttribute",
          "ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface", "ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface",
          "ec2:CreateVpcPeeringConnection", "ec2:AcceptVpcPeeringConnection", "ec2:DeleteVpcPeeringConnection",
          "ec2:CreateTransitGateway*", "ec2:DeleteTransitGateway*", "ec2:AttachTransitGateway*", "ec2:AssociateTransitGateway*",
        ]
        Resource = "*"
      },
      {
        Sid    = "AviatrixIAMPassRole"
        Effect = "Allow"
        Action = ["iam:PassRole", "iam:GetRole"]
        Resource = aws_iam_role.aviatrix_gateway.arn
      },
      {
        Sid    = "AviatrixSTS"
        Effect = "Allow"
        Action = ["sts:AssumeRole"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "aviatrix_gateway" {
  name = "${var.name_prefix}-aviatrix-gateway-profile"
  role = aws_iam_role.aviatrix_gateway.name
}

# ── Controller AMI lookup ─────────────────────────────────────────────────────

data "aws_ami" "aviatrix_controller" {
  most_recent = true
  owners      = ["679593333241"]  # Aviatrix Systems AWS Marketplace account

  filter {
    name   = "name"
    values = ["aviatrix-controller-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ── Controller EC2 instance ───────────────────────────────────────────────────

resource "aws_instance" "controller" {
  ami                    = data.aws_ami.aviatrix_controller.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.controller.id
  vpc_security_group_ids = [aws_security_group.controller.id]
  iam_instance_profile   = aws_iam_instance_profile.aviatrix_gateway.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 64
    encrypted             = true
    delete_on_termination = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    admin_password     = var.admin_password
    customer_id        = var.customer_id
    controller_version = var.controller_version
  }))

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  tags = { Name = "${var.name_prefix}-aviatrix-controller" }

  lifecycle {
    ignore_changes = [ami]
  }
}

# ── CloudWatch alarms ─────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "controller_cpu" {
  alarm_name          = "${var.name_prefix}-controller-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Aviatrix controller CPU > 80% for 10 minutes"

  dimensions = {
    InstanceId = aws_instance.controller.id
  }
}

resource "aws_cloudwatch_metric_alarm" "controller_status" {
  alarm_name          = "${var.name_prefix}-controller-status-check"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Aviatrix controller EC2 status check failed"

  dimensions = {
    InstanceId = aws_instance.controller.id
  }
}

data "aws_caller_identity" "current" {}
