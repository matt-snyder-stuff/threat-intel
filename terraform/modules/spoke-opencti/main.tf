# ── Spoke VPC ─────────────────────────────────────────────────────────────────

resource "aviatrix_vpc" "opencti" {
  cloud_type   = 1
  account_name = var.account_name
  region       = var.aws_region
  name         = "${var.name_prefix}-spoke-opencti"
  cidr         = var.vpc_cidr
}

# ── Spoke Gateway ─────────────────────────────────────────────────────────────

resource "aviatrix_spoke_gateway" "opencti" {
  cloud_type                        = 1
  account_name                      = var.account_name
  gw_name                           = "${var.name_prefix}-spoke-opencti-gw"
  vpc_id                            = aviatrix_vpc.opencti.vpc_id
  vpc_reg                           = var.aws_region
  gw_size                           = var.gw_size
  subnet                            = aviatrix_vpc.opencti.subnets[0].cidr
  enable_active_mesh                = true
  manage_transit_gateway_attachment = false

  tags = { Name = "${var.name_prefix}-spoke-opencti-gw" }
}

resource "aviatrix_spoke_transit_attachment" "opencti" {
  spoke_gw_name   = aviatrix_spoke_gateway.opencti.gw_name
  transit_gw_name = var.transit_gw_name
}

# ── IAM role ──────────────────────────────────────────────────────────────────

resource "aws_iam_role" "opencti" {
  name = "${var.name_prefix}-opencti-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.opencti.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "opencti_ssm_secrets" {
  name = "${var.name_prefix}-opencti-ssm-secrets"
  role = aws_iam_role.opencti.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOpenCTISecrets"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:*:parameter${var.opencti_admin_password_ssm}",
          "arn:aws:ssm:${var.aws_region}:*:parameter${var.opencti_admin_token_ssm}",
        ]
      },
      {
        Sid      = "DecryptSSMSecrets"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = { "kms:ViaService" = "ssm.${var.aws_region}.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "opencti" {
  name = "${var.name_prefix}-opencti-profile"
  role = aws_iam_role.opencti.name
}

# ── Security group ────────────────────────────────────────────────────────────
# No public inbound. The pipeline EC2 (and VPN users) reach port 8080 via the
# Aviatrix spoke-to-spoke path through the transit GW.

resource "aws_security_group" "opencti" {
  name        = "${var.name_prefix}-opencti-sg"
  description = "OpenCTI — inbound only from spoke-pipeline CIDR via Aviatrix transit"
  vpc_id      = aviatrix_vpc.opencti.vpc_id

  ingress {
    description = "OpenCTI UI and API from pipeline spoke"
    from_port   = var.opencti_port
    to_port     = var.opencti_port
    protocol    = "tcp"
    cidr_blocks = [var.pipeline_spoke_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Controlled by Aviatrix FQDN filter on transit GW"
  }

  tags = { Name = "${var.name_prefix}-opencti-sg" }
}

# ── Data volume ───────────────────────────────────────────────────────────────

resource "aws_ebs_volume" "opencti_data" {
  availability_zone = data.aws_subnet.opencti.availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  encrypted         = true

  tags = { Name = "${var.name_prefix}-opencti-data" }

  lifecycle {
    prevent_destroy = true
  }
}

data "aws_subnet" "opencti" {
  id = aviatrix_vpc.opencti.subnets[0].subnet_id
}

# ── EC2 instance ──────────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "opencti" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aviatrix_vpc.opencti.subnets[0].subnet_id
  vpc_security_group_ids = [aws_security_group.opencti.id]
  iam_instance_profile   = aws_iam_instance_profile.opencti.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    aws_region                 = var.aws_region
    opencti_version            = var.opencti_version
    opencti_port               = var.opencti_port
    opencti_admin_email        = var.opencti_admin_email
    opencti_admin_password_ssm = var.opencti_admin_password_ssm
    opencti_admin_token_ssm    = var.opencti_admin_token_ssm
  }))

  tags = { Name = "${var.name_prefix}-opencti" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  depends_on = [aviatrix_spoke_transit_attachment.opencti]
}

resource "aws_volume_attachment" "opencti_data" {
  device_name  = "/dev/xvdf"
  volume_id    = aws_ebs_volume.opencti_data.id
  instance_id  = aws_instance.opencti.id
  force_detach = false
}

# ── CloudWatch log group ──────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "opencti" {
  name              = "/threat-intel/${var.name_prefix}/opencti"
  retention_in_days = 30
}
