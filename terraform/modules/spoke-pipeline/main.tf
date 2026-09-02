# ── Spoke VPC ─────────────────────────────────────────────────────────────────

resource "aviatrix_vpc" "pipeline" {
  cloud_type   = 1
  account_name = var.account_name
  region       = var.aws_region
  name         = "${var.name_prefix}-spoke-pipeline"
  cidr         = var.vpc_cidr
}

# ── Spoke Gateway ─────────────────────────────────────────────────────────────

resource "aviatrix_spoke_gateway" "pipeline" {
  cloud_type   = 1
  account_name = var.account_name
  gw_name      = "${var.name_prefix}-spoke-pipeline-gw"
  vpc_id       = aviatrix_vpc.pipeline.vpc_id
  vpc_reg      = var.aws_region
  gw_size      = var.gw_size
  subnet       = aviatrix_vpc.pipeline.subnets[0].cidr

  tags = { Name = "${var.name_prefix}-spoke-pipeline-gw" }
}

resource "aviatrix_spoke_transit_attachment" "pipeline" {
  spoke_gw_name   = aviatrix_spoke_gateway.pipeline.gw_name
  transit_gw_name = var.transit_gw_name
}

# ── S3 data bucket ────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "data" {
  bucket = var.data_bucket_name
  tags   = { Name = var.data_bucket_name }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-old-builds"
    status = "Enabled"
    filter { prefix = "" }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

# ── IAM role for the pipeline EC2 ────────────────────────────────────────────

resource "aws_iam_role" "pipeline" {
  name = "${var.name_prefix}-pipeline-role"

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
  role       = aws_iam_role.pipeline.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "pipeline_s3" {
  name = "${var.name_prefix}-pipeline-s3"
  role = aws_iam_role.pipeline.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PipelineDataBucket"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:DeleteObject"]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "pipeline_ssm_params" {
  name = "${var.name_prefix}-pipeline-ssm-params"
  role = aws_iam_role.pipeline.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadPipelineSecrets"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
        Resource = length(var.pipeline_env_ssm) > 0 ? [
          for path in values(var.pipeline_env_ssm) :
          "arn:aws:ssm:${var.aws_region}:*:parameter${path}"
        ] : ["arn:aws:ssm:${var.aws_region}:*:parameter/threat-intel/*"]
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

resource "aws_iam_instance_profile" "pipeline" {
  name = "${var.name_prefix}-pipeline-profile"
  role = aws_iam_role.pipeline.name
}

# ── Pipeline EC2 security group ───────────────────────────────────────────────
# No inbound rules — access is exclusively via SSM Session Manager.
# Egress is controlled at the Aviatrix transit GW FQDN filter.

resource "aws_security_group" "pipeline" {
  name        = "${var.name_prefix}-pipeline-sg"
  description = "Pipeline EC2 — no inbound, all egress via Aviatrix transit"
  vpc_id      = aviatrix_vpc.pipeline.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Controlled by Aviatrix FQDN filter on transit GW"
  }

  tags = { Name = "${var.name_prefix}-pipeline-sg" }
}

# ── Pipeline EC2 ──────────────────────────────────────────────────────────────

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

resource "aws_instance" "pipeline" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aviatrix_vpc.pipeline.subnets[0].subnet_id
  vpc_security_group_ids = [aws_security_group.pipeline.id]
  iam_instance_profile   = aws_iam_instance_profile.pipeline.name
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
    data_bucket      = var.data_bucket_name
    pipeline_source  = var.pipeline_source
    pipeline_git_ref = var.pipeline_git_ref
    pipeline_env_ssm = var.pipeline_env_ssm
    aws_region       = var.aws_region
    opencti_url      = var.opencti_url
  }))

  tags = { Name = "${var.name_prefix}-pipeline" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  depends_on = [aviatrix_spoke_transit_attachment.pipeline]
}

# ── EventBridge scheduled run ─────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "pipeline" {
  name                = "${var.name_prefix}-pipeline-schedule"
  description         = "Trigger the threat intel pipeline on schedule"
  schedule_expression = var.pipeline_schedule
}

resource "aws_cloudwatch_event_target" "pipeline" {
  rule     = aws_cloudwatch_event_rule.pipeline.name
  arn      = "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"
  role_arn = aws_iam_role.eventbridge_ssm.arn

  run_command_targets {
    key    = "InstanceIds"
    values = [aws_instance.pipeline.id]
  }

  input = jsonencode({
    commands         = ["/usr/local/bin/run-pipeline.sh"]
    executionTimeout = ["3600"]
  })
}

resource "aws_iam_role" "eventbridge_ssm" {
  name = "${var.name_prefix}-eventbridge-ssm-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_ssm" {
  name = "${var.name_prefix}-eventbridge-ssm-policy"
  role = aws_iam_role.eventbridge_ssm.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["ssm:SendCommand"]
      Resource = [
        "arn:aws:ec2:${var.aws_region}:*:instance/${aws_instance.pipeline.id}",
        "arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"
      ]
    }]
  })
}

# ── CloudWatch log group for pipeline runs ────────────────────────────────────

resource "aws_cloudwatch_log_group" "pipeline" {
  name              = "/threat-intel/${var.name_prefix}/pipeline"
  retention_in_days = 30
}

# ── CloudWatch alarm — EventBridge pipeline failure ───────────────────────────
# SSM Run Command reports FAILED state when the shell script exits non-zero.
# The alarm fires after a single failure so the on-call team is notified before
# the next scheduled run overwrites state.

resource "aws_cloudwatch_metric_alarm" "pipeline_failure" {
  alarm_name          = "${var.name_prefix}-pipeline-failure"
  alarm_description   = "Threat intel pipeline run failed (SSM Run Command reported non-zero exit)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/SSM-RunCommand"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId   = aws_instance.pipeline.id
    DocumentName = "AWS-RunShellScript"
  }

  alarm_actions = var.alarm_sns_arn != "" ? [var.alarm_sns_arn] : []
  ok_actions    = var.alarm_sns_arn != "" ? [var.alarm_sns_arn] : []

  tags = { Name = "${var.name_prefix}-pipeline-failure-alarm" }
}
