variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment tag (dev / staging / prod)."
  type        = string
  default     = "prod"
}

variable "aviatrix_controller_version" {
  description = "Aviatrix controller software version to bootstrap (e.g. '7.1')."
  type        = string
  default     = "7.1"
}

variable "aviatrix_admin_password" {
  description = "Initial admin password for the Aviatrix controller. Must be changed after first login."
  type        = string
  sensitive   = true
}

variable "aviatrix_customer_id" {
  description = "Aviatrix customer ID (license) — from your Aviatrix account portal."
  type        = string
  sensitive   = true
}

variable "aviatrix_aws_account_name" {
  description = "Logical name for the AWS account as registered in the Aviatrix controller."
  type        = string
  default     = "aws-primary"
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "transit_vpc_cidr" {
  description = "CIDR block for the transit VPC."
  type        = string
  default     = "10.0.0.0/23"
}

variable "spoke_pipeline_vpc_cidr" {
  description = "CIDR block for the pipeline spoke VPC."
  type        = string
  default     = "10.1.0.0/24"
}

variable "spoke_opencti_vpc_cidr" {
  description = "CIDR block for the OpenCTI spoke VPC. Only used when opencti_deploy = true."
  type        = string
  default     = "10.2.0.0/24"
}

variable "transit_gw_size" {
  description = "EC2 instance type for the Aviatrix Transit Gateway."
  type        = string
  default     = "c5.xlarge"
}

variable "spoke_gw_size" {
  description = "EC2 instance type for the Aviatrix Spoke Gateways (pipeline and OpenCTI)."
  type        = string
  default     = "t3.small"
}

variable "controller_instance_type" {
  description = "EC2 instance type for the Aviatrix Controller."
  type        = string
  default     = "t3.large"
}

variable "pipeline_instance_type" {
  description = "EC2 instance type for the pipeline host."
  type        = string
  default     = "t3.medium"
}

# ── FQDN egress allowlist ─────────────────────────────────────────────────────

variable "fqdn_egress_domains" {
  description = "Domains the pipeline is permitted to reach through the transit gateway FQDN filter."
  type        = list(string)
  default = [
    # Threat intel RSS / API sources
    "feeds.feedburner.com",
    "www.bleepingcomputer.com",
    "therecord.media",
    "isc.sans.edu",
    "www.cisa.gov",
    "nvd.nist.gov",
    "crt.sh",
    "rdap.org",
    "ipapi.co",
    # OpenCTI (BYO — add your instance FQDN if not using opencti_deploy)
    # "opencti.example.com",
    # Splunk Cloud (add your instance FQDN here)
    # "your-instance.splunkcloud.com",
    # Slack API
    "slack.com",
    "api.slack.com",
    # AWS services (S3 + SSM)
    "s3.amazonaws.com",
    "*.s3.amazonaws.com",
    "ssm.us-east-1.amazonaws.com",
    "ssmmessages.us-east-1.amazonaws.com",
    "ec2messages.us-east-1.amazonaws.com",
    # Docker Hub (only needed when opencti_deploy = true)
    # "registry-1.docker.io",
    # "auth.docker.io",
    # "production.cloudflare.docker.com",
    # Elastic container registry (only needed when opencti_deploy = true)
    # "docker.elastic.co",
  ]
}

# ── Pipeline config ───────────────────────────────────────────────────────────

variable "pipeline_source" {
  description = <<-EOT
    Threat intel source for the pipeline. Leave empty ("") to auto-select based
    on OpenCTI configuration: "opencti" when opencti_deploy = true or opencti_url
    is set, otherwise "rss".

    Valid values: rss, opencti, slack, splunk, stix, or "" (auto).
  EOT
  type        = string
  default     = ""

  validation {
    condition     = contains(["rss", "opencti", "slack", "splunk", "stix", ""], var.pipeline_source)
    error_message = "pipeline_source must be one of: rss, opencti, slack, splunk, stix, or empty string for auto."
  }
}

variable "pipeline_schedule" {
  description = "Cron expression (UTC) for the pipeline EventBridge rule."
  type        = string
  default     = "cron(0 6 * * ? *)"
}

variable "pipeline_git_ref" {
  description = "Git ref (branch, tag, or SHA) to checkout after clone. Pin to a tag for production."
  type        = string
  default     = "main"
}

variable "pipeline_env_vars" {
  description = "Additional env vars injected into the pipeline EC2 via SSM Parameter Store paths. Map of VAR_NAME => SSM path."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "data_bucket_name" {
  description = "S3 bucket name for pipeline output (threat-watch-data.json + HTML). Must be globally unique."
  type        = string
}

variable "key_pair_name" {
  description = "EC2 key pair name for emergency SSH access (optional — SSM Session Manager is preferred)."
  type        = string
  default     = ""
}

# ── OpenCTI — three deployment modes ─────────────────────────────────────────
#
# Mode 1 — Pipeline only (default)
#   opencti_deploy = false, opencti_url = ""
#   Use pipeline_source = "rss" / "stix" / "splunk" / "slack"
#
# Mode 2 — BYO OpenCTI
#   opencti_deploy = false
#   opencti_url    = "https://opencti.yourorg.com/graphql"
#   opencti_token_ssm = "/threat-intel/prod/opencti_token"
#   pipeline_source is auto-set to "opencti"
#
# Mode 3 — Full-stack (Terraform deploys OpenCTI on its own spoke)
#   opencti_deploy = true
#   Supply opencti_admin_password_ssm and opencti_admin_token_ssm
#   Everything else auto-wires

variable "opencti_deploy" {
  description = "When true, Terraform deploys a full OpenCTI stack on a dedicated spoke VPC (Mode 3). False = pipeline-only or BYO (Modes 1 and 2)."
  type        = bool
  default     = false
}

variable "opencti_url" {
  description = "OpenCTI GraphQL URL for BYO mode (Mode 2). Example: https://opencti.yourorg.com/graphql. Leave empty when opencti_deploy = true (URL is derived automatically)."
  type        = string
  default     = ""
}

variable "opencti_token_ssm" {
  description = "SSM parameter path holding the OpenCTI API token for BYO mode. Example: /threat-intel/prod/opencti_token. Leave empty when opencti_deploy = true (the token SSM path is passed directly to the OpenCTI EC2)."
  type        = string
  default     = ""
}

variable "opencti_instance_type" {
  description = "EC2 instance type for the OpenCTI EC2 (full-stack mode). t3.xlarge is the minimum: OpenCTI + Elasticsearch + Redis + RabbitMQ + MinIO all run here."
  type        = string
  default     = "t3.xlarge"
}

variable "opencti_version" {
  description = "OpenCTI platform Docker image tag."
  type        = string
  default     = "6.2.18"
}

variable "opencti_port" {
  description = "Port OpenCTI listens on in full-stack mode."
  type        = number
  default     = 8080
}

variable "opencti_admin_email" {
  description = "Admin email for the OpenCTI instance created in full-stack mode."
  type        = string
  default     = "admin@opencti.io"
}

variable "opencti_admin_password_ssm" {
  description = "SSM parameter path for the OpenCTI admin password (full-stack mode). Required when opencti_deploy = true."
  type        = string
  default     = ""
}

variable "opencti_admin_token_ssm" {
  description = "SSM parameter path for the OpenCTI admin API token (must be a UUID). Required when opencti_deploy = true."
  type        = string
  default     = ""
}

variable "opencti_data_volume_size" {
  description = "EBS data volume size (GiB) for OpenCTI in full-stack mode. Holds Elasticsearch indices and MinIO objects."
  type        = number
  default     = 100
}
