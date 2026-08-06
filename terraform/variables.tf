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

variable "transit_gw_size" {
  description = "EC2 instance type for the Aviatrix Transit Gateway."
  type        = string
  default     = "c5.xlarge"
}

variable "spoke_gw_size" {
  description = "EC2 instance type for the Aviatrix Spoke Gateway."
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
    # OpenCTI (add your instance FQDN here)
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
  ]
}

# ── Pipeline config ───────────────────────────────────────────────────────────

variable "pipeline_source" {
  description = "Default threat intel source for the pipeline (rss / opencti / slack / splunk)."
  type        = string
  default     = "rss"

  validation {
    condition     = contains(["rss", "opencti", "slack", "splunk", "stix"], var.pipeline_source)
    error_message = "pipeline_source must be one of: rss, opencti, slack, splunk, stix."
  }
}

variable "pipeline_schedule" {
  description = "Cron expression (UTC) for the pipeline EventBridge rule."
  type        = string
  default     = "cron(0 6 * * ? *)"
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
