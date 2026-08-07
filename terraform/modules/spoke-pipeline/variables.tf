variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "account_name" { type = string }
variable "vpc_cidr" { type = string }
variable "transit_gw_name" { type = string }
variable "data_bucket_name" { type = string }

variable "gw_size" {
  type    = string
  default = "t3.small"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "key_pair_name" {
  type    = string
  default = ""
}

variable "pipeline_source" {
  type    = string
  default = "rss"
}

variable "pipeline_schedule" {
  type    = string
  default = "cron(0 6 * * ? *)"
}

variable "pipeline_git_ref" {
  type        = string
  default     = "main"
  description = "Git ref (branch, tag, or SHA) to checkout after clone. Pin to a tag for production."
}

variable "pipeline_env_ssm" {
  description = "Map of ENV_VAR_NAME => SSM parameter path for pipeline secrets."
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "opencti_url" {
  description = "OpenCTI GraphQL URL to inject as OPENCTI_URL into the pipeline env file. Empty = not set."
  type        = string
  default     = ""
}
