variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "account_name" { type = string }
variable "vpc_cidr" { type = string }

variable "gw_size" {
  type    = string
  default = "t3.small"
}

variable "transit_gw_name" { type = string }

variable "instance_type" {
  type        = string
  default     = "t3.xlarge"
  description = "OpenCTI + Elasticsearch + Redis + RabbitMQ + MinIO all run on this one instance. t3.xlarge (4 vCPU / 16 GB) is the minimum recommended size."
}

variable "key_pair_name" {
  type    = string
  default = ""
}

variable "opencti_version" {
  type        = string
  default     = "6.2.18"
  description = "OpenCTI platform Docker image tag."
}

variable "opencti_admin_email" {
  type        = string
  default     = "admin@opencti.io"
  description = "Admin user email for initial login."
}

variable "opencti_admin_password_ssm" {
  type        = string
  description = "SSM parameter path holding the OpenCTI admin password."
}

variable "opencti_admin_token_ssm" {
  type        = string
  description = "SSM parameter path holding the OpenCTI admin API token (must be a UUID)."
}

variable "opencti_port" {
  type        = number
  default     = 8080
  description = "Host port OpenCTI listens on. Accessible from within the Aviatrix VPN / spoke network."
}

variable "pipeline_spoke_cidr" {
  type        = string
  description = "CIDR of the pipeline spoke VPC. OpenCTI's security group allows inbound from this range."
}

variable "data_volume_size" {
  type        = number
  default     = 100
  description = "EBS volume size (GiB) for OpenCTI data (Elasticsearch indices, MinIO objects). Increase for large intel corpora."
}
