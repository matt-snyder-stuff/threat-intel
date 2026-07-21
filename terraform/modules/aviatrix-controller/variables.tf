variable "name_prefix" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.large"
}

variable "key_pair_name" {
  type    = string
  default = ""
}

variable "admin_password" {
  type      = string
  sensitive = true
}

variable "customer_id" {
  type      = string
  sensitive = true
}

variable "controller_version" {
  type    = string
  default = "7.1"
}

variable "admin_cidr_blocks" {
  description = "Required. CIDRs allowed to reach the controller HTTPS UI — provide your office or VPN CIDR (e.g. [\"203.0.113.0/24\"]). Do not use 0.0.0.0/0 in production."
  type        = list(string)
}
