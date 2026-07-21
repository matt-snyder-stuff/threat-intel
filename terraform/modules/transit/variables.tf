variable "name_prefix"         { type = string }
variable "aws_region"          { type = string }
variable "account_name"        { type = string }
variable "vpc_cidr"            { type = string }
variable "gw_size"             { type = string; default = "c5.xlarge" }
variable "fqdn_egress_domains" { type = list(string) }
