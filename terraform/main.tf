locals {
  name_prefix = "threat-intel-${var.environment}"
}

# ── Aviatrix Controller ───────────────────────────────────────────────────────

module "aviatrix_controller" {
  source = "./modules/aviatrix-controller"

  name_prefix      = local.name_prefix
  aws_region       = var.aws_region
  instance_type    = var.controller_instance_type
  key_pair_name    = var.key_pair_name
  admin_password   = var.aviatrix_admin_password
  customer_id      = var.aviatrix_customer_id
  controller_version = var.aviatrix_controller_version
}

# ── Onboard the AWS account into the controller ───────────────────────────────
# This runs after the controller bootstrap; it tells the controller which IAM
# role to assume when managing gateways in this account.

resource "aviatrix_account" "aws_primary" {
  account_name       = var.aviatrix_aws_account_name
  cloud_type         = 1  # AWS
  aws_account_number = data.aws_caller_identity.current.account_id
  aws_iam            = true
  aws_role_app       = module.aviatrix_controller.gateway_role_arn
  aws_role_ec2       = module.aviatrix_controller.gateway_role_arn

  depends_on = [module.aviatrix_controller]
}

# ── Transit network ───────────────────────────────────────────────────────────

module "transit" {
  source = "./modules/transit"

  name_prefix          = local.name_prefix
  aws_region           = var.aws_region
  account_name         = aviatrix_account.aws_primary.account_name
  vpc_cidr             = var.transit_vpc_cidr
  gw_size              = var.transit_gw_size
  fqdn_egress_domains  = var.fqdn_egress_domains

  depends_on = [aviatrix_account.aws_primary]
}

# ── Pipeline spoke ────────────────────────────────────────────────────────────

module "spoke_pipeline" {
  source = "./modules/spoke-pipeline"

  name_prefix          = local.name_prefix
  aws_region           = var.aws_region
  account_name         = aviatrix_account.aws_primary.account_name
  vpc_cidr             = var.spoke_pipeline_vpc_cidr
  gw_size              = var.spoke_gw_size
  transit_gw_name      = module.transit.gateway_name
  instance_type        = var.pipeline_instance_type
  key_pair_name        = var.key_pair_name
  data_bucket_name     = var.data_bucket_name
  pipeline_source      = var.pipeline_source
  pipeline_schedule    = var.pipeline_schedule
  pipeline_env_ssm     = var.pipeline_env_vars

  depends_on = [module.transit]
}

# ── Data lookup ───────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
