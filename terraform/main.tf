locals {
  name_prefix = "threat-intel-${var.environment}"

  # Resolve which OpenCTI URL the pipeline should use.
  # Priority: deployed spoke > BYO URL > empty (pipeline runs rss/stix/splunk/slack)
  opencti_url = (
    var.opencti_deploy
    ? "http://${module.spoke_opencti[0].instance_private_ip}:${var.opencti_port}/graphql"
    : var.opencti_url
  )

  # The pipeline source defaults to "opencti" when any OpenCTI is configured,
  # unless the caller has explicitly set pipeline_source to something else.
  effective_pipeline_source = (
    var.pipeline_source != "" ? var.pipeline_source :
    local.opencti_url != "" ? "opencti" : "rss"
  )
}

# ── Aviatrix Controller ───────────────────────────────────────────────────────

module "aviatrix_controller" {
  source = "./modules/aviatrix-controller"

  name_prefix        = local.name_prefix
  aws_region         = var.aws_region
  instance_type      = var.controller_instance_type
  key_pair_name      = var.key_pair_name
  admin_password     = var.aviatrix_admin_password
  customer_id        = var.aviatrix_customer_id
  controller_version = var.aviatrix_controller_version
  admin_cidr_blocks  = var.admin_cidr_blocks
}

# ── Onboard the AWS account into the controller ───────────────────────────────

resource "aviatrix_account" "aws_primary" {
  account_name       = var.aviatrix_aws_account_name
  cloud_type         = 1 # AWS
  aws_account_number = data.aws_caller_identity.current.account_id
  aws_iam            = true
  aws_role_app       = module.aviatrix_controller.gateway_role_arn
  aws_role_ec2       = module.aviatrix_controller.gateway_role_arn

  depends_on = [module.aviatrix_controller]
}

# ── Transit network ───────────────────────────────────────────────────────────

module "transit" {
  source = "./modules/transit"

  name_prefix         = local.name_prefix
  aws_region          = var.aws_region
  account_name        = aviatrix_account.aws_primary.account_name
  vpc_cidr            = var.transit_vpc_cidr
  gw_size             = var.transit_gw_size
  fqdn_egress_domains = var.fqdn_egress_domains

  depends_on = [aviatrix_account.aws_primary]
}

# ── OpenCTI spoke (optional — enabled via opencti_deploy = true) ─────────────

module "spoke_opencti" {
  count  = var.opencti_deploy ? 1 : 0
  source = "./modules/spoke-opencti"

  name_prefix                = local.name_prefix
  aws_region                 = var.aws_region
  account_name               = aviatrix_account.aws_primary.account_name
  vpc_cidr                   = var.spoke_opencti_vpc_cidr
  gw_size                    = var.spoke_gw_size
  transit_gw_name            = module.transit.gateway_name
  instance_type              = var.opencti_instance_type
  key_pair_name              = var.key_pair_name
  opencti_version            = var.opencti_version
  opencti_port               = var.opencti_port
  opencti_admin_email        = var.opencti_admin_email
  opencti_admin_password_ssm = var.opencti_admin_password_ssm
  opencti_admin_token_ssm    = var.opencti_admin_token_ssm
  pipeline_spoke_cidr        = var.spoke_pipeline_vpc_cidr
  data_volume_size           = var.opencti_data_volume_size

  depends_on = [module.transit]
}

# ── Pipeline spoke ────────────────────────────────────────────────────────────

module "spoke_pipeline" {
  source = "./modules/spoke-pipeline"

  name_prefix       = local.name_prefix
  aws_region        = var.aws_region
  account_name      = aviatrix_account.aws_primary.account_name
  vpc_cidr          = var.spoke_pipeline_vpc_cidr
  gw_size           = var.spoke_gw_size
  transit_gw_name   = module.transit.gateway_name
  instance_type     = var.pipeline_instance_type
  key_pair_name     = var.key_pair_name
  data_bucket_name  = var.data_bucket_name
  pipeline_source   = local.effective_pipeline_source
  pipeline_schedule = var.pipeline_schedule
  pipeline_git_ref  = var.pipeline_git_ref
  opencti_url       = local.opencti_url
  alarm_sns_arn     = var.alarm_sns_arn

  pipeline_env_ssm = merge(
    var.pipeline_env_vars,
    # When BYO OpenCTI, inject the token from SSM. The URL goes via opencti_url (plain env var).
    var.opencti_token_ssm != "" ? {
      OPENCTI_TOKEN = var.opencti_token_ssm
    } : {},
  )

  depends_on = [module.transit, module.spoke_opencti]
}

# ── Data lookup ───────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
