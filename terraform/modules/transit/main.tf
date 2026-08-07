# ── Transit VPC ───────────────────────────────────────────────────────────────
# Aviatrix creates and manages the VPC internals via aviatrix_transit_gateway;
# we only need to declare the VPC here for tagging / referencing from the spoke.

resource "aviatrix_vpc" "transit" {
  cloud_type           = 1 # AWS
  account_name         = var.account_name
  region               = var.aws_region
  name                 = "${var.name_prefix}-transit"
  cidr                 = var.vpc_cidr
  aviatrix_transit_vpc = true
  aviatrix_firenet_vpc = false
}

# ── Transit Gateway + HA pair ─────────────────────────────────────────────────

resource "aviatrix_transit_gateway" "this" {
  cloud_type               = 1
  account_name             = var.account_name
  gw_name                  = "${var.name_prefix}-transit-gw"
  vpc_id                   = aviatrix_vpc.transit.vpc_id
  vpc_reg                  = var.aws_region
  gw_size                  = var.gw_size
  subnet                   = aviatrix_vpc.transit.subnets[0].cidr
  ha_subnet                = aviatrix_vpc.transit.subnets[2].cidr
  ha_gw_size               = var.gw_size
  enable_active_mesh       = true
  enable_hybrid_connection = false
  connected_transit        = true

  # Enable FQDN egress so the gateway can enforce the domain allowlist
  enable_egress_transit_firenet = false
  single_ip_snat                = false

  tags = { Name = "${var.name_prefix}-transit-gw" }
}

# ── FQDN egress filter ────────────────────────────────────────────────────────
# Allows the pipeline spoke to reach only the listed threat intel source domains.
# Any other outbound traffic is dropped at the transit gateway.

resource "aviatrix_fqdn" "egress" {
  fqdn_tag     = "${var.name_prefix}-egress-allowlist"
  fqdn_enabled = true
  fqdn_mode    = "white" # allowlist mode

  gw_filter_tag_list {
    gw_name           = aviatrix_transit_gateway.this.gw_name
    destination_cidrs = []
  }

  dynamic "domain_names" {
    for_each = var.fqdn_egress_domains
    content {
      fqdn   = domain_names.value
      proto  = "tcp"
      port   = "443"
      action = "Allow"
    }
  }

  # Allow HTTP for package/yum mirrors during bootstrap
  dynamic "domain_names" {
    for_each = var.fqdn_egress_domains
    content {
      fqdn   = domain_names.value
      proto  = "tcp"
      port   = "80"
      action = "Allow"
    }
  }
}
