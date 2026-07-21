output "gateway_name" {
  value = aviatrix_transit_gateway.this.gw_name
}

output "vpc_id" {
  value = aviatrix_vpc.transit.vpc_id
}

output "fqdn_tag" {
  value = aviatrix_fqdn.egress.fqdn_tag
}
