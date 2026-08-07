output "controller_public_ip" {
  description = "Aviatrix controller UI — https://<ip>"
  value       = module.aviatrix_controller.public_ip
}

output "controller_private_ip" {
  description = "Controller private IP (used by the Aviatrix provider)."
  value       = module.aviatrix_controller.private_ip
}

output "transit_gateway_name" {
  description = "Aviatrix Transit Gateway name."
  value       = module.transit.gateway_name
}

output "pipeline_instance_id" {
  description = "EC2 instance ID for the pipeline host. Access via SSM Session Manager."
  value       = module.spoke_pipeline.instance_id
}

output "pipeline_instance_private_ip" {
  description = "Pipeline EC2 private IP."
  value       = module.spoke_pipeline.instance_private_ip
}

output "data_bucket" {
  description = "S3 bucket where the pipeline writes threat-watch-data.json and the HTML dashboard."
  value       = module.spoke_pipeline.data_bucket
}

output "data_bucket_url" {
  description = "Set this as THREAT_WATCH_URL in .env so agents and digest consumers can read the dataset."
  value       = "https://${module.spoke_pipeline.data_bucket}.s3.amazonaws.com/threat-watch-data.json"
}

output "ssm_connect_pipeline" {
  description = "Command to open a shell on the pipeline EC2 via SSM (no SSH key needed)."
  value       = "aws ssm start-session --target ${module.spoke_pipeline.instance_id} --region ${var.aws_region}"
}

output "pipeline_source_effective" {
  description = "Resolved pipeline source (rss / opencti / slack / splunk / stix) after auto-selection."
  value       = local.effective_pipeline_source
}

# ── OpenCTI outputs (full-stack mode only) ────────────────────────────────────

output "opencti_instance_id" {
  description = "OpenCTI EC2 instance ID (full-stack mode). Empty when opencti_deploy = false."
  value       = var.opencti_deploy ? module.spoke_opencti[0].instance_id : ""
}

output "opencti_url" {
  description = "OpenCTI URL reachable from within the Aviatrix network. Empty when not deployed or BYO."
  value       = local.opencti_url
}

output "opencti_graphql_url" {
  description = "OpenCTI GraphQL endpoint used by the pipeline. Empty when opencti is not configured."
  value       = local.opencti_url
}

output "ssm_connect_opencti" {
  description = "Command to open a shell on the OpenCTI EC2 via SSM (full-stack mode only)."
  value       = var.opencti_deploy ? module.spoke_opencti[0].ssm_connect_command : ""
}

output "opencti_data_volume_id" {
  description = "EBS volume ID for OpenCTI data. Back this up before terraform destroy (full-stack mode only)."
  value       = var.opencti_deploy ? module.spoke_opencti[0].data_volume_id : ""
}
