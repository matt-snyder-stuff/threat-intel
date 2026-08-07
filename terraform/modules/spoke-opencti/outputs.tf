output "instance_id" {
  description = "OpenCTI EC2 instance ID (access via SSM Session Manager)."
  value       = aws_instance.opencti.id
}

output "instance_private_ip" {
  description = "Private IP of the OpenCTI EC2. Use this to build OPENCTI_URL for the pipeline."
  value       = aws_instance.opencti.private_ip
}

output "opencti_url" {
  description = "OpenCTI API URL reachable from the pipeline spoke over the Aviatrix transit network."
  value       = "http://${aws_instance.opencti.private_ip}:${var.opencti_port}"
}

output "opencti_graphql_url" {
  description = "OpenCTI GraphQL endpoint — set as OPENCTI_URL in the pipeline env."
  value       = "http://${aws_instance.opencti.private_ip}:${var.opencti_port}/graphql"
}

output "spoke_gateway_name" {
  description = "Aviatrix Spoke Gateway name for this OpenCTI VPC."
  value       = aviatrix_spoke_gateway.opencti.gw_name
}

output "data_volume_id" {
  description = "EBS volume ID for OpenCTI data (Elasticsearch + MinIO). Back this up before destroy."
  value       = aws_ebs_volume.opencti_data.id
}

output "ssm_connect_command" {
  description = "SSM Session Manager command to open a shell on the OpenCTI EC2."
  value       = "aws ssm start-session --target ${aws_instance.opencti.id} --region ${var.aws_region}"
}
