output "instance_id" {
  value = aws_instance.pipeline.id
}

output "instance_private_ip" {
  value = aws_instance.pipeline.private_ip
}

output "data_bucket" {
  value = aws_s3_bucket.data.bucket
}

output "spoke_gateway_name" {
  value = aviatrix_spoke_gateway.pipeline.gw_name
}
