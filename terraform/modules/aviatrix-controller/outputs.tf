output "public_ip" {
  value = aws_eip.controller.public_ip
}

output "private_ip" {
  value = aws_instance.controller.private_ip
}

output "instance_id" {
  value = aws_instance.controller.id
}

output "gateway_role_arn" {
  value = aws_iam_role.aviatrix_gateway.arn
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.aviatrix_gateway.name
}
