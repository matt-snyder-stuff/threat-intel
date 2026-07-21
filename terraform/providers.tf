provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "threat-intel"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Aviatrix provider points at the controller we deploy.
# controller_ip is set after the controller module runs; using a data source
# avoids a chicken-and-egg issue for the initial apply (controller bootstrap
# must complete before gateway resources can be created).
provider "aviatrix" {
  controller_ip = module.aviatrix_controller.private_ip
  username      = "admin"
  password      = var.aviatrix_admin_password
}
