terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_YOUR_STATE_BUCKET"
    key            = "threat-intel/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}
