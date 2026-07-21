# Threat Intel — Terraform Deployment

Deploys a production-reference Aviatrix network topology in AWS with an isolated spoke VPC running the threat intel pipeline.

## Architecture

```
Internet
    │
    ▼
Aviatrix Transit GW (transit VPC)
    │  FQDN egress filtering — only allows known threat intel sources
    │
    ├── Spoke VPC (pipeline)
    │     EC2 running threat-intel container
    │     No direct internet access — all egress via transit GW
    │
    └── (future spokes attach here)
```

## Prerequisites

- Terraform >= 1.5
- AWS credentials with permissions to create VPCs, EC2, IAM, CloudWatch, S3
- An Aviatrix Controller AMI license (BYOL or Marketplace subscription)
- An Aviatrix account onboarded in the controller (after first boot)
- `admin_cidr_blocks` must be set to your office or VPN CIDR (e.g. `["203.0.113.0/24"]`) — this variable has no default and Terraform will error if it is not provided. Do not use `0.0.0.0/0` in production.

## Quick start

```bash
cd terraform

# 1. Copy and fill in your values
cp terraform.tfvars.example terraform.tfvars

# 2. Initialize (downloads AWS + Aviatrix providers)
terraform init

# 3. Preview
terraform plan

# 4. Deploy (~15 min — controller bootstrap takes the longest)
terraform apply

# 5. Tear down
terraform destroy
```

## State management

Remote state is configured in `backend.tf`. Create the S3 bucket and DynamoDB table before running `terraform init`, or switch to local state by removing `backend.tf`.

```bash
# Create state bucket (one-time)
aws s3api create-bucket --bucket YOUR_STATE_BUCKET --region us-east-1
aws dynamodb create-table \
  --table-name terraform-state-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

## Modules

| Module | What it creates |
|--------|----------------|
| `modules/aviatrix-controller` | Controller EC2, EIP, security group, IAM role, CloudWatch alarms |
| `modules/transit` | Transit VPC, Aviatrix Transit GW + HA pair, FQDN egress filter |
| `modules/spoke-pipeline` | Spoke VPC, Aviatrix Spoke GW, EC2 instance, IAM role for SSM + S3 |

## Outputs

After `apply`, Terraform prints:

| Output | Description |
|--------|-------------|
| `controller_public_ip` | Controller UI — https://<ip> |
| `controller_private_ip` | Internal reference |
| `pipeline_instance_id` | EC2 for the pipeline (access via SSM Session Manager) |
| `data_bucket` | S3 bucket where pipeline writes `threat-watch-data.json` |
| `data_bucket_url` | Set as `THREAT_WATCH_URL` in your `.env` |
