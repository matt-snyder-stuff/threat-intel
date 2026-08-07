# Threat Intel — Terraform Deployment

Deploys a production-reference Aviatrix network topology in AWS with an isolated spoke VPC running the threat intel pipeline. Three deployment modes let you choose how much infrastructure Terraform manages.

## Deployment modes

| Mode | `opencti_deploy` | `opencti_url` | What Terraform builds | Best for |
|------|-----------------|--------------|----------------------|----------|
| **1 — Pipeline only** | `false` | _(empty)_ | Transit VPC + pipeline spoke | RSS / STIX / Splunk / Slack sources; no OpenCTI needed |
| **2 — BYO OpenCTI** | `false` | your URL | Transit VPC + pipeline spoke | You already run OpenCTI elsewhere |
| **3 — Full-stack** | `true` | _(derived)_ | Transit VPC + pipeline spoke + **OpenCTI spoke** | Greenfield; Terraform manages everything |

Pick the right starter file:

```bash
# Mode 1
cp terraform.tfvars.pipeline-only.example terraform.tfvars

# Mode 2
cp terraform.tfvars.byo-opencti.example terraform.tfvars

# Mode 3
cp terraform.tfvars.full-stack.example terraform.tfvars
```

## Architecture

### Mode 1 & 2

```
Internet
    │
    ▼
Aviatrix Transit GW (transit VPC, 10.0.0.0/23)
    │  FQDN egress filtering
    │
    └── Spoke VPC — pipeline (10.1.0.0/24)
          EC2: threat-intel pipeline
          Reaches: RSS feeds, STIX/TAXII, Splunk, Slack, or BYO OpenCTI URL
```

### Mode 3 — Full-stack

```
Internet
    │
    ▼
Aviatrix Transit GW (transit VPC, 10.0.0.0/23)
    │  FQDN egress filtering
    │
    ├── Spoke VPC — pipeline (10.1.0.0/24)
    │     EC2: threat-intel pipeline
    │     OPENCTI_URL auto-wired to OpenCTI spoke
    │
    └── Spoke VPC — OpenCTI (10.2.0.0/24)
          EC2 (t3.xlarge): OpenCTI + Elasticsearch + Redis + RabbitMQ + MinIO
          EBS data volume (100 GiB, prevent_destroy = true)
          Inbound port 8080 from pipeline spoke only
```

## Prerequisites

- Terraform >= 1.5
- AWS credentials with permissions to create VPCs, EC2, IAM, CloudWatch, S3, EBS
- An Aviatrix Controller AMI license (BYOL or Marketplace subscription)

**Mode 3 additional prerequisites** — store two secrets in SSM before `terraform apply`:

```bash
aws ssm put-parameter \
  --name /threat-intel/prod/opencti_password \
  --type SecureString \
  --value "YourStrongPassword123!"

# Token must be a UUID
aws ssm put-parameter \
  --name /threat-intel/prod/opencti_token \
  --type SecureString \
  --value "$(python3 -c 'import uuid; print(uuid.uuid4())')"
```

## Quick start

```bash
cd terraform

# 1. Pick a mode and copy the right example
cp terraform.tfvars.full-stack.example terraform.tfvars
# edit terraform.tfvars — fill in Aviatrix credentials, bucket name, etc.

# 2. Initialize
terraform init

# 3. Preview
terraform plan

# 4. Deploy (~15-20 min — controller bootstrap takes the longest)
terraform apply

# 5. Tear down
terraform destroy
```

## Accessing OpenCTI (Mode 3)

After `apply`, OpenCTI is available on the private IP of the OpenCTI EC2. Access it from a host connected to the Aviatrix VPN, or tunnel via SSM:

```bash
# Get the private IP
terraform output opencti_url

# Open an SSM tunnel on port 8080
aws ssm start-session \
  --target $(terraform output -raw opencti_instance_id) \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8080"],"localPortNumber":["8080"]}'

# Then open http://localhost:8080 in your browser
# Email:    admin@opencti.io
# Password: (from SSM parameter you set above)
```

## Outputs

| Output | Description |
|--------|-------------|
| `controller_public_ip` | Aviatrix controller UI — `https://<ip>` |
| `pipeline_instance_id` | Pipeline EC2 (access via SSM Session Manager) |
| `ssm_connect_pipeline` | Ready-to-run SSM connect command |
| `data_bucket` | S3 bucket for `threat-watch-data.json` |
| `data_bucket_url` | Set as `THREAT_WATCH_URL` in your `.env` |
| `pipeline_source_effective` | Resolved pipeline source after auto-selection |
| `opencti_url` | OpenCTI GraphQL URL (Mode 2 or 3 only) |
| `opencti_instance_id` | OpenCTI EC2 ID (Mode 3 only) |
| `ssm_connect_opencti` | SSM connect command for OpenCTI EC2 (Mode 3 only) |
| `opencti_data_volume_id` | EBS data volume ID — back up before destroy (Mode 3 only) |

## State management

Remote state is configured in `backend.tf`. Create the S3 bucket and DynamoDB table before running `terraform init`, or switch to local state by removing `backend.tf`.

```bash
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
| `modules/spoke-pipeline` | Spoke VPC, Aviatrix Spoke GW, pipeline EC2, S3 bucket, EventBridge schedule |
| `modules/spoke-opencti` | Spoke VPC, Aviatrix Spoke GW, OpenCTI EC2, EBS data volume _(Mode 3 only)_ |

## Destroying Mode 3

The OpenCTI data volume has `prevent_destroy = true` to protect your threat intel data. To tear down fully:

```bash
# 1. Remove the volume from state (does not delete the actual EBS volume)
terraform state rm module.spoke_opencti[0].aws_ebs_volume.opencti_data

# 2. Destroy everything else
terraform destroy

# 3. Manually delete the EBS volume if you no longer need it
aws ec2 delete-volume --volume-id <volume-id-from-output>
```

## Cost estimate (us-east-1, on-demand)

| Mode | Monthly est. | Notes |
|------|-------------|-------|
| Mode 1 — Pipeline only | ~$250–400 | Controller t3.large + transit c5.xlarge + pipeline t3.medium + Aviatrix GW |
| Mode 2 — BYO OpenCTI | ~$250–400 | Same as Mode 1; OpenCTI cost depends on your existing setup |
| Mode 3 — Full-stack | ~$450–650 | Adds OpenCTI t3.xlarge + spoke GW + 100 GiB EBS gp3 |

Aviatrix licensing cost is separate and billed by Aviatrix.
