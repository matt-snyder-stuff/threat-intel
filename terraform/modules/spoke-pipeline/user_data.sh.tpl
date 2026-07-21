#!/bin/bash
# Bootstrap the pipeline EC2. Runs once on first boot.
set -euo pipefail

# ── System setup ──────────────────────────────────────────────────────────────
dnf update -y
dnf install -y python3 git aws-cli

# ── Clone the pipeline repo ───────────────────────────────────────────────────
git clone https://github.com/matt-snyder-stuff/threat-intel.git /opt/threat-intel
git -C /opt/threat-intel checkout ${pipeline_git_ref}

# ── Pull pipeline secrets from SSM Parameter Store ───────────────────────────
# Each entry in pipeline_env_ssm maps ENV_VAR => /ssm/path
%{ for var_name, ssm_path in pipeline_env_ssm ~}
export ${var_name}=$(aws ssm get-parameter \
  --name "${ssm_path}" \
  --with-decryption \
  --region ${aws_region} \
  --query Parameter.Value \
  --output text)
%{ endfor ~}

# ── Write the environment file ────────────────────────────────────────────────
# Additional vars that don't need secrets management
cat > /etc/threat-intel.env <<EOF
DATA_BUCKET=${data_bucket}
AWS_REGION=${aws_region}
PKL_OUT=/tmp/tw-30d-processed.pkl
RAW_OUT=/tmp/tw-30d.json
PUB_SIDECAR=/tmp/tw-30d-published.json
HTML_OUT=/tmp/threat-watch.html
JSON_OUT=/tmp/threat-watch-data.json
EOF

# ── Write the run script invoked by EventBridge ───────────────────────────────
cat > /usr/local/bin/run-pipeline.sh <<'SCRIPT'
#!/bin/bash
set -euo pipefail
set -a
source /etc/threat-intel.env
set +a

# Re-pull SSM secrets at runtime so rotated values are picked up
%{ for var_name, ssm_path in pipeline_env_ssm ~}
export ${var_name}=$(aws ssm get-parameter \
  --name "${ssm_path}" \
  --with-decryption \
  --region $AWS_REGION \
  --query Parameter.Value \
  --output text)
%{ endfor ~}

cd /opt/threat-intel
python3 run.py --source ${pipeline_source} --build

# Upload outputs to S3
aws s3 cp /tmp/threat-watch-data.json s3://$DATA_BUCKET/threat-watch-data.json
aws s3 cp /tmp/threat-watch.html      s3://$DATA_BUCKET/threat-watch.html

echo "Pipeline complete: $(date -u)"
SCRIPT

chmod +x /usr/local/bin/run-pipeline.sh

# ── Run pipeline once on boot ─────────────────────────────────────────────────
/usr/local/bin/run-pipeline.sh >> /var/log/threat-intel-bootstrap.log 2>&1 || true
