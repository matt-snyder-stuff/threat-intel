#!/bin/bash
# Bootstrap OpenCTI on a single EC2 using Docker Compose.
# Runs once on first boot via cloud-init.
set -euo pipefail

LOG=/var/log/opencti-bootstrap.log
exec >> "$LOG" 2>&1
echo "=== opencti bootstrap start $(date -u) ==="

# ── System setup ──────────────────────────────────────────────────────────────
dnf update -y
dnf install -y docker git aws-cli

systemctl enable --now docker

# Docker Compose v2 plugin
COMPOSE_VERSION=v2.27.1
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/$${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Tune kernel for Elasticsearch
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.d/99-opencti.conf

# ── Pull secrets from SSM ─────────────────────────────────────────────────────
OPENCTI_ADMIN_PASSWORD=$(aws ssm get-parameter \
  --name "${opencti_admin_password_ssm}" \
  --with-decryption \
  --region ${aws_region} \
  --query Parameter.Value \
  --output text)

OPENCTI_ADMIN_TOKEN=$(aws ssm get-parameter \
  --name "${opencti_admin_token_ssm}" \
  --with-decryption \
  --region ${aws_region} \
  --query Parameter.Value \
  --output text)

# ── Prepare data volume ───────────────────────────────────────────────────────
# The extra EBS volume is attached at /dev/xvdf; format and mount if fresh.
DATA_DEV=/dev/xvdf
DATA_MOUNT=/opt/opencti-data

if ! blkid "$DATA_DEV" &>/dev/null; then
  mkfs -t xfs "$DATA_DEV"
fi

mkdir -p "$DATA_MOUNT"
mount "$DATA_DEV" "$DATA_MOUNT"
echo "$DATA_DEV $DATA_MOUNT xfs defaults,nofail 0 2" >> /etc/fstab

mkdir -p "$DATA_MOUNT"/{esdata,s3data,redisdata,amqpdata}
chown -R 1000:1000 "$DATA_MOUNT/esdata"   # Elasticsearch runs as uid 1000
chown -R 1001:1001 "$DATA_MOUNT/s3data"   # MinIO runs as uid 1001

# ── Write Docker Compose file ─────────────────────────────────────────────────
mkdir -p /opt/opencti
cat > /opt/opencti/docker-compose.yml <<COMPOSE
version: "3.8"

networks:
  opencti-net:

services:
  redis:
    image: redis:7.2
    restart: unless-stopped
    volumes:
      - $${DATA_MOUNT}/redisdata:/data
    networks:
      - opencti-net
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 10

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.14.3
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    volumes:
      - $${DATA_MOUNT}/esdata:/usr/share/elasticsearch/data
    networks:
      - opencti-net
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 15s
      timeout: 10s
      retries: 20

  minio:
    image: minio/minio:latest
    restart: unless-stopped
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: opencti
      MINIO_ROOT_PASSWORD: \$${MINIO_SECRET}
    volumes:
      - $${DATA_MOUNT}/s3data:/data
    networks:
      - opencti-net
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:9000/minio/health/live"]
      interval: 10s
      timeout: 5s
      retries: 20

  rabbitmq:
    image: rabbitmq:3.12-management
    restart: unless-stopped
    environment:
      RABBITMQ_DEFAULT_USER: opencti
      RABBITMQ_DEFAULT_PASS: \$${RABBIT_SECRET}
    volumes:
      - $${DATA_MOUNT}/amqpdata:/var/lib/rabbitmq
    networks:
      - opencti-net
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 15s
      timeout: 10s
      retries: 20

  opencti:
    image: opencti/platform:${opencti_version}
    restart: unless-stopped
    environment:
      NODE_OPTIONS: --max-old-space-size=8096
      APP__PORT: ${opencti_port}
      APP__BASE_URL: http://\$${HOST_IP}:${opencti_port}
      APP__ADMIN__EMAIL: ${opencti_admin_email}
      APP__ADMIN__PASSWORD: \$${OPENCTI_ADMIN_PASSWORD}
      APP__ADMIN__TOKEN: \$${OPENCTI_ADMIN_TOKEN}
      REDIS__HOSTNAME: redis
      REDIS__PORT: 6379
      ELASTICSEARCH__URL: http://elasticsearch:9200
      MINIO__ENDPOINT: minio
      MINIO__PORT: 9000
      MINIO__USE_SSL: "false"
      MINIO__ACCESS_KEY: opencti
      MINIO__SECRET_KEY: \$${MINIO_SECRET}
      RABBITMQ__HOSTNAME: rabbitmq
      RABBITMQ__PORT: 5672
      RABBITMQ__USERNAME: opencti
      RABBITMQ__PASSWORD: \$${RABBIT_SECRET}
      SMTP__HOSTNAME: localhost
      SMTP__PORT: 25
    ports:
      - "${opencti_port}:${opencti_port}"
    networks:
      - opencti-net
    depends_on:
      redis:
        condition: service_healthy
      elasticsearch:
        condition: service_healthy
      minio:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
COMPOSE

# ── Write the env file with generated secrets ─────────────────────────────────
# RabbitMQ and MinIO passwords are derived from the admin token — no extra SSM
# parameters needed.
HOST_IP=$(curl -sf http://169.254.169.254/latest/meta-data/local-ipv4)
MINIO_SECRET=$(echo "$OPENCTI_ADMIN_TOKEN" | sha256sum | head -c 32)
RABBIT_SECRET=$(echo "$OPENCTI_ADMIN_TOKEN" | md5sum | head -c 24)

cat > /opt/opencti/.env <<ENV
OPENCTI_ADMIN_PASSWORD=$OPENCTI_ADMIN_PASSWORD
OPENCTI_ADMIN_TOKEN=$OPENCTI_ADMIN_TOKEN
MINIO_SECRET=$MINIO_SECRET
RABBIT_SECRET=$RABBIT_SECRET
HOST_IP=$HOST_IP
ENV
chmod 600 /opt/opencti/.env

# ── Start stack ───────────────────────────────────────────────────────────────
cd /opt/opencti
docker compose --env-file .env up -d

# ── Write a systemd service so the stack survives reboots ─────────────────────
cat > /etc/systemd/system/opencti.service <<UNIT
[Unit]
Description=OpenCTI Docker Compose stack
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/opencti
EnvironmentFile=/opt/opencti/.env
ExecStart=/usr/local/lib/docker/cli-plugins/docker-compose up -d
ExecStop=/usr/local/lib/docker/cli-plugins/docker-compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable opencti

echo "=== opencti bootstrap complete $(date -u) ==="
echo "UI will be available at http://$${HOST_IP}:${opencti_port} once containers are healthy (~2 min)"
