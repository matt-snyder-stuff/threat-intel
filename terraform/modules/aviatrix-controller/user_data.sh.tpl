#!/bin/bash
# Bootstrap the Aviatrix controller on first boot via the controller init API.
# The controller's built-in init script handles version installation; this
# script waits for the API to become reachable and then sets credentials.
set -euo pipefail

CONTROLLER_IP=$(curl -sf http://169.254.169.254/latest/meta-data/local-ipv4)
API="https://localhost/v1/api"

# Wait for the controller HTTPS port to open (up to 10 min)
for i in $(seq 1 60); do
  if curl -sk --max-time 5 "$API" > /dev/null 2>&1; then
    break
  fi
  sleep 10
done

# Set the initial admin password and customer ID via the init API
curl -sk -X POST "$API" \
  -d "action=initial_setup" \
  -d "subaction=run" \
  -d "target_version=${controller_version}" \
  -d "admin_email=admin@example.com" \
  -d "admin_password=${admin_password}" \
  -d "customer_id=${customer_id}" \
  > /var/log/aviatrix-init.log 2>&1

echo "Controller bootstrap complete." >> /var/log/aviatrix-init.log
