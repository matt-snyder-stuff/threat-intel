#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/outputs"
RESULTS="$OUT/search_results"
CONTAINER="${SPLUNK_CONTAINER:-splunk}"
AUTH="${SPLUNK_AUTH:-admin:Ch@ngeMe123!}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-security-lab-hec-token}"
HEC_URL="${SPLUNK_HEC_URL:-https://localhost:8088/services/collector/event}"
SPLUNK="/opt/splunk/bin/splunk"

mkdir -p "$RESULTS"

log() {
  printf '[demo] %s\n' "$*"
}

run_splunk() {
  docker exec --user splunk "$CONTAINER" "$SPLUNK" "$@" -auth "$AUTH"
}

log "Checking Splunk status"
run_splunk status

log "Creating demo_threat index if needed"
if ! run_splunk list index demo_threat >/dev/null 2>&1; then
  run_splunk add index demo_threat >/dev/null
fi

log "Ensuring HEC token can write to demo_threat"
docker exec "$CONTAINER" curl -k -s -u "$AUTH" \
  https://localhost:8089/servicesNS/nobody/splunk_httpinput/data/inputs/http/splunk_hec_token \
  -d index=demo_threat \
  -d indexes=demo_threat \
  -d disabled=0 >/tmp/demo_hec_update.json

log "Copying lookup files"
docker cp "$OUT/threat_iocs.csv" "$CONTAINER:/tmp/threat_iocs.csv"
docker cp "$OUT/ot_assets.csv" "$CONTAINER:/tmp/ot_assets.csv"
docker cp "$OUT/cicd_assets.csv" "$CONTAINER:/tmp/cicd_assets.csv"
docker cp "$OUT/demo_events.csv" "$CONTAINER:/tmp/demo_events.csv"
docker cp "$OUT/telemetry_readiness.csv" "$CONTAINER:/tmp/telemetry_readiness.csv"
docker cp "$OUT/confidence_scores.csv" "$CONTAINER:/tmp/confidence_scores.csv"
docker exec --user splunk "$CONTAINER" mkdir -p /opt/splunk/etc/system/lookups
docker exec --user splunk "$CONTAINER" cp /tmp/threat_iocs.csv /opt/splunk/etc/system/lookups/threat_iocs.csv
docker exec --user splunk "$CONTAINER" cp /tmp/ot_assets.csv /opt/splunk/etc/system/lookups/ot_assets.csv
docker exec --user splunk "$CONTAINER" cp /tmp/cicd_assets.csv /opt/splunk/etc/system/lookups/cicd_assets.csv
docker exec --user splunk "$CONTAINER" cp /tmp/demo_events.csv /opt/splunk/etc/system/lookups/demo_events.csv
docker exec --user splunk "$CONTAINER" cp /tmp/telemetry_readiness.csv /opt/splunk/etc/system/lookups/telemetry_readiness.csv
docker exec --user splunk "$CONTAINER" cp /tmp/confidence_scores.csv /opt/splunk/etc/system/lookups/confidence_scores.csv

log "Updating KV Store collection demo_threat_iocs"
docker cp "$OUT/kv_store_payload.json" "$CONTAINER:/tmp/kv_store_payload.json"
docker exec "$CONTAINER" curl -k -s -u "$AUTH" \
  https://localhost:8089/servicesNS/nobody/search/storage/collections/config \
  -d name=demo_threat_iocs >/tmp/demo_kv_create.json || true
docker exec "$CONTAINER" curl -k -s -u "$AUTH" \
  https://localhost:8089/servicesNS/nobody/search/storage/collections/data/demo_threat_iocs/batch_save \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/kv_store_payload.json > "$RESULTS/kv_store_batch_save.json"
docker exec "$CONTAINER" curl -k -s -u "$AUTH" \
  'https://localhost:8089/servicesNS/nobody/search/storage/collections/data/demo_threat_iocs?count=0' \
  > "$RESULTS/kv_store_documents.json"

log "Sending seed events through HEC"
docker cp "$OUT/splunk_events.jsonl" "$CONTAINER:/tmp/splunk_events.jsonl"
docker exec "$CONTAINER" sh -c "rm -f /tmp/hec_responses.jsonl; while IFS= read -r event; do curl -k -s '$HEC_URL' -H 'Authorization: Splunk $HEC_TOKEN' -H 'Content-Type: application/json' -d \"\$event\" >> /tmp/hec_responses.jsonl; printf '\n' >> /tmp/hec_responses.jsonl; done < /tmp/splunk_events.jsonl"
docker cp "$CONTAINER:/tmp/hec_responses.jsonl" "$RESULTS/hec_responses.jsonl"
if grep -v '"code":0' "$RESULTS/hec_responses.jsonl" >/dev/null; then
  log "HEC returned at least one error"
  cat "$RESULTS/hec_responses.jsonl"
  exit 1
fi

log "Waiting for events to become searchable"
sleep 5

run_search() {
  local name="$1"
  local spl_file="$2"
  local query
  query="$(cat "$spl_file")"
  log "Running $name"
  docker exec --user splunk "$CONTAINER" "$SPLUNK" search "$query" -auth "$AUTH" -output csv -maxout 50 > "$RESULTS/$name.csv"
}

run_search "01_ioc_starter" "$OUT/spl/01_ioc_starter.spl"
run_search "02_cyberav3ngers_plc_behavior" "$OUT/spl/02_cyberav3ngers_plc_behavior.spl"
run_search "03_teampcp_cicd_behavior" "$OUT/spl/03_teampcp_cicd_behavior.spl"
run_search "04_kv_store_check" "$OUT/spl/04_kv_store_check.spl"
run_search "05_telemetry_readiness" "$OUT/spl/05_telemetry_readiness.spl"
run_search "06_detection_confidence" "$OUT/spl/06_detection_confidence.spl"
run_search "proof_01_ioc_starter" "$OUT/spl/proof_01_ioc_starter.spl"
run_search "proof_02_cyberav3ngers_plc_behavior" "$OUT/spl/proof_02_cyberav3ngers_plc_behavior.spl"
run_search "proof_03_teampcp_cicd_behavior" "$OUT/spl/proof_03_teampcp_cicd_behavior.spl"

log "Capturing indexed-data proof"
docker exec --user splunk "$CONTAINER" "$SPLUNK" search '| eventcount summarize=false index=demo_threat | table index count' -auth "$AUTH" -output csv -maxout 20 > "$RESULTS/index_eventcount.csv"
docker exec --user splunk "$CONTAINER" "$SPLUNK" search '| metadata type=sourcetypes index=demo_threat | table sourcetype totalCount recentTime' -auth "$AUTH" -output csv -maxout 20 > "$RESULTS/index_metadata.csv"

log "Writing run proof"
{
  echo "# Splunk Demo Seed Proof"
  echo
  echo "Container: $CONTAINER"
  echo "Index: demo_threat"
  echo "Lookup files: threat_iocs.csv, ot_assets.csv, cicd_assets.csv"
  echo "KV Store collection: demo_threat_iocs"
  echo
  echo "Result files:"
  find "$RESULTS" -maxdepth 1 -type f | sort | sed "s#^$ROOT/##"
} > "$RESULTS/seed_proof.md"

log "Done. Results are in $RESULTS"
