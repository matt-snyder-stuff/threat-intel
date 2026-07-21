# Threat Watch — Splunk App

A Splunk 9.x app that ingests the Threat Watch pipeline's JSON dataset into KV Store collections, surfaces threat intelligence in a unified dashboard, and ships pre-built hunt searches and alerting rules.

---

## Directory layout

```
splunk/
├── README.md                         ← this file
└── threat_watch/
    ├── default/
    │   ├── app.conf                  ← app metadata
    │   ├── collections.conf          ← KV Store collection definitions
    │   ├── transforms.conf           ← KV Store lookup definitions
    │   ├── savedsearches.conf        ← scheduled ingestion, alerts, hunt searches
    │   └── data/ui/
    │       ├── nav/default.xml       ← app navigation bar
    │       └── views/threat_watch.xml ← main Simple XML dashboard
    └── metadata/
        └── default.meta              ← object-level access permissions
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Splunk Enterprise or Cloud 9.x | Tested on 9.1+ |
| KV Store enabled | On by default; check `$SPLUNK_HOME/etc/system/local/server.conf` |
| `threat_intel` index | Create it before installing, or adjust `index = threat_intel` in `savedsearches.conf` |
| Pipeline JSON on disk or in Splunk | See **Data Ingestion** below |

---

## Installation

### Manual (recommended for dev)

```bash
# Copy the app into your Splunk apps directory
cp -r splunk/threat_watch $SPLUNK_HOME/etc/apps/

# Restart Splunk to pick up the new app
$SPLUNK_HOME/bin/splunk restart
```

### Package and upload (Splunk Cloud / production)

```bash
cd splunk/
tar -czf threat_watch.tar.gz threat_watch/
# Upload threat_watch.tar.gz via Splunk Web > Apps > Manage Apps > Install app from file
```

---

## Data ingestion

The app expects threat intelligence events in the `threat_intel` Splunk index. Two approaches:

### Option A — Feed the pipeline JSON directly into Splunk

Run the pipeline with the `splunk` source, which requires these environment variables:

```bash
SPLUNK_URL=https://your-splunk:8089
SPLUNK_TOKEN=<HEC or REST token>
# For REST-based writes:
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=changeme
# Optional search overrides:
SPLUNK_SEARCH="search index=threat_intel sourcetype=threat_watch | head 500"
SPLUNK_EARLIEST=-30d
# Field mappings (defaults shown):
SPLUNK_FIELD_NAME=name
SPLUNK_FIELD_DESC=description
SPLUNK_FIELD_URL=url
SPLUNK_FIELD_PUBLISHER=publisher
SPLUNK_FIELD_TIME=_time
```

Then run:

```bash
python3 run.py --source splunk --build
```

### Option B — Write the JSON output into Splunk via HEC

After running the pipeline normally, push `threat-watch-data.json` to Splunk via HTTP Event Collector:

```bash
curl -k -H "Authorization: Splunk <HEC_TOKEN>" \
     -H "Content-Type: application/json" \
     https://your-splunk:8088/services/collector/event \
     -d @threat-watch-data.json
```

Set the sourcetype to `threat_watch` and the index to `threat_intel`.

---

## KV Store collections

| Collection | Key field | Purpose |
|---|---|---|
| `threat_intel_clusters` | `cluster_id` | One record per cloud cluster from `cloud_clusters[]` |
| `threat_intel_iocs` | `ioc` | Extracted IOC watchlist (IPs, domains, hashes, CVEs) |

Populate the KV Store by running the **Threat Watch — Ingest Clusters** saved search manually after installation, or wait for the hourly schedule to fire.

---

## Saved searches

| Name | Schedule | Purpose |
|---|---|---|
| Threat Watch — Ingest Clusters | Every 1h | Reads pipeline JSON from `threat_intel` index, upserts cluster records to KV Store |
| Threat Watch — Alert: High-Reach Cluster | Every 4h | Fires when any cluster has `reach_score >= 75` and was ingested within the last 24h |
| Threat Watch — Alert: New Threat Actor | Every 6h | Fires when a threat actor appears that was not seen in the prior 7 days |
| Threat Watch — Hunt: Cloud Initial Access | Daily at 06:00 | Hunts for T1078/T1190/T1133 correlated against cloud-tagged clusters |
| Threat Watch — Hunt: AI/LLM Abuse | On demand | Searches for MCP, prompt injection, and model exfiltration indicators |
| Threat Watch — Hunt: Lateral Movement by Known Actors | On demand | Correlates known threat actors against lateral movement events |

---

## Dashboard

Navigate to **Apps > Threat Watch > Threat Watch Dashboard**.

The dashboard has four rows:

1. **KPI tiles** — total reports (30d), cloud-relevant, AI/LLM, active threat actors
2. **Trend charts** — threat actor activity over time; cloud provider targeting breakdown
3. **Cluster and vendor tables** — top clusters by reach score; vendor mentions this week
4. **Recent activity** — last 24h reports; IOC watchlist from KV Store

A global time picker token (`$time_tok$`) controls searches that support relative time ranges.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| KV Store panels show no data | Run **Threat Watch — Ingest Clusters** saved search manually |
| `threat_intel` index not found | Create the index: `$SPLUNK_HOME/bin/splunk add index threat_intel` |
| Permission denied on KV Store | Check `metadata/default.meta` — objects need `access = read : [ * ], write : [ admin, power ]` |
| Dashboard shows `Error in 'outputlookup'` | Ensure the Splunk user running the search has the `edit_lookups` capability |
