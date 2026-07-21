# /hunt-live

Run live threat hunts against Splunk — reads the threat-watch-data.json dataset, generates targeted SPL, executes against your Splunk instance via the REST API, and returns actual findings.

## Usage

```
/hunt-live                       # hunt top signals, execute live
/hunt-live ShinyHunters          # focus hunt on a specific threat actor
/hunt-live supply chain          # focus on a technique or trend
/hunt-live CVE-2024-12345        # pivot on a CVE
```

## Prerequisites

Must be set before running:

```bash
SPLUNK_URL=https://your-instance.splunkcloud.com:8089   # REST API endpoint
SPLUNK_TOKEN=your-api-token                             # preferred auth
# OR
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=your-password
```

Optional:
```bash
SPLUNK_VERIFY_SSL=false    # for self-signed certs
HUNT_FOCUS="Scattered Spider"   # passed through to the agent
```

## Steps

1. **Check Splunk connectivity** — verify `SPLUNK_URL` is set. If not, print:
   ```
   SPLUNK_URL is required. Set it and re-run /hunt-live.
   Docs: https://docs.splunk.com/Documentation/Splunk/latest/RESTAPI/RESTprefs
   ```
   and STOP.

2. **Check for auth** — at least one of `SPLUNK_TOKEN` or (`SPLUNK_USERNAME` + `SPLUNK_PASSWORD`) must be set.

3. **Check the dataset** — look for `THREAT_WATCH_URL`, `THREAT_WATCH_FILE`, or `/tmp/threat-watch-data.json`. If none available, suggest running `/rebuild` first and STOP.

4. **Set `HUNT_FOCUS`** from `$ARGUMENTS` if provided.

5. **Hand off to the `splunk-hunter` agent** with the dataset location and Splunk config.

6. **After the agent completes**, print:
   - Path to the live hunt report (`/tmp/hunt-report-live-<date>.md`)
   - Summary: N confirmed / N investigate / N no-evidence
   - Top recommended action
   - Reminder: "Run `/hunt [focus]` to generate offline queries (SPL + KQL + Sigma) for the same signals."
