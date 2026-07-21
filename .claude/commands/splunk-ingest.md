# /splunk-ingest

Fetch threat intel from Splunk via the REST API and rebuild the dashboard. Use when your threat intel data already lives in Splunk (a threat intel index, a lookup, a saved search result, etc.).

## Usage

```
/splunk-ingest                   # run with SPLUNK_SEARCH or the default search
/splunk-ingest index=threat_intel | table _time, title, description, url, source
```

## Prerequisites

```bash
SPLUNK_URL=https://your-instance.splunkcloud.com:8089
SPLUNK_TOKEN=your-api-token    # or SPLUNK_USERNAME + SPLUNK_PASSWORD
```

Optional field mappings (if your data uses non-default field names):
```bash
SPLUNK_FIELD_NAME=title           # field containing the article/report title
SPLUNK_FIELD_DESC=description     # field containing body text
SPLUNK_FIELD_URL=url              # field containing the source URL
SPLUNK_FIELD_PUBLISHER=source     # field containing the publisher name
SPLUNK_FIELD_TIME=_time           # field containing the event timestamp
SPLUNK_SEARCH="index=my_intel | table _time, title, description, url, source"
```

## Steps

1. **Validate env** — `SPLUNK_URL` must be set. Auth: `SPLUNK_TOKEN` or `SPLUNK_USERNAME`+`SPLUNK_PASSWORD`.

2. **If a search string was passed as `$ARGUMENTS`**, set `SPLUNK_SEARCH` to that value.

3. **Run the pipeline:**
   ```bash
   python3 run.py --source splunk --build
   ```

4. **Print output paths** — HTML dashboard and JSON dataset locations.

5. **Print a summary** of what was ingested: result count, earliest/latest timestamps, unique publishers detected.

## Notes

- The Splunk source auto-detects cloud/AI labels from the title + description text using the same label logic as the RSS and Slack sources.
- Threat actors are extracted via regex from title + description (40+ known actor names built in).
- Set `SPLUNK_VERIFY_SSL=false` for on-prem instances with self-signed certificates.
- If your threat intel lives in a KV store lookup, use: `| inputlookup threat_intel.csv`
