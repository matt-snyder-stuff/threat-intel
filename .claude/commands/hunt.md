# /hunt

Start a threat hunting session from the current threat-watch-data.json dataset.

## Usage

```
/hunt                            # hunt from top clusters in the current dataset
/hunt <topic>                    # focus hunt on a specific tactic, actor, or IOC
/hunt ShinyHunters               # focus on a specific threat actor
/hunt supply chain               # focus on a specific technique or trend
/hunt CVE-2024-12345             # pivot on a specific CVE
```

## Steps

1. **Parse the hunt focus** from `$ARGUMENTS`.
   - If empty: use the `threat-hunter` agent with no focus — it will select the top 3 signals automatically.
   - If provided: pass it as the hunt focus so the agent narrows its cluster selection.

2. **Load the dataset** and confirm it exists:
   - Check `THREAT_WATCH_URL`, `THREAT_WATCH_FILE`, or `/tmp/threat-watch-data.json` (in that order).
   - If none is available, suggest running `/rebuild` first and STOP.
   - Print the dataset's `generated_at` timestamp so the analyst knows how fresh the data is.

3. **Hand off to the `threat-hunter` agent** with:
   - The hunt focus (or "no focus — select top signals" if none provided)
   - The dataset location
   - Today's date for the report filename

4. **After the hunt agent completes**, print:
   - Path to the written hunt report (`/tmp/hunt-report-<date>.md`)
   - The three hunt titles selected
   - A reminder: "Run these queries in your SIEM. If you get hits, re-run `/hunt` with the IOC as focus to pivot deeper."

## Tips

- The hunt report includes queries in Splunk SPL, KQL (Sentinel/Defender), and Sigma YAML format.
- Run `/enrich` after a hunt to get public context on any extracted IOCs.
- If the dataset is stale (older than 24h), suggest running `/rebuild` before hunting.
