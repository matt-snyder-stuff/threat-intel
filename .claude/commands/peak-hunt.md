# /peak-hunt

Run a full-lifecycle threat hunt using the PEAK framework (Prepare / Execute / Act + Knowledge). Produces a hunt plan before any query runs, executes live queries against Splunk (if configured) or generates offline artifacts, iterates based on what it finds, enriches IOCs, generates working detection artifacts, calculates hunt metrics, and writes a closure report.

## Usage

```
/peak-hunt                              # auto-select hunt type from top signals
/peak-hunt hypothesis                   # force Hypothesis-Driven hunt
/peak-hunt baseline                     # force Baseline hunt
/peak-hunt math                         # force M-ATH (Model-Assisted Threat Hunt)
/peak-hunt ShinyHunters                 # Hypothesis-Driven hunt focused on a specific actor
/peak-hunt T1078.004                    # hunt focused on a specific MITRE technique
/peak-hunt supply chain hypothesis      # hunt type + focus topic
```

## What this produces

Three files, always:

| File | Written when | Contents |
|------|-------------|----------|
| `/tmp/peak-hunt-plan-<date>.md` | Before any query runs | ABLE hypotheses, data source requirements, success criteria |
| `/tmp/peak-hunt-log-<date>.json` | Throughout execution | Every query, result count, pivot, and classification decision |
| `/tmp/peak-hunt-report-<date>.md` | After hunt closes | Findings, detection artifacts, metrics, knowledge base updates |

## PEAK phases (what actually runs)

**PREPARE**
- Selects hunt type (Hypothesis-Driven, Baseline, or M-ATH) with rationale
- Writes ABLE hypotheses — Actor, Behavior (MITRE T-ID), Location, Evidence field — in full sentence form
- Defines scope, time range, and required data sources
- Sets explicit success criteria: Confirmed / Negative (data present) / Inconclusive (data absent)
- Writes the hunt plan to disk before running any query

**EXECUTE**
- Validates data source presence via Splunk (if live) or flags gaps (if offline)
- Runs broad-first, then iterates: Round 1 (broad) → Round 2 (targeted) → Round 3 (confirmation/pivot)
- Classifies every result: Confirmed | Investigate | False Positive
- Logs every query run including zero-result queries
- Enriches confirmed/investigate IOCs via ipapi.co, crt.sh, and NVD

**ACT + KNOWLEDGE**
- Generates Sigma rules for stable behavioral patterns and IOC-based detections
- Generates Splunk correlation searches with tuning notes and FP documentation
- Documents all negative results explicitly — "data present, no hits" vs "data absent, inconclusive" are different outcomes
- Calculates PEAK metrics: hypotheses, queries, findings, conversion rate, HMM level, data quality
- Lists open items and re-hunt triggers

## Live Splunk vs offline mode

**Live mode** (full execution): Set `SPLUNK_URL` before running:
```bash
export SPLUNK_URL=https://your-instance.splunkcloud.com:8089
export SPLUNK_TOKEN=your-api-token
# OR
export SPLUNK_USERNAME=admin
export SPLUNK_PASSWORD=your-password
export SPLUNK_VERIFY_SSL=false   # for self-signed certs
```

**Offline mode** (no Splunk): The agent generates all query artifacts and detection rules, flags data-source requirements, and produces the full plan and report — but result counts and live findings are skipped. Useful for building hunt plans before access is available.

## Steps

1. **Parse arguments** from `$ARGUMENTS`:
   - First token matching `hypothesis`, `baseline`, or `math` → set as `PEAK_HUNT_TYPE`
   - Remaining tokens → set as `PEAK_FOCUS`

2. **Check the dataset**:
   - Look for `THREAT_WATCH_URL`, `THREAT_WATCH_FILE`, or `/tmp/threat-watch-data.json`
   - If none found: tell the user to run `/rebuild` first and STOP
   - Warn (but don't stop) if dataset is older than 24 hours

3. **Check Splunk config**:
   - If `SPLUNK_URL` is set: run in live mode
   - If not set: run in offline mode; note it clearly in all output files

4. **Export environment variables** and invoke the `peak-hunt` agent

5. **After the agent completes**, print:
   - Paths to all three output files
   - Hunt type and mode (Live / Offline)
   - Findings summary: N confirmed | N investigate | N negative | N inconclusive
   - Detection artifacts produced: N Sigma rules | N SPL correlation searches
   - HMM level achieved
   - Any data-source gaps that need attention
   - Next steps (enrichment, re-hunt triggers, detection deployment)

## Integration with other commands

| Command | When to use with /peak-hunt |
|---------|----------------------------|
| `/rebuild` | Run first if dataset is stale (>24h) |
| `/hunt <IOC>` | Pivot deeper on a specific IOC from confirmed findings |
| `/enrich <IOC>` | Get additional public context on extracted indicators |
| `/hunt-live <focus>` | Run a faster, less-structured live hunt for a quick pivot |
| `/splunk-ingest` | Push threat intel from Splunk before running the hunt |

## PEAK Hunt Types — when to choose

| Type | Use when |
|------|----------|
| `hypothesis` | Named actor in dataset, specific MITRE technique, recent CVE exploitation, active campaign report |
| `baseline` | No named actors, trend-only data, new data source just onboarded, want to establish what normal looks like |
| `math` | Anomaly scores or UBA-style signals in dataset, behavioral deviations that need human validation |

If unsure: let the agent auto-select. It scores each cluster for hunt value and picks the type that best fits the signals present.

## Key discipline notes

- A hypothesis without a specified Evidence field (index + sourcetype + key field) is not ready to execute — the agent will sharpen it before querying
- "No results" only means "behavior not observed" when the required data source was present and complete — the agent distinguishes this from "data absent"
- Every query is logged, including zero-result queries — the log is the reproducibility record
- Detection artifacts belong in version control — commit the Sigma rules and SPL searches to your detection repo after validating
