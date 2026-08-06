# /peak-hunt

Run a structured threat hunt using the PEAK framework (Prepare / Execute / Act + Knowledge).

## Usage

```
/peak-hunt                              # best hunt type selected automatically from dataset
/peak-hunt hypothesis                   # force Hypothesis-Driven hunt
/peak-hunt baseline                     # force Baseline hunt
/peak-hunt math                         # force M-ATH (Model-Assisted Threat Hunt)
/peak-hunt ShinyHunters                 # Hypothesis-Driven hunt focused on a specific actor
/peak-hunt T1078.004                    # hunt focused on a specific MITRE technique
/peak-hunt supply chain hypothesis      # hunt type + focus topic
```

## What this does

Applies the full PEAK framework to the current threat-watch-data.json dataset:

- **PREPARE**: selects hunt type, writes ABLE hypotheses, validates data sources
- **EXECUTE**: generates Splunk SPL, KQL, and Sigma queries per hypothesis
- **ACT + KNOWLEDGE**: recommends detection conversion tier, documents negative results

Output is a structured Markdown report at `/tmp/peak-hunt-report-<date>.md`.

## Steps

1. **Parse arguments** from `$ARGUMENTS`:
   - First word matching `hypothesis`, `baseline`, or `math` → sets `PEAK_HUNT_TYPE`
   - Remaining words → set as `PEAK_FOCUS`
   - If no args: leave both unset; the agent selects automatically

2. **Validate the dataset**:
   - Check `THREAT_WATCH_URL`, `THREAT_WATCH_FILE`, or `/tmp/threat-watch-data.json`
   - If none found: tell the user to run `/rebuild` first and STOP
   - Print the dataset's `generated_at` timestamp

3. **Export environment variables** and hand off to the `peak-hunt` agent:
   - `PEAK_HUNT_TYPE` (if parsed)
   - `PEAK_FOCUS` (if parsed)
   - Dataset location

4. **After the agent completes**, print:
   - Path to the written report
   - Hunt type used and rationale
   - One-line summary per hypothesis
   - Any data-source gaps flagged
   - "Next: run these queries in your SIEM. Use `/hunt <IOC>` to pivot on any hits."

## PEAK Hunt Types — Quick Reference

| Type | When to use |
|------|-------------|
| `hypothesis` | Named actor, specific TTP, recent CVE, threat report just dropped |
| `baseline` | New data source, no active threat, want to know what "normal" looks like |
| `math` | ML/UBA output needs validation, large behavioral datasets |

## Integration with other commands

- Run `/rebuild` first if the dataset is older than 24 hours
- After getting hits, use `/hunt <IOC>` to pivot deeper with the `threat-hunter` agent
- Use `/enrich <IOC>` to get public context on extracted indicators
- Use `/splunk-ingest` to push generated detections into a Splunk environment

## Tips

- The PEAK report includes ABLE hypotheses — actor, behavior, location, evidence — for every hunt target
- Sigma rules in the report are `status: experimental`; promote to `status: test` after analyst validation
- Negative results are documented explicitly: "not found — data present" is very different from "not found — data absent"
- The HMM maturity target is HMM3; the report notes what data gaps are preventing HMM4
