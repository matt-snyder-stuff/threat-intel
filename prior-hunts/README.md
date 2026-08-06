# Prior Hunts Index

This directory stores a lightweight record of every completed `/peak-hunt` run.

Each hunt closure writes one JSON file here. The `peak-hunt` agent reads all
entries at the start of PREPARE to avoid re-running hunts that have already
been executed, and to inherit lessons and false-positive notes from past work.

## File naming

```
HUNT-YYYYMMDD-<slug>.json
```

Example: `HUNT-20260801-apt40-cloud-token-abuse.json`

## Schema

```json
{
  "hunt_id": "HUNT-20260801-apt40-cloud-token-abuse",
  "date": "2026-08-01",
  "hunt_type": "hypothesis",
  "focus": "APT40 cloud token abuse",
  "hypotheses": [
    {
      "id": "H1",
      "actor": "APT40",
      "behavior": "T1078.004 - Valid Accounts: Cloud Accounts",
      "location": "cloud",
      "evidence_field": "index=cloud sourcetype=aws:cloudtrail eventName=AssumeRole",
      "outcome": "negative_data_present",
      "data_sources_present": true
    },
    {
      "id": "H2",
      "actor": "APT40",
      "behavior": "T1530 - Data from Cloud Storage Object",
      "location": "cloud",
      "evidence_field": "index=cloud sourcetype=aws:cloudtrail eventName=GetObject",
      "outcome": "inconclusive_data_absent",
      "data_sources_present": false,
      "data_gap": "S3 access logs not enabled in this account"
    }
  ],
  "mitre_techniques": ["T1078.004", "T1530"],
  "confirmed_findings": 0,
  "detection_artifacts": [],
  "key_fp_notes": "AssumeRole events from CI/CD role arn:aws:iam::*:role/github-actions are expected",
  "re_hunt_trigger": "Re-run if S3 access logging is enabled or after next APT40 campaign report",
  "queries_run": 5,
  "dataset_generated_at": "2026-08-01T06:00:00Z"
}
```

## How the peak-hunt agent uses this

At the start of PREPARE, the agent scans all JSON files and checks:
1. Have any of the same MITRE techniques been hunted in the last 90 days?
2. Have any of the same threat actors been the hunt focus recently?
3. Are there FP notes that should be inherited into this hunt's success criteria?

If a near-duplicate hunt is found (same technique + same environment zone, <90 days ago),
the agent notes it in the hunt plan and adjusts the hypothesis to look for new signals
rather than repeating the same query unchanged.

Do not delete entries. They are the institutional memory of this hunt program.
