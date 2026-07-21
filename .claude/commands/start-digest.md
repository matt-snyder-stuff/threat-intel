# /start-digest

Register the Threat Intel Digest as a recurring daily cron job. Reads from threat-watch-data.json and posts a formatted summary to Slack.

## Prerequisites

Make sure these env vars are set:
- `THREAT_WATCH_URL` or `THREAT_WATCH_FILE` — where to read the dataset from
- `SLACK_TOKEN` — Slack bot token
- `SLACK_CHANNEL_ID` — target channel

## Steps

1. Validate that `SLACK_CHANNEL_ID` is set. If not, print:
   ```
   SLACK_CHANNEL_ID is required. Set it in your environment and re-run /start-digest.
   ```
   and STOP.

2. Call `CronCreate` with:
   - **cron:** `0 9 * * *` (daily at 09:00 UTC — adjust to your timezone)
   - **recurring:** true
   - **prompt:**
     ```
     Threat Intel Digest — daily run.

     GOAL: Read threat-watch-data.json and post a digest of the last 24h of
     cloud- and AI-relevant reports to Slack channel $SLACK_CHANNEL_ID.

     Use the `digest` agent to perform the full digest workflow.

     Configuration:
       THREAT_WATCH_URL = $THREAT_WATCH_URL
       THREAT_WATCH_FILE = $THREAT_WATCH_FILE
       SLACK_TOKEN = $SLACK_TOKEN
       SLACK_CHANNEL_ID = $SLACK_CHANNEL_ID
     ```

3. Print the returned cron job ID and the next scheduled run time.

4. Print a reminder:
   ```
   Digest scheduled daily at 09:00 UTC.
   The digest reads from threat-watch-data.json — make sure your pipeline
   rebuilds the dataset before this time each day (e.g. schedule /rebuild at 08:00).
   Re-run /start-digest to reset the schedule.
   ```

## What the digest posts

Each day's post looks like:

```
🛰️ Threat Intel Digest — 2026-07-17 UTC
3 reports in the last 24h · 🤖 2 AI · ☁️ 1 cloud · 📰 2 publishers

*The Hacker News* (2)
• <url|Title of article one>  ⟶  `cloud-aws` `ai-llm`
• <url|Title of article two>  ⟶  `ai-agentic`

*BleepingComputer* (1)
• <url|Title of article three>  ⟶  `cloud-k8s`
```

Empty days post: `📭 Threat Intel Digest — <date> No new cloud- or AI-relevant reports in the last 24 hours.`
