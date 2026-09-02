# Threat Intel

An AI-native threat intelligence pipeline powered by OpenCTI, RSS feeds, or Slack — producing a rolling 30-day Threat Watch dashboard + daily Slack digests + hunt-ready IOC packages.

This is a conference demo project for **"Building AI Agents for Threat Intel"**.

---

## How the pipeline works

```
Source (opencti | slack | rss | splunk | stix)
        │
        ▼
sources/<source>.py   →   /tmp/tw-30d-processed.pkl  +  /tmp/tw-30d-published.json
        │
        ▼
generator/build.py    →   threat-watch.html  +  threat-watch-data.json
        │
        ├── digest agent     → daily Slack digest
        ├── threat-hunter    → SIEM hunt queries (SPL / KQL / Sigma)
        └── ioc-enricher     → public API enrichment (ipapi.co, crt.sh, NVD)
```

Run the whole pipeline with:
```bash
python3 quickstart.py                    # deterministic offline conference demo
python3 run.py --source sample --build  # bundled synthetic source
python3 run.py --source splunk --build   # pull from Splunk REST API
python3 run.py --source rss --build      # no account needed
python3 run.py --source opencti --build
python3 run.py --source slack --build
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and fill in the values for your chosen source:

```bash
cp .env.example .env
source .env
```

### Splunk source
- `SPLUNK_URL` — REST API base URL, e.g. `https://your-instance.splunkcloud.com:8089`
- `SPLUNK_TOKEN` — API token (preferred) OR `SPLUNK_USERNAME` + `SPLUNK_PASSWORD`
- `SPLUNK_SEARCH` — custom SPL (optional; defaults to `index=threat_intel | table _time, title, description, url, source`)
- `SPLUNK_EARLIEST` — time modifier (default: `-30d@d`)
- `SPLUNK_VERIFY_SSL` — set `false` for self-signed certs
- Field mappings: `SPLUNK_FIELD_NAME`, `SPLUNK_FIELD_DESC`, `SPLUNK_FIELD_URL`, `SPLUNK_FIELD_PUBLISHER`, `SPLUNK_FIELD_TIME`

### Live hunt config (splunk-hunter agent + /hunt-live)
- Reuses `SPLUNK_URL` + auth above
- `HUNT_FOCUS` — optional: actor name, technique, CVE, or free text

### OpenCTI source
- `OPENCTI_URL` — GraphQL endpoint, e.g. `http://host:8080/graphql`
- `OPENCTI_TOKEN` — API token

### Slack source
- `SLACK_TOKEN` — bot token (`xoxb-...`)
- `SLACK_CHANNEL_ID` — channel to read

### RSS source
- `RSS_FEEDS` — comma-separated feed URLs (optional; defaults to the curated list in `sources/feeds.py`)

### Agent / digest configuration
- `THREAT_WATCH_URL` — where the built JSON is served (agents read from here)
- `THREAT_WATCH_FILE` — or a local path to `threat-watch-data.json`
- `SLACK_TOKEN` — for the digest agent to post
- `SLACK_CHANNEL_ID` — target channel for digest posts

---

## Slash Commands

| Command | What it does |
|---------|-------------|
| `/rebuild [source]` | Fetch from a source and regenerate the dashboard (`splunk` \| `opencti` \| `slack` \| `rss` \| `stix`). |
| `/splunk-ingest [spl]` | Pull threat intel from Splunk via REST API. Optionally pass a custom SPL query. |
| `/peak-hunt [type] [focus]` | Full-lifecycle PEAK hunt — plan, execute, detect, report. Type: `hypothesis` \| `baseline` \| `math`. |
| `/check-pipeline` | Health check: dataset freshness, source connectivity, environment completeness, prior-hunts count. Read-only. |
| `/hunt [focus]` | Quick offline hunt: generate SPL + KQL + Sigma queries from the current dataset. |
| `/hunt-live [focus]` | Generate and execute SPL queries live against Splunk; returns actual findings. |
| `/enrich [ioc ...]` | Enrich IOCs from the dataset (or a provided list) via public APIs. |
| `/start-digest` | Register a daily Slack digest cron job. |

---

## Agents

| Agent | When to use |
|-------|-------------|
| `peak-hunt` | Full PEAK lifecycle hunt: plan → execute → detect → report. Reads `environment.md` and `prior-hunts/` for context. |
| `digest` | Posts a daily summary of the last 24h of cloud/AI reports to Slack. |
| `threat-hunter` | Generates hunt queries (SPL, KQL, Sigma) from the top signals — no live SIEM needed. |
| `splunk-hunter` | Executes SPL hunt queries live against Splunk via REST API; returns actual findings. |
| `late-ioc-matcher` | Retroactive IOC matching for threat intel that arrived after a device was cleaned. Searches Splunk history (default 90d), correlates against notable events, computes the latency gap, and classifies each match. Needs `SPLUNK_URL` + auth + `THREAT_WATCH_FILE` or `THREAT_WATCH_URL`. |
| `ioc-enricher` | Enriches IPs, domains, CVEs via ipapi.co, crt.sh, rdap.org, NVD. No API keys needed. |

---

## Setup files (update once, used by all hunts)

**`environment.md`** — Describes available Splunk indexes, sourcetypes, and key fields in your deployment. The `peak-hunt` agent reads this during PREPARE to scope hypotheses to telemetry that actually exists. Update the Status column as you verify each data source. A hypothesis pointing at an absent index is flagged Inconclusive before any query runs.

**`prior-hunts/`** — One YAML file per completed `/peak-hunt` run. Written automatically at hunt closure. The `peak-hunt` agent reads all entries at the start of PREPARE to avoid re-running the same hunt and to inherit false-positive notes. Do not delete entries — they are institutional memory.

---

## Repo structure

```
quickstart.py                 # deterministic offline build/serve entry point
run.py                        # top-level CLI: --source, --build
check_pipeline.py             # standalone health check (make status / /check-pipeline)
environment.md                # YOUR DEPLOYMENT — update indexes, sourcetypes, key fields
prior-hunts/                  # auto-written hunt index — one JSON per /peak-hunt run
sources/
├── base.py                   # shared helpers: actors, publishers, vendors, labels
├── sample.py                 # deterministic bundled conference dataset
├── splunk.py                 # Splunk REST API source (job submit → poll → results)
├── opencti.py                # OpenCTI GraphQL source
├── slack.py                  # Slack channel source
├── rss.py                    # RSS/Atom feed source
└── stix.py                   # STIX 2.x / TAXII 2.x source (zero extra dependencies)
generator/
└── build.py                  # aggregation + scoring → HTML + JSON (do not modify)
splunk/threat_watch/          # Splunk 9.x app — KV Store, dashboard, hunt alerts (see splunk/README.md)
agent/
└── digest-agent.md           # standalone agent definition (use without Claude Code)
.claude/
├── agents/
│   ├── peak-hunt.md          # PEAK full-lifecycle hunt (plan + execute + detect + report)
│   ├── digest.md             # Claude Code digest agent
│   ├── threat-hunter.md      # offline hunt query generation (SPL + KQL + Sigma)
│   ├── splunk-hunter.md      # live Splunk hunt — executes SPL, returns findings
│   ├── late-ioc-matcher.md   # retroactive IOC matching — exposure after device is cleaned
│   └── ioc-enricher.md       # public API enrichment agent
└── commands/
    ├── peak-hunt.md          # /peak-hunt command (full PEAK lifecycle)
    ├── rebuild.md            # /rebuild command
    ├── check-pipeline.md     # /check-pipeline — health check (freshness, connectivity, env)
    ├── splunk-ingest.md      # /splunk-ingest — pull from Splunk REST API
    ├── hunt.md               # /hunt command (offline, quick)
    ├── hunt-live.md          # /hunt-live — execute live against Splunk
    ├── enrich.md             # /enrich command
    └── start-digest.md       # /start-digest cron registration
```

---

## Key data contract

`build.py` reads one file: `/tmp/tw-30d-processed.pkl` — a Python pickle with schema:
```python
{"items": [<item>, ...], "cutoff": <datetime>}
```

Each item must have: `id`, `name`, `created` (timezone-aware UTC datetime), `confidence` (0-100), `all_labels` (list of strings like `"cloud"`, `"ai-llm"`), `publisher`, `url`, `tas` (threat actor names), `t1_vendors`, `t2_vendors`, `description`.

All six sources in `sources/` write this exact schema. `build.py` is source-agnostic.

---

## Extending with a new source

1. Create `sources/myplatform.py`
2. Implement a `run()` function that reads env vars, builds the items list, and calls `save_pickle(items, cutoff_dt, pkl_out)` and `save_published(pub_dates, pub_sidecar)` from `sources/base.py`
3. Register it in `run.py`'s `SOURCES` dict with its required env vars

That's it — `build.py`, all agents, and all commands work without modification.
