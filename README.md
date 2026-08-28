# Threat Intel

> **AI-native threat intelligence pipeline** — ingest from OpenCTI, Slack, or RSS feeds; score and cluster by cloud/AI relevance; generate a rolling dashboard, daily Slack digests, and SIEM-ready hunt queries — all driven by Claude agents.

Demo project for the talk **"Building AI Agents for Threat Intel"**.

---

## What it does

1. **Ingests** threat intel reports from your choice of source — OpenCTI, a Slack channel, or raw RSS/Atom feeds
2. **Scores and clusters** reports by cloud surface area, named adversaries, and publisher reach
3. **Builds** a self-contained HTML dashboard with CEO, CISO, and Analyst preset views
4. **Exports** a canonical JSON dataset that downstream agents consume
5. **Posts** a daily Slack digest of the last 24 hours
6. **Generates** hunt queries (Splunk SPL, KQL, Sigma) from the top signals
7. **Enriches** extracted IOCs via public no-auth APIs

Zero pip dependencies for the core pipeline. Python 3.9+. Runs locally or on a schedule via Claude Code's `CronCreate`.
(The `demo/sec1390` sub-project requires `pdfplumber` — see its own `requirements.txt`.)

---

## Architecture

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐
│ OpenCTI  │  │  Slack   │  │   RSS    │  │  Splunk  │  │   STIX / TAXII   │
│ GraphQL  │  │ channel  │  │  feeds   │  │ REST API │  │ TAXII 2.x server │
│   API    │  │ history  │  │ (stdlib) │  │          │  │ bundle URL/file  │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘
     │              │              │              │                 │
     └──────────────┴──────────────┴──────────────┴─────────────────┘
                                   │
                             sources/base.py
                   (shared: actors · publishers ·
                    vendors · labels · save helpers)
                                   │
                                   ▼
              tw-30d-processed.pkl  +  tw-30d-published.json
                                   │
                                   ▼
                          generator/build.py
                    (scoring · clustering · aggregation)
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
      threat-watch.html                     threat-watch-data.json
    (CEO / CISO / Analyst views)           (canonical dataset for agents)
              │                                         │
    ┌─────────┴──────────────────────────────────────────┤
    ▼                          ▼                         ▼
digest agent            threat-hunter               ioc-enricher
(daily Slack post)      (SPL/KQL/Sigma)             (ipapi · crt.sh · NVD)
```

---

## Quickstart

```bash
git clone https://github.com/matt-snyder-stuff/threat-intel.git
cd threat-intel

# Option A — Splunk REST API (your threat intel index or any search)
export SPLUNK_URL=https://your-instance.splunkcloud.com:8089
export SPLUNK_TOKEN=your-api-token
python3 run.py --source splunk --build

# Option B — RSS feeds (no account needed, great for demos)
export RSS_FEEDS="https://feeds.feedburner.com/TheHackersNews,https://www.bleepingcomputer.com/feed/"
python3 run.py --source rss --build

# Option C — OpenCTI
export OPENCTI_URL=http://your-opencti-host:8080/graphql
export OPENCTI_TOKEN=your-token
python3 run.py --source opencti --build

# Option D — Slack channel
export SLACK_TOKEN=xoxb-your-bot-token
export SLACK_CHANNEL_ID=C0123456789
python3 run.py --source slack --build

# Option E — TAXII 2.x server (e.g. AlienVault OTX, MISP, CISA AIS)
export TAXII_URL=https://otx.alienvault.com/taxii/
export TAXII_TOKEN=your-otx-api-key
python3 run.py --source stix --build

# Option F — Raw STIX bundle URL (no TAXII wrapper, e.g. MITRE ATT&CK)
export STIX_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python3 run.py --source stix --build

# Option G — Local STIX bundle file
export STIX_FILE=/path/to/bundle.json
python3 run.py --source stix --build
```

Use `python3 run.py --help` to see all options and env vars for each source.

---

## SEC1390 .conf Demo

The `.conf26` talk **The AI Detection Engineer** uses a replayable Splunk demo in [`demo/sec1390`](demo/sec1390).

The two files referenced in the slides are:

- [`demo/sec1390/run_agent_demo.py`](demo/sec1390/run_agent_demo.py)
- [`demo/sec1390/seed_splunk_demo.sh`](demo/sec1390/seed_splunk_demo.sh)

Quick replay:

```bash
cd demo/sec1390
python3 -m pip install -r requirements.txt
python3 run_agent_demo.py
./seed_splunk_demo.sh
```

The demo parses CyberAv3ngers/Iran PLC activity and TeamPCP CI/CD supply-chain intel, generates SPL, loads lookup artifacts, validates telemetry readiness, and scores detection confidence in Splunk.

---

## Sources

All five sources write the same pickle schema. `build.py` never knows which one ran.

| Source | How it works | Required env vars |
|--------|-------------|-------------------|
| `splunk` | Runs a search against Splunk via the REST API (job submit → poll → results). Maps result fields to the item schema; auto-detects labels and threat actors from text. Works with Splunk Cloud and on-prem. | `SPLUNK_URL` + `SPLUNK_TOKEN` |
| `opencti` | Pages through your OpenCTI instance's GraphQL API for reports labeled `cloud` or `ai`. Fetches confidence scores, SDO-linked threat actors, and a published-dates sidecar for accurate WoW math. | `OPENCTI_URL`, `OPENCTI_TOKEN` |
| `slack` | Reads messages from a Slack channel via `conversations.history`. Treats each message as a report — URLs become the article link, auto-detects cloud/AI labels from text. | `SLACK_TOKEN`, `SLACK_CHANNEL_ID` |
| `rss` | Fetches and parses RSS and Atom feeds directly using stdlib `urllib` + `xml.etree`. No OpenCTI, no Slack, no extra installs. | none — `RSS_FEEDS` is optional (defaults to 40+ curated feeds in `sources/feeds.py`) |
| `stix` | Ingests STIX 2.x Report, Indicator, Threat Actor, Attack Pattern, Campaign, Malware, and Vulnerability objects. Supports TAXII 2.0/2.1 servers (auto-discovers API root and collections), raw STIX bundle URLs, and local bundle files. Zero extra dependencies (pure stdlib). | at least one of: `TAXII_URL`, `STIX_URL`, or `STIX_FILE` |

Optional env vars shared across sources:

```bash
CUTOFF_DAYS=30                              # lookback window (default: 30)
PKL_OUT=/tmp/tw-30d-processed.pkl           # pickle path
PUB_SIDECAR=/tmp/tw-30d-published.json      # published-dates sidecar
HTML_OUT=/tmp/threat-watch.html             # dashboard output path
JSON_OUT=/tmp/threat-watch-data.json        # JSON dataset output path
```

---

## Dashboard

The built `threat-watch.html` is a single self-contained file with four preset views:

| View | Audience | Sections shown |
|------|----------|----------------|
| **Full** | SOC analyst | Everything |
| **CEO Brief** | Executive | Exec overview · Containment banner · Top cloud clusters · Industry trends |
| **CISO Brief** | CISO | + Threat actor watch · Vendor watch · Filter chips |
| **Analyst Brief** | Threat intel analyst | Everything except Containment Impact |

Each cloud threat cluster card has a hover popover with key points, extracted IOCs, MITRE ATT&CK mappings, and talking points.

### Scoring

**Industry Reach Index** (0–100) per cluster:

```
reach = (unique publishers × 12) + (cloud sub-tags × 7) + (AI sub-tags × 5) + (named actors × 8)
```

**Containment Relevance** — reports scored against patterns that network-level controls address: lateral movement, supply chain, credential reuse, container/K8s pivot, C2/exfil, ransomware. Heuristic scoring, not retroactive attribution.

---

## Claude Agents

Drop these into your `.claude/agents/` directory to use them with [Claude Code](https://claude.ai/code).

| Agent | What it does |
|-------|-------------|
| [`peak-hunt`](.claude/agents/peak-hunt.md) | Full-lifecycle PEAK hunt: reads `environment.md` + `prior-hunts/`, writes ABLE hypotheses, executes COUNT-FIRST queries, generates Sigma rules + SPL correlation searches, writes closure report and prior-hunts index entry |
| [`digest`](.claude/agents/digest.md) | Reads `threat-watch-data.json`, formats the last 24h of cloud/AI reports, posts to Slack |
| [`threat-hunter`](.claude/agents/threat-hunter.md) | Extracts the top 3 hunt-worthy signals and generates queries in Splunk SPL, KQL (Sentinel/Defender), and Sigma YAML — no live SIEM needed |
| [`splunk-hunter`](.claude/agents/splunk-hunter.md) | Like `threat-hunter` but executes the SPL live against Splunk via the REST API and reports actual findings (COUNT-FIRST enforced) |
| [`late-ioc-matcher`](.claude/agents/late-ioc-matcher.md) | **Retroactive IOC matching.** Searches Splunk historical indexes (default 90d) for IOCs that arrived late — after a device may already have been cleaned. Correlates device notable event history, computes the latency gap (days between device exposure and intel publish date), and classifies each match: high confidence / possible / late intel only / no exposure. Surfaces detection gaps where alerts should have fired but didn't. |
| [`ioc-enricher`](.claude/agents/ioc-enricher.md) | Enriches IPs, domains, and CVEs via ipapi.co, crt.sh, rdap.org, and the NVD — no API keys required |

The standalone [`agent/digest-agent.md`](agent/digest-agent.md) works without Claude Code — it queries OpenCTI directly and can be wired to any Claude agent runtime.

### Slash Commands

| Command | What it does |
|---------|-------------|
| `/peak-hunt [type] [focus]` | Full PEAK lifecycle hunt — plan, execute, detect, report, index. Type: `hypothesis` \| `baseline` \| `math` |
| `/rebuild [source]` | Fetch from a source and regenerate the dashboard (`opencti` \| `splunk` \| `slack` \| `rss` \| `stix`) |
| `/check-pipeline` | Health check: dataset freshness, source connectivity, environment completeness, prior-hunts status |
| `/splunk-ingest [spl]` | Pull threat intel from Splunk via the REST API — optionally pass a custom SPL query |
| `/hunt [focus]` | Quick offline hunt: generate SPL + KQL + Sigma queries from the current dataset |
| `/hunt-live [focus]` | Generate and execute SPL queries live against Splunk; returns actual findings |
| `/enrich [iocs]` | Enrich extracted or provided IOCs via public APIs |
| `/start-digest` | Register a daily Slack digest via Claude Code's `CronCreate` |

---

## Dataset schema (`threat-watch-data.json`)

The JSON export is the single canonical dataset consumed by all downstream agents and tools. Schema version `1.0`.

```json
{
  "generated_at":   "ISO timestamp",
  "window_days":    30,
  "schema_version": "1.0",

  "summary": {
    "total_reports": 142, "cloud": 89, "ai": 53, "publishers": 18
  },

  "executive_overview": {
    "thesis":      "...",
    "stats":       [{ "value": "89", "label": "cloud-relevant reports / 30d", "kind": "num" }],
    "imperatives": [{ "label": "Adversary watch", "body": "..." }]
  },

  "cloud_clusters": [{
    "reach_score": 87, "size": 23,
    "cloud_tags": ["cloud-aws", "cloud-container"], "ai_tags": [],
    "publishers": ["BleepingComputer"], "threat_actors": ["Lazarus"],
    "lead":    { "id": "...", "name": "...", "url": "...", "labels": [...] },
    "reports": [{ "id": "...", "name": "...", "url": "...", "tas": [...] }]
  }],

  "threat_actors":   [{ "name": "...", "count": 7, "last7": 3, "wow": "up" }],
  "vendor_watch":    { "tier1": [...], "tier2": [...] },
  "industry_trends": [{ "name": "...", "count": 65, "narrative": "...", "examples": [...] }],
  "containment_impact": [{ "score": 85, "matched": [...], "narrative": "...", "report": {...} }],

  "last_24h": {
    "count": 3, "cloud_count": 2, "ai_count": 1,
    "vendor_hits": ["GitHub", "AWS"],
    "reports": [{ "id": "...", "name": "...", "labels": [...], "description": "..." }]
  }
}
```

**Consuming the dataset from an agent:**

```bash
curl -sf http://your-host/threat-watch-data.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('Generated:', d['generated_at'])
print('Last 24h:', d['last_24h']['count'], 'reports')
for r in d['last_24h']['reports']:
    print(' -', r['name'], r['labels'])
"
```

---

## Adding a new source

1. Create `sources/myplatform.py`
2. Implement `run()` — read env vars, build the items list, call `save_pickle` and `save_published` from `sources/base.py`
3. Add it to `SOURCES` in `run.py`

Each item needs:

```python
{
    "id":          str,           # unique identifier
    "name":        str,           # title
    "created":     datetime,      # timezone-aware UTC
    "confidence":  int,           # 0–100
    "all_labels":  list[str],     # e.g. ["cloud", "cloud-aws", "ai-llm"]
    "labels":      list[str],     # same list (alias)
    "publisher":   str,
    "url":         str,
    "tas":         list[str],     # threat actor names
    "t1_vendors":  list[str],
    "t2_vendors":  list[str],
    "description": str,
}
```

`build.py`, all agents, and all commands work without modification.

---

## Repo structure

```
run.py                         # CLI: --source {splunk,opencti,slack,rss,stix} [--build]
check_pipeline.py              # standalone pipeline health check (see make status)
environment.md                 # YOUR DEPLOYMENT — update Splunk indexes, sourcetypes, fields
prior-hunts/                   # auto-written hunt index — one JSON per /peak-hunt run
sources/
├── base.py                    # shared: actors, publishers, vendors, label detection
├── splunk.py                  # Splunk REST API source (job submit → poll → results)
├── opencti.py                 # OpenCTI GraphQL source
├── slack.py                   # Slack channel source
├── rss.py                     # RSS/Atom source
└── stix.py                    # STIX 2.x / TAXII 2.x source (zero extra dependencies)
generator/
└── build.py                   # aggregation + scoring → HTML + JSON  ← do not modify
splunk/
└── threat_watch/              # Splunk 9.x app — KV Store ingestion, dashboard, hunt alerts
    └── (see splunk/README.md for install instructions)
agent/
└── digest-agent.md            # standalone agent (no Claude Code needed)
.claude/
├── agents/                    # Claude Code agent definitions
│   ├── peak-hunt.md           # PEAK full-lifecycle hunt (plan + execute + detect + report)
│   ├── digest.md
│   ├── threat-hunter.md       # offline: generates SPL + KQL + Sigma
│   ├── splunk-hunter.md       # live: executes SPL, returns findings (COUNT-FIRST)
│   ├── late-ioc-matcher.md    # retroactive IOC matching — finds exposure after device is cleaned
│   └── ioc-enricher.md
└── commands/                  # Claude Code slash commands
    ├── peak-hunt.md           # /peak-hunt — full PEAK lifecycle
    ├── rebuild.md
    ├── check-pipeline.md      # /check-pipeline — health check (freshness, connectivity, env)
    ├── splunk-ingest.md       # pull threat intel from Splunk
    ├── hunt.md
    ├── hunt-live.md           # hunt + execute live against Splunk
    ├── enrich.md
    └── start-digest.md
.env.example                   # copy to .env, fill in your values
CLAUDE.md                      # project guide for Claude Code
```

---

## Splunk App

The `splunk/threat_watch/` directory contains a Splunk 9.x app that ingests the pipeline's JSON dataset into KV Store, surfaces intel in a unified dashboard, and ships pre-built hunt searches and alert rules.

See **[splunk/README.md](splunk/README.md)** for installation, data ingestion, and dashboard usage.

Quick install:

```bash
cp -r splunk/threat_watch "$SPLUNK_HOME/etc/apps/"
"$SPLUNK_HOME/bin/splunk" restart
```

The app uses four KV Store collections: `threat_clusters`, `threat_actors`, `ioc_watchlist`, and `hunt_results`. The included `threat_intel_ingest` saved search imports from the pipeline JSON; configure `THREAT_WATCH_JSON_PATH` in `savedsearches.conf` to point at your output file.

---

## Pipeline health check

```bash
make status           # uses .env if present
python3 check_pipeline.py    # or run directly
```

Or from Claude Code: `/check-pipeline`

Checks: dataset freshness · OpenCTI connectivity · Splunk connectivity · Slack auth · `environment.md` completeness · prior-hunts record count. Read-only, no data modified. Exits with code 1 on any FAIL.

---

## Contributing

PRs welcome. The highest-value additions are:

- **New sources** — VirusTotal, MISP, email ingest
- **New threat actors** in `KNOWN_ACTORS` (`sources/base.py`)
- **New publisher mappings** in `PUBLISHER_MAP` (`sources/base.py`)
- **New vendor names** in `VENDORS_TIER1` / `VENDORS_TIER2` (`sources/base.py`)
- **New industry trend buckets** in `TREND_BUCKETS` (`generator/build.py`)
- **New containment pattern categories** in `CONTAINMENT_PATTERNS` (`generator/build.py`)

---

## License

MIT
