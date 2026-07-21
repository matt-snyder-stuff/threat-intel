#!/usr/bin/env python3
"""Refresh `/tmp/tw-30d-published.json` — a map of {report_id: published_iso}
for every report ingested with the `rss` label since the dashboard cutoff.

This file is a thin wrapper kept for backwards compatibility.
All logic now lives in sources/opencti.py (which calls sources/base.py for shared helpers).

Note: when using the top-level CLI (`python3 run.py --source opencti`), this step is
performed automatically as part of the OpenCTI source run — you no longer need to call
fetch_published.py separately.

`build.py` reads this sidecar so WoW math can use the real publication date
instead of OpenCTI's ingest timestamp. Without it, recently-backfilled
historical content (e.g. Wiz threats.wiz.io records) inflates last-7-day
counts and creates fake "🆕 N this week" deltas.
"""
import json, os, sys

# Ensure the repo root is on the path so `sources/` is importable
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from sources.opencti import fetch_published_dates
from sources.base import save_published

URL   = os.environ.get("OPENCTI_URL")
TOKEN = os.environ.get("OPENCTI_TOKEN")

if __name__ == "__main__":
    if not URL or not TOKEN:
        print("Error: OPENCTI_URL and OPENCTI_TOKEN environment variables are required.", file=sys.stderr)
        sys.exit(1)

    out_path = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")
    data = fetch_published_dates(URL, TOKEN)
    save_published(data, out_path)
    print(f"Wrote {out_path} ({len(data)} report IDs)", file=sys.stderr)
