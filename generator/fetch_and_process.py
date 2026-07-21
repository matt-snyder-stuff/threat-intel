#!/usr/bin/env python3
"""Fetch 30 days of cloud/AI Reports from OpenCTI → tw-30d.json + tw-30d-processed.pkl.

This file is a thin wrapper kept for backwards compatibility.
All logic now lives in sources/opencti.py (which calls sources/base.py for shared helpers).

Run this before build.py (and fetch_published.py for honest WoW math):
  python3 fetch_and_process.py
  python3 fetch_published.py
  python3 build.py

Or use the top-level CLI from the repo root:
  python3 run.py --source opencti --build

Required env vars:
  OPENCTI_URL   — e.g. http://your-opencti-host:8080/graphql
  OPENCTI_TOKEN — your OpenCTI API token

Optional env vars:
  RAW_OUT       — JSON dump path (default /tmp/tw-30d.json)
  PKL_OUT       — pickle path   (default /tmp/tw-30d-processed.pkl)
  CUTOFF_DAYS   — lookback window in days (default 30)
"""
import os, sys

# Ensure the repo root is on the path so `sources/` is importable
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from sources.opencti import run

if __name__ == "__main__":
    run()
