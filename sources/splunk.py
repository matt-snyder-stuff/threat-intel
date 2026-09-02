#!/usr/bin/env python3
"""Splunk source — run a search against Splunk REST API and convert results to items.

Required env vars:
  SPLUNK_URL       — https://your-instance.splunkcloud.com:8089
  SPLUNK_TOKEN     — API token (preferred)
    OR
  SPLUNK_USERNAME + SPLUNK_PASSWORD — basic auth fallback

Optional env vars:
  SPLUNK_SEARCH          — full SPL query to run (see DEFAULT_SEARCH below)
  SPLUNK_EARLIEST        — earliest time modifier (default: -30d@d)
  SPLUNK_FIELD_NAME      — result field to use as item name       (default: title)
  SPLUNK_FIELD_DESC      — result field for description           (default: description)
  SPLUNK_FIELD_URL       — result field for article URL           (default: url)
  SPLUNK_FIELD_PUBLISHER — result field for publisher/source name (default: source)
  SPLUNK_FIELD_TIME      — result field for timestamp             (default: _time)
  SPLUNK_VERIFY_SSL      — set to "false" to skip TLS verify      (default: true)
  CUTOFF_DAYS            — lookback window in days                (default: 30)
  PKL_OUT                — pickle output path
  PUB_SIDECAR            — published-dates sidecar path
"""
import os, sys
from datetime import datetime, timezone, timedelta

from guardrails.splunk import SplunkClient

from sources.base import (
    extract_tas, extract_vendors, extract_iocs, VENDORS_TIER1, VENDORS_TIER2,
    _VRE1, _VRE2, auto_labels, publisher_from_url, save_pickle, save_published,
    lifecycle_fields,
)

# Default search — finds items in a threat intel index or lookup.
# Override completely with SPLUNK_SEARCH if your data lives elsewhere.
DEFAULT_SEARCH = (
    "search index=threat_intel OR index=main sourcetype=threat_intel "
    "| table _time, title, description, url, source, confidence "
    "| sort -_time"
)

def _run_search(base_url, spl, earliest):
    """Submit a policy-validated search and return bounded results."""
    limit = int(os.environ.get("SPLUNK_MAX_RESULTS", "500"))
    result = SplunkClient(base_url=base_url).search(spl, earliest, max_results=limit)
    print(f"[splunk] Job {result.sid}: fetched {len(result.rows)} results", file=sys.stderr)
    return result.rows


def _parse_time(raw):
    """Parse _time (epoch float or ISO string) → timezone-aware UTC datetime."""
    if not raw:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(str(raw)[:26], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def run():
    base_url = os.environ.get("SPLUNK_URL", "").rstrip("/")
    if not base_url:
        print("Error: SPLUNK_URL is required", file=sys.stderr)
        sys.exit(1)

    spl      = os.environ.get("SPLUNK_SEARCH", DEFAULT_SEARCH)
    earliest = os.environ.get("SPLUNK_EARLIEST", f"-{os.environ.get('CUTOFF_DAYS', '30')}d@d")
    pkl_out  = os.environ.get("PKL_OUT",     "/tmp/tw-30d-processed.pkl")
    pub_out  = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")

    # Field name overrides
    f_name   = os.environ.get("SPLUNK_FIELD_NAME",      "title")
    f_desc   = os.environ.get("SPLUNK_FIELD_DESC",      "description")
    f_url    = os.environ.get("SPLUNK_FIELD_URL",        "url")
    f_pub    = os.environ.get("SPLUNK_FIELD_PUBLISHER",  "source")
    f_time   = os.environ.get("SPLUNK_FIELD_TIME",       "_time")

    rows = _run_search(base_url, spl, earliest)

    items, pub_dates = [], {}
    for i, row in enumerate(rows):
        name   = str(row.get(f_name,   row.get("name", f"Splunk result {i}")))
        desc   = str(row.get(f_desc,   row.get("body", "")))
        url    = str(row.get(f_url,    row.get("link", "")))
        pub    = str(row.get(f_pub,    "Splunk"))
        raw_t  = row.get(f_time, row.get("_time", ""))
        created = _parse_time(raw_t)
        item_id = str(row.get("_cd", row.get("_key", row.get("id", f"splunk-{i}"))))

        try:
            conf = int(float(str(row.get("confidence", 75))))
        except (ValueError, TypeError):
            conf = 75
        conf = max(0, min(100, conf))

        if not pub or pub == "Splunk":
            pub = publisher_from_url(url) if url else "Splunk"

        labels  = auto_labels(f"{name} {desc}")
        tas     = extract_tas(name, desc, row.get("threat_actors", "").split(",") if row.get("threat_actors") else [])
        t1v     = extract_vendors(name, desc, _VRE1, VENDORS_TIER1)
        t2v     = extract_vendors(name, desc, _VRE2, VENDORS_TIER2)

        item = {
            "id":                   item_id,
            "name":                 name,
            "created":              created,
            "confidence":           conf,
            "all_labels":           labels,
            "labels":               labels,
            "publisher":            pub,
            "url":                  url,
            "tas":                  tas,
            "t1_vendors":           t1v,
            "t2_vendors":           t2v,
            "description":          desc,
            "attack_technique_ids": [],
            "mitre_tactics":        [],
            "iocs":                 extract_iocs(desc),
            **lifecycle_fields(pub, "splunk"),
        }
        items.append(item)
        if url:
            pub_dates[item_id] = created.isoformat()

    if not items:
        print("[splunk] No results returned — check your SPLUNK_SEARCH query.", file=sys.stderr)
        sys.exit(1)

    cutoff_days = int(os.environ.get("CUTOFF_DAYS", "30"))
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=cutoff_days)
    save_pickle(items, cutoff_dt, pkl_out)
    save_published(pub_dates, pub_out)
    print(f"[splunk] Wrote {len(items)} items → {pkl_out}", file=sys.stderr)
