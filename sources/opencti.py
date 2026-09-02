#!/usr/bin/env python3
"""OpenCTI source — fetches 30-day cloud/AI reports from an OpenCTI instance.

Required env:
  OPENCTI_URL   — e.g. http://your-opencti-host:8080/graphql
  OPENCTI_TOKEN — your OpenCTI API token

Optional env:
  RAW_OUT       — JSON dump path  (default /tmp/tw-30d.json)
  PKL_OUT       — pickle path     (default /tmp/tw-30d-processed.pkl)
  PUB_SIDECAR   — sidecar path    (default /tmp/tw-30d-published.json)
  CUTOFF_DAYS   — lookback window (default 30)
"""
import json, os, sys, urllib.request
from datetime import datetime, timezone, timedelta

from sources.base import (
    publisher_from_url,
    extract_tas,
    extract_vendors,
    extract_iocs,
    auto_labels,
    save_pickle,
    save_published,
    lifecycle_fields,
    atomic_write_json,
    _VRE1, _VRE2,
    VENDORS_TIER1, VENDORS_TIER2,
)

# ── GraphQL query ─────────────────────────────────────────────────────────────
QUERY = """
query($first: Int, $after: ID) {
  reports(
    first: $first
    after: $after
    filters: {
      mode: or
      filterGroups: []
      filters: [
        { key: "objectLabel", values: ["cloud"] }
        { key: "objectLabel", values: ["ai"] }
      ]
    }
    orderBy: created_at
    orderMode: desc
  ) {
    pageInfo { hasNextPage endCursor globalCount }
    edges {
      node {
        id
        name
        description
        published
        created_at
        confidence
        objectLabel { value }
        externalReferences {
          edges { node { url } }
        }
        objects {
          edges {
            node {
              ... on ThreatActor { name }
            }
          }
        }
      }
    }
  }
}
"""

PUBLISHED_QUERY = """
query($first: Int, $after: ID) {
  reports(
    first: $first
    after: $after
    filters: { mode: and, filterGroups: [], filters: [{ key: "objectLabel", values: ["rss"] }] }
    orderBy: created_at
    orderMode: desc
  ) {
    pageInfo { hasNextPage endCursor }
    edges { node { id published } }
  }
}
"""


def _gql(url, token, query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def fetch_all_raw(url, token, cutoff_iso):
    """Page through reports until we hit the cutoff date or exhaust results."""
    all_edges = []
    cursor = None
    page = 0
    while True:
        resp = _gql(url, token, QUERY, {"first": 500, "after": cursor})
        if "errors" in resp:
            print(f"GraphQL error: {resp['errors']}", file=sys.stderr)
            break
        data = resp["data"]["reports"]
        edges = data["edges"]
        if not edges:
            break
        for e in edges:
            n = e["node"]
            ts = n.get("created_at", "")
            if ts and ts < cutoff_iso:
                print(f"  Hit cutoff at page {page}, {len(all_edges)} edges collected", file=sys.stderr)
                return all_edges
            all_edges.append(e)
        pi = data["pageInfo"]
        page += 1
        total = pi.get("globalCount", "?")
        print(f"  Page {page}: {len(all_edges)}/{total} edges", file=sys.stderr)
        if not pi["hasNextPage"] or page >= 40:
            break
        cursor = pi["endCursor"]
    return all_edges


def fetch_published_dates(url, token):
    """Fetch published dates for all rss-labeled reports.

    Returns dict of {report_id: published_iso}.
    """
    out = {}
    cursor = None
    page = 0
    while True:
        resp = _gql(url, token, PUBLISHED_QUERY, {"first": 500, "after": cursor})
        edges = resp["data"]["reports"]["edges"]
        for e in edges:
            n = e["node"]
            if n.get("published"):
                out[n["id"]] = n["published"]
        pi = resp["data"]["reports"]["pageInfo"]
        page += 1
        if not pi["hasNextPage"] or page >= 20:
            break
        cursor = pi["endCursor"]
    return out


def run():
    url   = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN")

    if not url or not token:
        print("Error: OPENCTI_URL and OPENCTI_TOKEN environment variables are required.", file=sys.stderr)
        print("  export OPENCTI_URL=http://your-opencti-host:8080/graphql", file=sys.stderr)
        print("  export OPENCTI_TOKEN=your-api-token", file=sys.stderr)
        sys.exit(1)

    raw_out     = os.environ.get("RAW_OUT",     "/tmp/tw-30d.json")
    pkl_out     = os.environ.get("PKL_OUT",     "/tmp/tw-30d-processed.pkl")
    pub_sidecar = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")
    cutoff_days = int(os.environ.get("CUTOFF_DAYS", "30"))

    now        = datetime.now(timezone.utc)
    cutoff_dt  = now - timedelta(days=cutoff_days)
    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    print(f"Fetching reports from {cutoff_iso} to {now.isoformat()}", file=sys.stderr)

    # Step 1: Fetch raw data
    print("Fetching from OpenCTI...", file=sys.stderr)
    edges = fetch_all_raw(url, token, cutoff_iso)
    print(f"Total edges fetched: {len(edges)}", file=sys.stderr)

    # Build raw JSON structure that build.py reads for descriptions
    raw = {"data": {"reports": {"edges": edges}}}
    atomic_write_json(raw_out, raw)
    print(f"Wrote {raw_out}", file=sys.stderr)

    # Step 2: Process into items list
    items = []
    for e in edges:
        n = e["node"]
        # Labels: merge OpenCTI object labels with auto-detected sub-labels from text
        raw_labels = [lbl["value"] for lbl in (n.get("objectLabel") or [])]
        computed   = auto_labels((n.get("name") or "") + " " + (n.get("description") or ""))
        labels     = list(dict.fromkeys(raw_labels + computed))
        # External URL (first reference)
        ext_refs = (n.get("externalReferences") or {}).get("edges") or []
        url_val = ext_refs[0]["node"]["url"] if ext_refs else ""
        # Publisher
        publisher = publisher_from_url(url_val)
        # SDO-linked threat actors
        obj_edges = (n.get("objects") or {}).get("edges") or []
        obj_tas = [oe["node"]["name"] for oe in obj_edges if oe.get("node", {}).get("name")]
        # Extract TAs from text + SDO links
        tas = extract_tas(n.get("name", ""), n.get("description", ""), obj_tas)
        # Parse created_at timestamp
        ts_str = n.get("created_at", "")
        try:
            created = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            created = now

        name = n.get("name", "")
        desc = n.get("description", "") or ""
        t1_vend = extract_vendors(name, desc, _VRE1, VENDORS_TIER1)
        t2_vend = extract_vendors(name, desc, _VRE2, VENDORS_TIER2)

        items.append({
            "id":                   n["id"],
            "name":                 name,
            "created":              created,
            "confidence":           max(0, min(100, int(n.get("confidence") or 0))),
            "all_labels":           labels,
            "labels":               labels,   # alias — build.py uses both keys
            "publisher":            publisher,
            "url":                  url_val,
            "tas":                  tas,
            "t1_vendors":           t1_vend,
            "t2_vendors":           t2_vend,
            "description":          desc,
            "attack_technique_ids": [],
            "mitre_tactics":        [],
            "iocs":                 extract_iocs(desc),
            **lifecycle_fields(publisher, "opencti"),
        })

    print(f"Processed {len(items)} items (cutoff: {cutoff_dt.date()})", file=sys.stderr)

    # Step 3: Write pickle
    save_pickle(items, cutoff_dt, pkl_out)
    print(f"Wrote {pkl_out}", file=sys.stderr)

    # Step 4: Fetch and write published-dates sidecar
    print("Fetching published dates sidecar...", file=sys.stderr)
    pub_dates = fetch_published_dates(url, token)
    save_published(pub_dates, pub_sidecar)
    print(f"Wrote {pub_sidecar} ({len(pub_dates)} report IDs)", file=sys.stderr)


if __name__ == "__main__":
    run()
