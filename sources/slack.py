#!/usr/bin/env python3
"""Slack source — reads threat intel from a Slack channel.

Each message in the channel is treated as a threat-intel item. URLs extracted
from the message text become the article URL; the first line of the message
becomes the title.

Required env:
  SLACK_TOKEN       — Slack bot token (xoxb-...)
  SLACK_CHANNEL_ID  — channel to read (e.g. C0123456789)

Optional env:
  SLACK_LOOKBACK_DAYS — how many days back to read (default 30)
  PKL_OUT             — pickle output path (default /tmp/tw-30d-processed.pkl)
  PUB_SIDECAR         — sidecar JSON path  (default /tmp/tw-30d-published.json)
"""
import json, os, re, sys, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta

from sources.base import (
    publisher_from_url,
    confidence_for_publisher,
    lifecycle_fields,
    extract_tas,
    extract_vendors,
    extract_iocs,
    save_pickle,
    save_published,
    auto_labels,
    _VRE1, _VRE2,
    VENDORS_TIER1, VENDORS_TIER2,
)

_URL_RE = re.compile(r"https?://[^\s<>\"\]]+")


def _slack_get(token, method, params):
    """Call a Slack Web API method via GET (urllib, no extra deps)."""
    base = f"https://slack.com/api/{method}"
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base}?{qs}" if qs else base
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _fetch_messages(token, channel_id, oldest_ts):
    """Page through conversations.history and return all messages since oldest_ts."""
    messages = []
    cursor = None
    while True:
        params = {
            "channel": channel_id,
            "oldest":  str(oldest_ts),
            "limit":   200,
        }
        if cursor:
            params["cursor"] = cursor
        resp = _slack_get(token, "conversations.history", params)
        if not resp.get("ok"):
            print(f"Slack API error: {resp.get('error', 'unknown')}", file=sys.stderr)
            break
        messages.extend(resp.get("messages", []))
        meta = resp.get("response_metadata", {})
        cursor = meta.get("next_cursor")
        if not cursor:
            break
    return messages


def run():
    token      = os.environ.get("SLACK_TOKEN")
    channel_id = os.environ.get("SLACK_CHANNEL_ID")

    if not token or not channel_id:
        print("Error: SLACK_TOKEN and SLACK_CHANNEL_ID environment variables are required.", file=sys.stderr)
        print("  export SLACK_TOKEN=xoxb-your-bot-token", file=sys.stderr)
        print("  export SLACK_CHANNEL_ID=C0123456789", file=sys.stderr)
        sys.exit(1)

    lookback_days = int(os.environ.get("SLACK_LOOKBACK_DAYS", "30"))
    pkl_out       = os.environ.get("PKL_OUT",     "/tmp/tw-30d-processed.pkl")
    pub_sidecar   = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")

    now       = datetime.now(timezone.utc)
    cutoff_dt = now - timedelta(days=lookback_days)
    oldest_ts = cutoff_dt.timestamp()

    print(f"Reading Slack channel {channel_id} (last {lookback_days} days)...", file=sys.stderr)
    messages = _fetch_messages(token, channel_id, oldest_ts)
    print(f"Fetched {len(messages)} messages", file=sys.stderr)

    items = []
    for msg in messages:
        # Skip bot messages, sub-types (join/leave), and empty texts
        if msg.get("subtype") or not msg.get("text"):
            continue

        text = msg["text"]
        ts   = msg["ts"]   # Slack timestamp string, e.g. "1720000000.123456"

        # created datetime from Slack ts
        try:
            created = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except (ValueError, TypeError):
            created = now

        # Extract URLs
        urls = _URL_RE.findall(text)
        # Slack wraps URLs as <URL> or <URL|label> — strip those too
        slack_url_re = re.compile(r"<(https?://[^|>]+)(?:\|[^>]*)?>")
        for m in slack_url_re.finditer(text):
            u = m.group(1)
            if u not in urls:
                urls.append(u)

        first_url = urls[0] if urls else ""

        # Title: first non-empty line of the message text (strip Slack markup)
        clean_text = re.sub(r"<https?://[^>]+>", "", text).strip()
        first_line = clean_text.split("\n")[0].strip()
        if first_line:
            name = first_line[:200]
        elif first_url:
            name = urllib.parse.urlparse(first_url).netloc or first_url[:200]
        else:
            name = f"Slack message {ts}"

        description = text
        publisher   = publisher_from_url(first_url) if first_url else "Slack"
        labels      = auto_labels(text)
        tas         = extract_tas(name, description, [])
        t1_vend     = extract_vendors(name, description, _VRE1, VENDORS_TIER1)
        t2_vend     = extract_vendors(name, description, _VRE2, VENDORS_TIER2)

        items.append({
            "id":                   ts,
            "name":                 name,
            "created":              created,
            "confidence":           confidence_for_publisher(publisher),
            "all_labels":           labels,
            "labels":               labels,
            "publisher":            publisher,
            "url":                  first_url,
            "tas":                  tas,
            "t1_vendors":           t1_vend,
            "t2_vendors":           t2_vend,
            "description":          description,
            "attack_technique_ids": [],
            "mitre_tactics":        [],
            "iocs":                 extract_iocs(description),
            **lifecycle_fields(publisher, "slack"),
        })

    print(f"Processed {len(items)} items (cutoff: {cutoff_dt.date()})", file=sys.stderr)

    save_pickle(items, cutoff_dt, pkl_out)
    print(f"Wrote {pkl_out}", file=sys.stderr)

    # Sidecar: empty dict (Slack messages don't have a separate "published" date)
    save_published({}, pub_sidecar)
    print(f"Wrote {pub_sidecar} (empty sidecar)", file=sys.stderr)


if __name__ == "__main__":
    run()
