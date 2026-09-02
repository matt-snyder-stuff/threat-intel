#!/usr/bin/env python3
"""RSS source — reads threat intel directly from RSS/Atom feeds (no OpenCTI required).

Optional env:
  RSS_FEEDS — comma-separated list of feed URLs (defaults to sources/feeds.py DEFAULT_FEEDS)
  CUTOFF_DAYS — lookback window in days (default 30)
  PKL_OUT     — pickle output path (default /tmp/tw-30d-processed.pkl)
  PUB_SIDECAR — sidecar JSON path  (default /tmp/tw-30d-published.json)
"""
import os, re, sys, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

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

# Atom namespace
_ATOM_NS = "http://www.w3.org/2005/Atom"

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE       = re.compile(r"\s+")


def _strip_html(text):
    """Remove HTML tags and collapse whitespace."""
    if not text:
        return ""
    return _WS_RE.sub(" ", _HTML_TAG_RE.sub(" ", text)).strip()


def _parse_date(date_str):
    """Parse RSS pubDate or Atom published/updated; returns UTC-aware datetime or None."""
    if not date_str:
        return None
    date_str = date_str.strip()
    # RFC 2822 (RSS pubDate)
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    # ISO 8601 / Atom
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str[:len(fmt) + 6], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    # fromisoformat fallback (Python 3.7+)
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _text(node, tag, ns=None):
    """Return stripped text of a child element, or '' if absent."""
    if ns:
        child = node.find(f"{{{ns}}}{tag}")
    else:
        child = node.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


def _fetch_feed(feed_url):
    """Fetch and parse a single RSS or Atom feed.  Returns list of raw item dicts."""
    try:
        req = urllib.request.Request(feed_url, headers={"User-Agent": "threat-intel-pipeline/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = r.read()
    except Exception as exc:
        print(f"  Warning: could not fetch {feed_url}: {exc}", file=sys.stderr)
        return []

    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        print(f"  Warning: XML parse error for {feed_url}: {exc}", file=sys.stderr)
        return []

    items = []

    # ── Atom feed ──────────────────────────────────────────────────────────
    if root.tag == f"{{{_ATOM_NS}}}feed":
        for entry in root.findall(f"{{{_ATOM_NS}}}entry"):
            title = _text(entry, "title", _ATOM_NS)
            # link: prefer rel="alternate" or just first link
            link = ""
            for lel in entry.findall(f"{{{_ATOM_NS}}}link"):
                rel = lel.get("rel", "alternate")
                href = lel.get("href", "")
                if rel == "alternate" and href:
                    link = href
                    break
            if not link:
                link_el = entry.find(f"{{{_ATOM_NS}}}link")
                if link_el is not None:
                    link = link_el.get("href", "")
            # id / guid
            item_id = _text(entry, "id", _ATOM_NS) or link
            # published > updated
            pub_str = _text(entry, "published", _ATOM_NS) or _text(entry, "updated", _ATOM_NS)
            # summary or content
            desc = _text(entry, "summary", _ATOM_NS) or _text(entry, "content", _ATOM_NS)
            items.append({"id": item_id, "title": title, "link": link,
                          "pub_str": pub_str, "desc": desc})
        return items

    # ── RSS feed (channel/item) ────────────────────────────────────────────
    channel = root.find("channel")
    if channel is None:
        # Some feeds wrap in <rss><channel> — root IS the rss node
        channel = root
    for item in channel.findall("item"):
        title  = _text(item, "title")
        link   = _text(item, "link")
        guid   = _text(item, "guid") or link
        pub_str = _text(item, "pubDate")
        desc   = _text(item, "description") or _text(item, "summary")
        items.append({"id": guid, "title": title, "link": link,
                      "pub_str": pub_str, "desc": desc})
    return items


def run():
    feeds_env = os.environ.get("RSS_FEEDS", "")
    if not feeds_env.strip():
        from sources.feeds import DEFAULT_FEEDS
        feed_urls = DEFAULT_FEEDS
        print(f"RSS_FEEDS not set — using default feed list ({len(feed_urls)} feeds)", file=sys.stderr)
    else:
        feed_urls = [u.strip() for u in feeds_env.split(",") if u.strip()]
    cutoff_days = int(os.environ.get("CUTOFF_DAYS", "30"))
    pkl_out     = os.environ.get("PKL_OUT",     "/tmp/tw-30d-processed.pkl")
    pub_sidecar = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")

    now       = datetime.now(timezone.utc)
    cutoff_dt = now - timedelta(days=cutoff_days)

    print(f"Reading {len(feed_urls)} RSS feed(s) (last {cutoff_days} days)...", file=sys.stderr)

    items       = []
    pub_dates   = {}   # id → published_iso for sidecar

    for feed_url in feed_urls:
        print(f"  Fetching {feed_url}", file=sys.stderr)
        raw_items = _fetch_feed(feed_url)
        print(f"    → {len(raw_items)} entries", file=sys.stderr)

        for ri in raw_items:
            # Parse date; skip items older than cutoff
            created = _parse_date(ri.get("pub_str", ""))
            if created is None:
                created = now
            if created < cutoff_dt:
                continue

            item_id = ri.get("id", "") or ri.get("link", "")
            name    = ri.get("title", "") or item_id[:200]
            url     = ri.get("link", "")
            desc    = _strip_html(ri.get("desc", ""))

            publisher = publisher_from_url(url)
            labels    = auto_labels(name + " " + desc)
            tas       = extract_tas(name, desc, [])
            t1_vend   = extract_vendors(name, desc, _VRE1, VENDORS_TIER1)
            t2_vend   = extract_vendors(name, desc, _VRE2, VENDORS_TIER2)

            pub_dates[item_id] = created.isoformat()

            items.append({
                "id":                   item_id,
                "name":                 name,
                "created":              created,
                "confidence":           confidence_for_publisher(publisher),
                "all_labels":           labels,
                "labels":               labels,
                "publisher":            publisher,
                "url":                  url,
                "tas":                  tas,
                "t1_vendors":           t1_vend,
                "t2_vendors":           t2_vend,
                "description":          desc,
                "attack_technique_ids": [],
                "mitre_tactics":        [],
                "iocs":                 extract_iocs(desc),
                **lifecycle_fields(publisher, "rss"),
            })

    # Deduplicate by id (same item may appear in multiple feeds)
    seen_ids = set()
    unique_items = []
    for it in items:
        if it["id"] not in seen_ids:
            seen_ids.add(it["id"])
            unique_items.append(it)
    items = unique_items

    print(f"Processed {len(items)} items (cutoff: {cutoff_dt.date()})", file=sys.stderr)

    save_pickle(items, cutoff_dt, pkl_out)
    print(f"Wrote {pkl_out}", file=sys.stderr)

    save_published(pub_dates, pub_sidecar)
    print(f"Wrote {pub_sidecar} ({len(pub_dates)} entries)", file=sys.stderr)


if __name__ == "__main__":
    run()
