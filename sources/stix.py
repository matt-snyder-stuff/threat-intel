#!/usr/bin/env python3
"""STIX/TAXII source — ingest threat intel from TAXII 2.x servers or local STIX 2.x bundles.

Supports:
  - TAXII 2.0 and 2.1 servers (auto-detected)
  - Local STIX 2.x bundle files (JSON)
  - Direct STIX bundle URLs (no TAXII wrapper)

Ingests STIX Report objects as items. Falls back to Indicator, Threat Actor,
Attack Pattern, Campaign, and Malware objects when no Reports are present.

Required env vars (TAXII server mode):
  TAXII_URL     — base URL of the TAXII server, e.g. https://otx.alienvault.com/taxii/

Optional env vars:
  TAXII_USERNAME      — HTTP Basic auth username
  TAXII_PASSWORD      — HTTP Basic auth password
  TAXII_TOKEN         — Bearer token (preferred over Basic auth)
  TAXII_COLLECTION    — collection ID or title to fetch (default: first readable collection)
  TAXII_API_ROOT      — specific API root path (default: auto-discover from /taxii/ endpoint)

  STIX_FILE           — path to a local STIX 2.x bundle JSON file
  STIX_URL            — URL of a raw STIX bundle JSON (no TAXII wrapper)

  CUTOFF_DAYS         — lookback window in days (default: 30)
  PKL_OUT             — pickle output path (default: /tmp/tw-30d-processed.pkl)
  PUB_SIDECAR         — published-dates sidecar path (default: /tmp/tw-30d-published.json)
  STIX_VERIFY_SSL     — set to "false" to skip TLS verification (default: true)
  STIX_LIMIT          — max objects to fetch per collection (default: 500)

At least one of TAXII_URL, STIX_FILE, or STIX_URL must be set.

Examples:
  # AlienVault OTX TAXII feed
  export TAXII_URL=https://otx.alienvault.com/taxii/
  export TAXII_TOKEN=your-otx-api-key

  # MITRE ATT&CK STIX bundle (direct URL, no TAXII)
  export STIX_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

  # Local bundle file
  export STIX_FILE=/path/to/bundle.json
"""
import base64, json, os, re, sys, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin, urlparse

from sources.base import (
    extract_tas,
    extract_vendors,
    auto_labels,
    publisher_from_url,
    confidence_for_publisher,
    save_pickle,
    save_published,
    extract_iocs,
    lifecycle_fields,
    VENDORS_TIER1,
    VENDORS_TIER2,
    _VRE1,
    _VRE2,
)

_VERIFY = os.environ.get("STIX_VERIFY_SSL", "true").lower() != "false"

_TLP_ORDER = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}

# Standard STIX marking-definition IDs from the OASIS examples and ATT&CK data.
_KNOWN_TLP_MARKINGS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6a3-dac60c9f6e8": "TLP:RED",
}

# TAXII media types — prefer 2.1, accept 2.0
_TAXII_MEDIA_TYPES = [
    "application/taxii+json;version=2.1",
    "application/taxii+json;version=2.0",
    "application/vnd.oasis.taxii+json;version=2.1",
    "application/vnd.oasis.taxii+json;version=2.0",
    "application/json",
]

_STIX_REPORT_TYPES = {
    "report", "indicator", "threat-actor", "attack-pattern",
    "campaign", "malware", "course-of-action", "intrusion-set",
    "tool", "vulnerability",
}

# STIX type → readable label for publisher field
_TYPE_LABELS = {
    "report":           "STIX Report",
    "indicator":        "STIX Indicator",
    "threat-actor":     "STIX Threat Actor",
    "attack-pattern":   "STIX Attack Pattern",
    "campaign":         "STIX Campaign",
    "malware":          "STIX Malware",
    "intrusion-set":    "STIX Intrusion Set",
    "vulnerability":    "STIX Vulnerability",
    "course-of-action": "STIX Course of Action",
    "tool":             "STIX Tool",
}


# ── SSL context ────────────────────────────────────────────────────────────────

def _ssl_ctx():
    if not _VERIFY:
        import ssl
        print("Warning: STIX_VERIFY_SSL=false — TLS certificate verification is disabled", file=sys.stderr)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _auth_headers():
    headers = {}
    token = os.environ.get("TAXII_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
        return headers
    user = os.environ.get("TAXII_USERNAME", "")
    pw   = os.environ.get("TAXII_PASSWORD", "")
    if user and pw:
        creds = base64.b64encode(f"{user}:{pw}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    return headers


def _get(url, accept=None):
    """HTTP GET, return parsed JSON or raise."""
    headers = {
        **_auth_headers(),
        "Accept": accept or _TAXII_MEDIA_TYPES[0],
        "User-Agent": "threat-intel-pipeline/1.0 (STIX/TAXII)",
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = _ssl_ctx()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            raw = r.read()
        return json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        # Some TAXII servers 406 on strict accept headers — retry with plain json
        if e.code == 406 and accept != "application/json":
            return _get(url, accept="application/json")
        raise RuntimeError(f"HTTP {e.code} from {url}: {body[:300]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach {url}: {e.reason}") from e


def _get_paginated(url, limit=500):
    """Fetch a TAXII objects endpoint, following next/added_after pagination."""
    objects = []
    next_url = f"{url}?limit={limit}"
    while next_url:
        data = _get(next_url)
        batch = data.get("objects", [])
        objects.extend(batch)
        print(f"    fetched {len(batch)} objects (total: {len(objects)})", file=sys.stderr)
        # TAXII 2.1 pagination via 'next' cursor
        cursor = data.get("next")
        if cursor:
            parsed = urlparse(url)
            next_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?next={cursor}&limit={limit}"
        else:
            next_url = None
    return objects


# ── STIX parsing ───────────────────────────────────────────────────────────────

def _parse_stix_date(date_str):
    """Parse a STIX timestamp string to a UTC-aware datetime, or return now."""
    if not date_str:
        return datetime.now(timezone.utc)
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _stix_name(obj):
    """Best available name string for a STIX object."""
    return (
        obj.get("name")
        or obj.get("title")
        or obj.get("pattern")           # indicators have patterns instead of names
        or obj.get("id", "")
    )


def _stix_description(obj):
    """Best available description string for a STIX object."""
    desc = obj.get("description", "")
    # Indicators: also surface the pattern for label/actor extraction
    pattern = obj.get("pattern", "")
    if pattern and pattern not in desc:
        desc = f"{desc} {pattern}".strip()
    # Threat Actor: also pull aliases and goals
    for field in ("aliases", "goals", "sophistication"):
        val = obj.get(field)
        if isinstance(val, list):
            desc = f"{desc} {' '.join(val)}".strip()
        elif isinstance(val, str) and val:
            desc = f"{desc} {val}".strip()
    return desc[:2000]


def _stix_confidence(obj):
    """Map STIX confidence (0–100) to our pipeline's 0–100 scale.
    STIX confidence is already 0–100 per spec; fall back to publisher confidence."""
    c = obj.get("confidence")
    if c is not None:
        try:
            return max(0, min(100, int(c)))
        except (TypeError, ValueError):
            pass
    return 60


def _stix_url(obj, source_label):
    """Extract a reference URL from a STIX object's external_references, or synthesise one."""
    for ref in obj.get("external_references", []):
        url = ref.get("url", "")
        if url and url.startswith("http"):
            return url
    # No URL in the object — link to the source collection page if we have one
    return ""


def _stix_external_id(obj):
    """Return the first non-ATT&CK external ID (CVE, CWE, etc.) if present."""
    for ref in obj.get("external_references", []):
        eid = ref.get("external_id", "")
        src = ref.get("source_name", "")
        if eid and src != "mitre-attack":
            return eid
    return ""


def _stix_attack_technique_ids(obj):
    """Return list of ATT&CK technique IDs from external_references (e.g. ['T1059', 'T1078.004'])."""
    ids = []
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id", "")
            if re.match(r'T\d{4}(?:\.\d{3})?$', eid):
                ids.append(eid)
    return ids


def _stix_mitre_tactics(obj):
    """Return list of ATT&CK tactic phase names from kill_chain_phases."""
    tactics = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            name = phase.get("phase_name", "")
            if name and name not in tactics:
                tactics.append(name)
    return tactics


def _tlp_from_marking_definition(obj):
    """Return a normalized TLP 2.0 value from a STIX marking-definition."""
    raw = ""
    if obj.get("definition_type") == "tlp":
        raw = obj.get("definition", {}).get("tlp", "")
    if not raw:
        for extension in obj.get("extensions", {}).values():
            if isinstance(extension, dict) and extension.get("tlp_2_0"):
                raw = extension["tlp_2_0"]
                break
    normalized = str(raw).strip().upper().replace("TLP:", "")
    if normalized == "WHITE":
        normalized = "CLEAR"
    value = f"TLP:{normalized}" if normalized else ""
    return value if value in _TLP_ORDER else ""


def _stix_tlp(obj, marking_definitions):
    """Resolve object markings and return the most restrictive TLP value."""
    values = []
    for ref in obj.get("object_marking_refs", []):
        value = _KNOWN_TLP_MARKINGS.get(ref)
        if not value and ref in marking_definitions:
            value = _tlp_from_marking_definition(marking_definitions[ref])
        if value:
            values.append(value)
    return max(values, key=_TLP_ORDER.get) if values else "TLP:AMBER"


def _object_to_item(obj, source_label, cutoff_dt, marking_definitions=None):
    """Convert a single STIX object to a pipeline item dict, or return None if filtered."""
    obj_type = obj.get("type", "")
    if obj_type not in _STIX_REPORT_TYPES:
        return None

    # Drop revoked or deprecated objects — MITRE docs require explicit checks here
    # because STIX library built-in filters are unreliable for these fields.
    if obj.get("revoked") or obj.get("x_mitre_deprecated"):
        return None

    # Date: prefer published > modified > created
    date_str = obj.get("published") or obj.get("modified") or obj.get("created") or ""
    created = _parse_stix_date(date_str)
    if created < cutoff_dt:
        return None

    name     = _stix_name(obj)
    desc     = _stix_description(obj)
    url      = _stix_url(obj, source_label)
    ext_id   = _stix_external_id(obj)

    # Augment name with non-ATT&CK external ID when it adds context (CVE, CWE, etc.)
    # ATT&CK technique IDs go into the structured attack_technique_ids field instead.
    if ext_id and ext_id not in name:
        name = f"{name} [{ext_id}]" if name else ext_id

    # Publisher: prefer source_label, fall back to type label, then URL
    publisher = source_label or _TYPE_LABELS.get(obj_type, "STIX")

    labels         = auto_labels(name + " " + desc)
    attack_ids     = _stix_attack_technique_ids(obj)
    mitre_tactics  = _stix_mitre_tactics(obj)

    # Seed tas from any structured aliases list (intrusion-set carries these)
    aliases = obj.get("aliases", [])
    tas = extract_tas(name, desc, aliases)

    # For threat-actor objects without aliases, also seed from name directly
    if obj_type == "threat-actor" and name and name not in tas:
        tas = extract_tas(name, desc, [name])

    t1_vend = extract_vendors(name, desc, _VRE1, VENDORS_TIER1)
    t2_vend = extract_vendors(name, desc, _VRE2, VENDORS_TIER2)

    # Extract structured IOCs from description for enrichment routing
    iocs = extract_iocs(desc)

    return {
        "id":                    obj.get("id", ""),
        "name":                  name[:400],
        "created":               created,
        "confidence":            _stix_confidence(obj),
        "all_labels":            labels,
        "labels":                labels,
        "publisher":             publisher,
        "url":                   url,
        "tas":                   tas,
        "t1_vendors":            t1_vend,
        "t2_vendors":            t2_vend,
        "description":           desc,
        "attack_technique_ids":  attack_ids,
        "mitre_tactics":         mitre_tactics,
        "iocs":                  iocs,
        **lifecycle_fields(
            publisher,
            "stix",
            tlp=_stix_tlp(obj, marking_definitions or {}),
            valid_until=obj.get("valid_until", ""),
            revoked=obj.get("revoked", False),
        ),
    }


def _objects_to_items(objects, source_label, cutoff_dt):
    """Convert a list of STIX objects to pipeline items, filtering by cutoff and type."""
    items, pub_dates = [], {}
    skipped_old = 0
    skipped_type = 0
    marking_definitions = {
        o.get("id"): o
        for o in objects
        if o.get("type") == "marking-definition" and o.get("id")
    }

    # Priority: ingest Reports first; if none, fall back to all supported types
    report_objects = [o for o in objects if o.get("type") == "report"]
    if report_objects:
        work_objects = report_objects
        print(f"  Found {len(report_objects)} Report objects (out of {len(objects)} total)", file=sys.stderr)
    else:
        work_objects = objects
        print(f"  No Report objects found — ingesting all {len(objects)} supported objects", file=sys.stderr)

    for obj in work_objects:
        item = _object_to_item(obj, source_label, cutoff_dt, marking_definitions)
        if item is None:
            obj_type = obj.get("type", "")
            if obj_type not in _STIX_REPORT_TYPES:
                skipped_type += 1
            else:
                skipped_old += 1
            continue
        items.append(item)
        pub_dates[item["id"]] = item["created"].isoformat()

    print(f"  Accepted: {len(items)} | Too old: {skipped_old} | Wrong type: {skipped_type}", file=sys.stderr)
    return items, pub_dates


# ── TAXII discovery and collection fetch ──────────────────────────────────────

def _discover_api_root(taxii_base_url):
    """Call the TAXII discovery endpoint and return the first API root URL."""
    discovery_url = taxii_base_url.rstrip("/") + "/taxii/"
    # Some servers use /taxii2/ or expose the discovery at the root
    for url in [discovery_url, taxii_base_url.rstrip("/") + "/taxii2/", taxii_base_url.rstrip("/") + "/"]:
        try:
            data = _get(url)
            api_roots = data.get("api_roots", [])
            if api_roots:
                print(f"  Discovered {len(api_roots)} API root(s)", file=sys.stderr)
                forced = os.environ.get("TAXII_API_ROOT", "")
                if forced:
                    return forced.rstrip("/")
                return api_roots[0].rstrip("/")
            # Some servers return the root object without api_roots
            if "title" in data:
                return taxii_base_url.rstrip("/")
        except RuntimeError as e:
            print(f"  Discovery at {url} failed: {e}", file=sys.stderr)
            continue
    raise RuntimeError(f"Could not discover TAXII API root from {taxii_base_url}")


def _list_collections(api_root_url):
    """Return list of collection dicts from the API root."""
    url = api_root_url.rstrip("/") + "/collections/"
    data = _get(url)
    return data.get("collections", [])


def _select_collection(collections):
    """Pick the target collection by TAXII_COLLECTION env var (ID or title) or first readable."""
    target = os.environ.get("TAXII_COLLECTION", "").strip()
    readable = [c for c in collections if c.get("can_read", True)]
    if not readable:
        raise RuntimeError("No readable collections found in this TAXII server")

    if target:
        for c in readable:
            if c.get("id") == target or c.get("title", "").lower() == target.lower():
                return c
        print(f"  Warning: collection '{target}' not found — using first readable collection", file=sys.stderr)

    chosen = readable[0]
    print(f"  Using collection: '{chosen.get('title','(no title)')}' (id={chosen.get('id','')})", file=sys.stderr)
    return chosen


def _fetch_taxii(taxii_url):
    """Full TAXII fetch: discover → list collections → fetch objects."""
    limit = int(os.environ.get("STIX_LIMIT", "500"))

    print(f"Discovering TAXII server at {taxii_url}", file=sys.stderr)
    api_root = _discover_api_root(taxii_url)
    print(f"  API root: {api_root}", file=sys.stderr)

    print("  Listing collections...", file=sys.stderr)
    collections = _list_collections(api_root)
    print(f"  Found {len(collections)} collection(s)", file=sys.stderr)
    for c in collections:
        readable = "readable" if c.get("can_read", True) else "no-read"
        print(f"    - {c.get('id','')} | {c.get('title','(no title)')} | {readable}", file=sys.stderr)

    collection = _select_collection(collections)
    objects_url = f"{api_root}/collections/{collection['id']}/objects/"

    # Source label: server hostname + collection title
    hostname = urlparse(taxii_url).hostname or taxii_url
    source_label = f"{hostname} / {collection.get('title', collection['id'])}"

    print(f"  Fetching objects from {objects_url}", file=sys.stderr)
    objects = _get_paginated(objects_url, limit=limit)
    return objects, source_label


def _fetch_bundle(url_or_path):
    """Load a STIX bundle from a URL or local file path. Returns (objects list, source_label)."""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        print(f"Fetching STIX bundle from {url_or_path}", file=sys.stderr)
        data = _get(url_or_path, accept="application/json")
        source_label = urlparse(url_or_path).hostname or "STIX bundle"
    else:
        print(f"Loading STIX bundle from file {url_or_path}", file=sys.stderr)
        with open(url_or_path) as f:
            data = json.load(f)
        source_label = os.path.basename(url_or_path)

    if data.get("type") != "bundle":
        # Some publishers wrap in a top-level dict without the bundle type
        # Try to find objects list directly
        if isinstance(data.get("objects"), list):
            return data["objects"], source_label
        raise RuntimeError(f"Expected a STIX bundle (type=bundle), got type={data.get('type','unknown')}")

    return data.get("objects", []), source_label


# ── Entry point ────────────────────────────────────────────────────────────────

def run():
    cutoff_days = int(os.environ.get("CUTOFF_DAYS", "30"))
    pkl_out     = os.environ.get("PKL_OUT",     "/tmp/tw-30d-processed.pkl")
    pub_sidecar = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")

    now       = datetime.now(timezone.utc)
    cutoff_dt = now - timedelta(days=cutoff_days)

    taxii_url  = os.environ.get("TAXII_URL",  "").strip()
    stix_file  = os.environ.get("STIX_FILE",  "").strip()
    stix_url   = os.environ.get("STIX_URL",   "").strip()

    if not (taxii_url or stix_file or stix_url):
        print(
            "Error: set at least one of TAXII_URL, STIX_FILE, or STIX_URL.\n"
            "  TAXII_URL  — base URL of a TAXII 2.x server\n"
            "  STIX_FILE  — path to a local STIX 2.x bundle JSON file\n"
            "  STIX_URL   — URL of a raw STIX bundle JSON (no TAXII wrapper)",
            file=sys.stderr,
        )
        sys.exit(1)

    all_items    = []
    all_pub_dates = {}

    # Each configured source is fetched independently and merged
    sources_run = []

    if taxii_url:
        sources_run.append(("TAXII", taxii_url))
    if stix_url:
        sources_run.append(("STIX_URL", stix_url))
    if stix_file:
        sources_run.append(("STIX_FILE", stix_file))

    for mode, source_ref in sources_run:
        print(f"\n[stix] Source: {mode} = {source_ref}", file=sys.stderr)
        try:
            if mode == "TAXII":
                objects, source_label = _fetch_taxii(source_ref)
            else:
                objects, source_label = _fetch_bundle(source_ref)
        except RuntimeError as e:
            print(f"[stix] ERROR fetching {mode}: {e}", file=sys.stderr)
            continue

        print(f"  Raw objects: {len(objects)}", file=sys.stderr)
        items, pub_dates = _objects_to_items(objects, source_label, cutoff_dt)
        all_items.extend(items)
        all_pub_dates.update(pub_dates)

    # Deduplicate by STIX id
    seen, unique = set(), []
    for item in all_items:
        if item["id"] not in seen:
            seen.add(item["id"])
            unique.append(item)
    all_items = unique

    print(f"\n[stix] Total items after dedup: {len(all_items)} (cutoff: {cutoff_dt.date()})", file=sys.stderr)

    if not all_items:
        print("[stix] Warning: no items produced. Check CUTOFF_DAYS and that your source has recent data.", file=sys.stderr)

    save_pickle(all_items, cutoff_dt, pkl_out)
    print(f"[stix] Wrote {pkl_out}", file=sys.stderr)

    save_published(all_pub_dates, pub_sidecar)
    print(f"[stix] Wrote {pub_sidecar} ({len(all_pub_dates)} entries)", file=sys.stderr)


if __name__ == "__main__":
    run()
