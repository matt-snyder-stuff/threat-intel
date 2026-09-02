#!/usr/bin/env python3
"""Shared helpers for all threat-intel sources.

Extracted from generator/fetch_and_process.py so every source can import:
  - KNOWN_ACTORS, ACTOR_RE, extract_tas()
  - PUBLISHER_MAP, publisher_from_url()
  - VENDORS_TIER1, VENDORS_TIER2, extract_vendors()
  - refang(), extract_cves(), extract_iocs(), classify_ioc()
  - save_pickle(), save_published()
"""
import json, os, pickle, re, tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse


# ── Threat Actor extraction via regex ────────────────────────────────────────
KNOWN_ACTORS = [
    # Nation-state / sponsored
    "APT1", "APT10", "APT28", "APT29", "APT30", "APT31", "APT32", "APT33",
    "APT34", "APT35", "APT38", "APT40", "APT41",
    "Volt Typhoon", "Salt Typhoon", "Silk Typhoon", "Flax Typhoon",
    "Sandworm", "Cozy Bear", "Fancy Bear", "Lazarus Group", "Lazarus",
    "Kimsuky", "Andariel", "BlueNoroff",
    # Ransomware groups
    "RansomHub", "Cl0p", "Clop", "LockBit", "ALPHV", "BlackCat",
    "Akira", "Play", "Black Basta", "Royal", "Hive", "Vice Society",
    "8Base", "Medusa", "BianLian", "RA World", "Hunters International",
    "Rhysida", "INC Ransom", "Qilin", "Fog", "DragonForce",
    # Cybercrime / FIN
    "FIN7", "FIN8", "Carbanak", "Scattered Spider", "ShinyHunters",
    "Lapsus$", "LAPSUS$", "UNC3944", "Octo Tempest",
    "TeamPCP", "Shai-Hulud",
    # Other tracked actors
    "Storm-0558", "Storm-0744", "Storm-1152", "Storm-",
    "TA505", "TA577", "TA4903",
    "Midnight Blizzard", "Forest Blizzard", "Cadet Blizzard",
    "GXC Team", "SilentBob",
]
# Build a single alternation regex, longest match first
_actors_sorted = sorted(KNOWN_ACTORS, key=len, reverse=True)
_actor_pattern = "|".join(re.escape(a) for a in _actors_sorted)
ACTOR_RE = re.compile(rf"\b({_actor_pattern})\b", re.I)


def extract_tas(name, description, obj_tas):
    """Extract threat actor names from text + any SDO-linked ThreatActor objects."""
    tas = list(obj_tas)  # start with SDO-linked actors
    text = (name or "") + " " + (description or "")[:800]
    for m in ACTOR_RE.finditer(text):
        matched = m.group(0)
        # Normalise case to canonical name
        canon = next((a for a in _actors_sorted if a.lower() == matched.lower()), matched)
        if canon not in tas:
            tas.append(canon)
    # Keep Storm- as a sentinel if found — build.py will expand to Storm-NNNN
    return tas


# ── Publisher extraction from URL domain ─────────────────────────────────────
PUBLISHER_MAP = {
    "thehackernews.com":        "The Hacker News",
    "bleepingcomputer.com":     "BleepingComputer",
    "threatpost.com":           "Threatpost",
    "krebsonsecurity.com":      "Krebs on Security",
    "darkreading.com":          "Dark Reading",
    "securityweek.com":         "SecurityWeek",
    "wired.com":                "Wired",
    "arstechnica.com":          "Ars Technica",
    "therecord.media":          "The Record",
    "cyberscoop.com":           "CyberScoop",
    "infosecurity-magazine.com":"Infosecurity Magazine",
    "helpnetsecurity.com":      "Help Net Security",
    "zdnet.com":                "ZDNet",
    "techcrunch.com":           "TechCrunch",
    "forbes.com":               "Forbes",
    "cisa.gov":                 "CISA",
    "unit42.paloaltonetworks.com": "Palo Alto Unit 42",
    "research.checkpoint.com":  "Check Point Research",
    "securelist.com":           "Kaspersky Securelist",
    "blog.google":              "Google Security Blog",
    "cloud.google.com":         "Google Cloud Blog",
    "microsoft.com":            "Microsoft Security Blog",
    "aws.amazon.com":           "AWS Security Blog",
    "crowdstrike.com":          "CrowdStrike",
    "sentinelone.com":          "SentinelOne",
    "mandiant.com":             "Mandiant",
    "recordedfuture.com":       "Recorded Future",
    "threats.wiz.io":           "Wiz",
    "wiz.io":                   "Wiz",
    "datadog.com":              "Datadog",
    "snyk.io":                  "Snyk",
    "socradar.io":              "SOCRadar",
    "sekoia.io":                "Sekoia",
    "harfanglab.io":            "HarfangLab",
    "blog.cloudflare.com":      "Cloudflare",
    "labs.guard.io":            "Guard.io Labs",
    "reversinglabs.com":        "ReversingLabs",
    "trendmicro.com":           "Trend Micro",
    "symantec.com":             "Symantec",
    "talos-intelligence.com":   "Cisco Talos",
    "blog.talosintelligence.com": "Cisco Talos",
    "bitdefender.com":          "Bitdefender Labs",
    "blog.virustotal.com":      "VirusTotal",
    "socprime.com":             "SOC Prime",
    "thedfirreport.com":        "The DFIR Report",
    "malware-traffic-analysis.net": "Malware Traffic Analysis",
    "msrc.microsoft.com":       "Microsoft Security Response Center",
}


# ── Publisher confidence tiers ────────────────────────────────────────────────
PUBLISHER_CONFIDENCE = {
    # 90 — authoritative government advisories
    "CISA":                    90,
    # 85 — primary vendor research with direct telemetry
    "Palo Alto Unit 42":       85,
    "Mandiant":                85,
    "CrowdStrike":             85,
    "Recorded Future":         85,
    "Google Security Blog":    85,
    "Google Cloud Blog":       85,
    "Microsoft Security Blog": 85,
    "Microsoft Security Response Center": 85,
    "AWS Security Blog":       85,
    "Wiz":                     85,
    # 80 — solid vendor research, may have marketing angle
    "Check Point Research":    80,
    "Kaspersky Securelist":    80,
    "SentinelOne":             80,
    "Cisco Talos":             80,
    "Bitdefender Labs":        80,
    "The DFIR Report":         80,
    "VirusTotal":              80,
    "Malware Traffic Analysis": 80,
    "Cloudflare":              80,
    "Datadog":                 80,
    "Snyk":                    80,
    "ReversingLabs":           80,
    "Sekoia":                  80,
    "HarfangLab":              80,
    # 75 — high-quality journalism, secondary sourcing
    "Krebs on Security":       75,
    "The Record":              75,
    "BleepingComputer":        75,
    "CyberScoop":              75,
    "SecurityWeek":            75,
    # 70 — news aggregators, trade press, and community blogs
    "SOC Prime":               70,
    "The Hacker News":         70,
    "Dark Reading":            70,
    "Infosecurity Magazine":   70,
    "Help Net Security":       70,
    "ZDNet":                   70,
    "Ars Technica":            70,
    "Wired":                   70,
    "TechCrunch":              70,
    "Forbes":                  70,
    "Threatpost":              70,
    "SOCRadar":                70,
}

# Reliability describes the publisher's reporting process. It is intentionally
# maintained separately from item confidence, which can vary claim by claim.
PUBLISHER_RELIABILITY = {
    "CISA": "A",
    "Palo Alto Unit 42": "A",
    "Mandiant": "A",
    "CrowdStrike": "A",
    "Recorded Future": "A",
    "Google Security Blog": "A",
    "Google Cloud Blog": "A",
    "Microsoft Security Blog": "A",
    "Microsoft Security Response Center": "A",
    "AWS Security Blog": "A",
    "Wiz": "A",
    "Check Point Research": "B",
    "Kaspersky Securelist": "B",
    "SentinelOne": "B",
    "Cisco Talos": "B",
    "Bitdefender Labs": "B",
    "The DFIR Report": "B",
    "VirusTotal": "B",
    "Malware Traffic Analysis": "B",
    "Cloudflare": "B",
    "Datadog": "B",
    "Snyk": "B",
    "ReversingLabs": "B",
    "Sekoia": "B",
    "HarfangLab": "B",
    "Krebs on Security": "B",
    "The Record": "B",
    "BleepingComputer": "B",
    "CyberScoop": "B",
    "SecurityWeek": "B",
}


def confidence_for_publisher(publisher_name):
    """Return the confidence score for a publisher name, defaulting to 60."""
    return PUBLISHER_CONFIDENCE.get(publisher_name, 60)


def source_reliability_for_publisher(publisher_name):
    """Return an Admiralty-style source reliability grade (A-F).

    This grades the publisher's established reporting process, not whether a
    specific claim is true. Item confidence remains a separate field.
    """
    return PUBLISHER_RELIABILITY.get(publisher_name, "C")


def lifecycle_fields(publisher, source_type, tlp=None, valid_until="", revoked=False):
    """Return normalized handling and lifecycle metadata for a pipeline item."""
    if tlp is None:
        tlp = "TLP:CLEAR" if source_type == "rss" else "TLP:AMBER"
    return {
        "source_type": source_type,
        "source_reliability": source_reliability_for_publisher(publisher),
        "tlp": tlp,
        "valid_until": valid_until or "",
        "revoked": bool(revoked),
        "analyst_disposition": "unreviewed",
    }


# feedburner path → canonical publisher (feedburner masks the real domain in feed URLs)
_FEEDBURNER_MAP = {
    "talosintelligenceblog":   "Cisco Talos",
    "talos":                   "Cisco Talos",
    "thedfirreport":           "The DFIR Report",
    "thehackernews":           "The Hacker News",
    "thehackersnews":          "The Hacker News",
    "securityweek":            "SecurityWeek",
}


def publisher_from_url(url):
    if not url:
        return "Unknown"
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Strip www. prefix properly (lstrip strips chars, not a prefix string)
        if host.startswith("www."):
            host = host[4:]
        # Special case: feedburner masks the real publisher — resolve from path
        if "feedburner.com" in host:
            path_slug = parsed.path.strip("/").split("/")[-1].lower().replace("-", "")
            for key, name in _FEEDBURNER_MAP.items():
                if key in path_slug:
                    return name
            return "Unknown"
        for domain, name in PUBLISHER_MAP.items():
            if host == domain or host.endswith("." + domain):
                return name
        # Fall back to cleaned hostname
        parts = host.split(".")
        if len(parts) >= 2:
            return parts[-2].replace("-", " ").title()
        return host
    except Exception:
        return "Unknown"


# ── Vendor extraction ────────────────────────────────────────────────────────
VENDORS_TIER1 = [
    "Salesforce", "Okta", "Workday", "GitHub", "AWS", "Azure", "GCP", "Google Cloud",
    "Microsoft", "Cisco", "Fortinet", "Palo Alto", "Splunk", "CrowdStrike", "Snowflake",
    "Databricks", "Slack", "Zoom", "Cloudflare", "Ivanti", "Atlassian", "ServiceNow",
]
VENDORS_TIER2 = [
    "Notion", "Asana", "Jira", "Confluence", "DataDog", "PagerDuty", "Linear",
    "Auth0", "1Password", "LastPass", "Dropbox", "Box", "Tableau", "Looker", "MongoDB",
    "Redis", "PostgreSQL", "Elastic", "Grafana", "Terraform", "Ansible", "Jenkins",
    "GitLab", "Bitbucket", "Docker", "Kubernetes", "VMware", "Citrix", "F5",
    "Check Point", "SentinelOne", "Tenable", "Qualys", "Rapid7", "Mimecast",
]


def _build_vendor_re(vendors):
    pat = "|".join(re.escape(v) for v in sorted(vendors, key=len, reverse=True))
    return re.compile(rf"\b({pat})\b", re.I)


_VRE1 = _build_vendor_re(VENDORS_TIER1)
_VRE2 = _build_vendor_re(VENDORS_TIER2)


def extract_vendors(name, description, tier_re, canonical_list):
    text = (name or "") + " " + (description or "")[:800]
    found = []
    for m in tier_re.finditer(text):
        matched = m.group(0)
        canon = next((v for v in canonical_list if v.lower() == matched.lower()), matched)
        if canon not in found:
            found.append(canon)
    return found


# ── IOC extraction helpers ────────────────────────────────────────────────────

# CVE pattern — covers CVE-YYYY-NNNN through CVE-YYYY-NNNNNNN
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# Hash patterns anchored on non-hex / word boundaries to avoid substring matches
_MD5_RE    = re.compile(r'(?<![a-fA-F\d])[a-fA-F\d]{32}(?![a-fA-F\d])')
_SHA1_RE   = re.compile(r'(?<![a-fA-F\d])[a-fA-F\d]{40}(?![a-fA-F\d])')
_SHA256_RE = re.compile(r'(?<![a-fA-F\d])[a-fA-F\d]{64}(?![a-fA-F\d])')

# IPv4: plain or defanged (bracketed/parenthesized dots, backslash dots)
_IPV4_RE = re.compile(
    r'\b(?:\d{1,3}(?:[\[\(\\]\.\]?|\.)[\]\)]?){3}\d{1,3}\b'
)

# URL: plain or defanged schemes (hxxp, hxxps) + bracket-defanged bare domains
_URL_RE = re.compile(
    r'(?:https?|hxxps?|ftps?|fxps?)(?:://|:\\\\|__|\[://\])'
    r'[^\s\[\]<>"\']+',
    re.IGNORECASE,
)
_BRACKET_URL_RE = re.compile(
    r'(?:[a-zA-Z0-9\-]+\[?\.\]?[a-zA-Z]{2,})'
    r'(?:/[^\s\[\]<>"\']*)?',
)

# Trailing punctuation to strip from extracted values
_TRAIL_RE = re.compile(r'[\.\?>"\')\]]+$')


def refang(value: str) -> str:
    """Normalize a defanged IOC string to its plain form.

    Handles bracket/paren notation, hxxp schemes, and Unicode middle dot.
    """
    v = value
    # Scheme obfuscation: hxxp(s) → http(s), fxp/ftx → ftp
    v = re.sub(r'^hxxps?', lambda m: m.group(0).replace('xx', 'tt'), v, flags=re.I)
    v = re.sub(r'^f[xt]ps?', lambda m: 'ftp' + m.group(0)[3:], v, flags=re.I)
    # Delimiter obfuscation: :// variants
    v = re.sub(r'(?i)(https?|ftps?)(:\\\\|__|__)', r'\1://', v)
    # Dot obfuscation: [.] (.) [dot] (dot) \. and Unicode middle dot
    for pat, rep in (
        ('[dot]', '.'), ('(dot)', '.'), ('[.]', '.'), ('(.)', '.'),
        (r'\.', '.'), ('・', '.'), ('․', '.'),
    ):
        v = v.replace(pat, rep)
    # Strip bracket/paren around individual octets: 1[.]2 → 1.2
    v = re.sub(r'[\[\(]\.[\]\)]', '.', v)
    # Remove trailing punctuation noise
    v = _TRAIL_RE.sub('', v)
    return v


def extract_cves(text: str) -> list:
    """Return deduplicated CVE IDs found in *text*, uppercased."""
    seen, result = set(), []
    for m in _CVE_RE.finditer(text or ""):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            result.append(cve)
    return result


def classify_ioc(value: str) -> str:
    """Return the IOC type string for a plain (refanged) value."""
    v = value.strip()
    if _CVE_RE.match(v):
        return "cve"
    lv = len(v)
    if re.fullmatch(r'[a-fA-F\d]+', v):
        if lv == 32:   return "md5"
        if lv == 40:   return "sha1"
        if lv == 64:   return "sha256"
        if lv == 128:  return "sha512"
    if re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', v):
        return "ipv4"
    if re.fullmatch(r'[0-9a-fA-F:]{2,39}', v) and ':' in v:
        return "ipv6"
    if v.startswith(('http://', 'https://', 'ftp://')):
        return "url"
    if re.fullmatch(r'[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+', v) and '.' in v:
        return "domain"
    return "unknown"


def extract_iocs(text: str) -> dict:
    """Extract structured IOCs from free text, including defanged variants.

    Returns a dict with lists keyed by IOC type:
      {"cve": [...], "ipv4": [...], "url": [...], "md5": [...],
       "sha1": [...], "sha256": [...], "domain": [...]}

    All values are refanged (plain form, no brackets or hxxp).
    """
    t = (text or "").replace("\x00", "")  # strip wide-char null bytes
    seen: dict = {}

    def _add(ioc_type, raw):
        val = refang(raw).strip()
        if not val:
            return
        key = (ioc_type, val.lower() if ioc_type in ("url", "domain") else val.upper() if ioc_type == "cve" else val)
        if key not in seen:
            seen[key] = (ioc_type, val)

    for m in _CVE_RE.finditer(t):
        _add("cve", m.group(0))

    for m in _IPV4_RE.finditer(t):
        candidate = refang(m.group(0))
        # Validate all four octets are 0-255
        parts = candidate.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            _add("ipv4", m.group(0))

    for m in _URL_RE.finditer(t):
        _add("url", m.group(0))

    for m in _MD5_RE.finditer(t):
        _add("md5", m.group(0))

    for m in _SHA1_RE.finditer(t):
        # Exclude values that also match SHA256 (first 40 hex chars of a 64-char string)
        start, end = m.start(), m.end()
        if end < len(t) and t[end] in '0123456789abcdefABCDEF':
            continue
        _add("sha1", m.group(0))

    for m in _SHA256_RE.finditer(t):
        _add("sha256", m.group(0))

    result: dict = {"cve": [], "ipv4": [], "url": [], "md5": [], "sha1": [], "sha256": [], "domain": []}
    for ioc_type, val in seen.values():
        if ioc_type in result:
            result[ioc_type].append(val)
    return result


# ── Pickle / sidecar writers ──────────────────────────────────────────────────

REQUIRED_ITEM_FIELDS = {
    "id", "name", "created", "confidence", "all_labels", "labels",
    "publisher", "url", "tas", "t1_vendors", "t2_vendors", "description",
    "attack_technique_ids", "mitre_tactics", "iocs", "source_type",
    "source_reliability", "tlp", "valid_until", "revoked",
    "analyst_disposition",
}
IOC_TYPES = {"cve", "ipv4", "url", "md5", "sha1", "sha256", "domain"}


def validate_item(item):
    """Reject malformed normalized items before they reach persistent state."""
    missing = REQUIRED_ITEM_FIELDS - set(item)
    if missing:
        raise ValueError(f"item is missing required fields: {', '.join(sorted(missing))}")
    if not isinstance(item["id"], str) or not item["id"]:
        raise ValueError("item id must be a non-empty string")
    if not isinstance(item["created"], datetime) or item["created"].tzinfo is None:
        raise ValueError("item created must be a timezone-aware datetime")
    if not isinstance(item["confidence"], int) or not 0 <= item["confidence"] <= 100:
        raise ValueError("item confidence must be an integer from 0 through 100")
    for field in ("all_labels", "labels", "tas", "t1_vendors", "t2_vendors", "attack_technique_ids", "mitre_tactics"):
        if not isinstance(item[field], list):
            raise ValueError(f"item {field} must be a list")
    if not isinstance(item["iocs"], dict) or set(item["iocs"]) != IOC_TYPES:
        raise ValueError("item iocs must contain exactly the canonical IOC types")
    if any(not isinstance(values, list) for values in item["iocs"].values()):
        raise ValueError("every item IOC collection must be a list")
    if item["source_reliability"] not in set("ABCDEF"):
        raise ValueError("item source_reliability must be A through F")
    if item["tlp"] not in {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}:
        raise ValueError("item tlp is invalid")
    if not isinstance(item["revoked"], bool):
        raise ValueError("item revoked must be boolean")

def _atomic_write(path, mode, writer):
    """Write a complete sibling temporary file and atomically replace *path*."""
    destination = os.path.abspath(path)
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=os.path.dirname(destination))
    try:
        with os.fdopen(fd, mode) as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path, content):
    _atomic_write(path, "w", lambda handle: handle.write(content))


def atomic_write_json(path, value):
    _atomic_write(path, "w", lambda handle: json.dump(value, handle))

def save_pickle(items, cutoff_dt, pkl_out):
    """Write ``{"items": items, "cutoff": cutoff_dt}`` to *pkl_out*.

    Also writes a sibling ``*-cutoff.txt`` with the cutoff ISO string.
    """
    for item in items:
        validate_item(item)
    state = {"items": items, "cutoff": cutoff_dt}
    _atomic_write(pkl_out, "wb", lambda handle: pickle.dump(state, handle))
    cutoff_txt = pkl_out.replace(".pkl", "-cutoff.txt")
    atomic_write_text(cutoff_txt, cutoff_dt.isoformat())


def save_published(pub_dates, out_path):
    """Write the published-dates sidecar JSON ``{id: published_iso}``."""
    atomic_write_json(out_path, pub_dates)


# ── Label auto-detection (used by Slack + RSS sources) ───────────────────────

def auto_labels(text):
    """Detect cloud/AI labels from free text.  Returns a list of label strings."""
    text_lower = (text or "").lower()
    labels = []

    # Top-level buckets
    if re.search(r'\bcloud\b', text_lower):
        labels.append("cloud")
    if re.search(r'\b(ai|llm|gpt|machine learning|artificial intelligence|agentic|mcp|prompt injection|deepfake|model poisoning)\b', text_lower):
        labels.append("ai")

    # Cloud sub-labels
    if "aws" in text_lower or "amazon web" in text_lower:
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-aws")
    if "azure" in text_lower:
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-azure")
    if any(k in text_lower for k in ("gcp", "google cloud", "bigquery")):
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-gcp")
    if any(k in text_lower for k in ("kubernetes", "k8s", "kubelet", "kubectl")):
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-k8s")
    if any(k in text_lower for k in ("container", "docker", "containerd")):
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-container")
    if any(k in text_lower for k in ("saas", "salesforce", "okta", "workday", "servicenow")):
        if "cloud" not in labels:
            labels.append("cloud")
        labels.append("cloud-saas")

    # AI sub-labels
    if any(k in text_lower for k in ("llm", "large language model")):
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-llm")
    if any(k in text_lower for k in ("agentic", "ai agent", "mcp server", "tool call")):
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-agentic")
    if re.search(r'\bmcp\b', text_lower):
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-mcp")
    if "deepfake" in text_lower:
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-deepfake")
    if "prompt injection" in text_lower:
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-prompt-injection")
    if "data poisoning" in text_lower or "model poisoning" in text_lower:
        if "ai" not in labels:
            labels.append("ai")
        labels.append("ai-data-poisoning")

    # Deduplicate while preserving order
    seen = set()
    result = []
    for l in labels:
        if l not in seen:
            seen.add(l)
            result.append(l)
    return result
