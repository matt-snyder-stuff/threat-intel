#!/usr/bin/env python3
"""Shared helpers for all threat-intel sources.

Extracted from generator/fetch_and_process.py so every source can import:
  - KNOWN_ACTORS, ACTOR_RE, extract_tas()
  - PUBLISHER_MAP, publisher_from_url()
  - VENDORS_TIER1, VENDORS_TIER2, extract_vendors()
  - save_pickle(), save_published()
"""
import json, os, pickle, re
from datetime import timezone
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


def confidence_for_publisher(publisher_name):
    """Return the confidence score for a publisher name, defaulting to 60."""
    return PUBLISHER_CONFIDENCE.get(publisher_name, 60)


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


# ── Pickle / sidecar writers ──────────────────────────────────────────────────

def save_pickle(items, cutoff_dt, pkl_out):
    """Write ``{"items": items, "cutoff": cutoff_dt}`` to *pkl_out*.

    Also writes a sibling ``*-cutoff.txt`` with the cutoff ISO string.
    """
    state = {"items": items, "cutoff": cutoff_dt}
    with open(pkl_out, "wb") as f:
        pickle.dump(state, f)
    cutoff_txt = pkl_out.replace(".pkl", "-cutoff.txt")
    with open(cutoff_txt, "w") as f:
        f.write(cutoff_dt.isoformat())


def save_published(pub_dates, out_path):
    """Write the published-dates sidecar JSON ``{id: published_iso}``."""
    with open(out_path, "w") as f:
        json.dump(pub_dates, f)


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
