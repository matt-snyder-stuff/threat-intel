#!/usr/bin/env python3
"""Generate Threat Watch site and JSON data export from processed pipeline data."""
import json, os, re, pickle, html, sys
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

# Input paths — set PKL_IN / RAW_IN to match whatever PKL_OUT / RAW_OUT you used
# when running the source. Defaults match the sources' own defaults.
PKL_IN  = os.environ.get("PKL_IN",  os.environ.get("PKL_OUT",  "/tmp/tw-30d-processed.pkl"))
RAW_IN  = os.environ.get("RAW_IN",  os.environ.get("RAW_OUT",  "/tmp/tw-30d.json"))
PUB_IN  = os.environ.get("PUB_IN",  os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json"))

# Output paths — override to serve files from a web root or object storage mount.
HTML_OUT = os.environ.get("HTML_OUT", "/tmp/threat-watch.html")
JSON_OUT = os.environ.get("JSON_OUT", "/tmp/threat-watch-data.json")

def esc(s):
    return html.escape(s or "")

if not os.path.exists(PKL_IN):
    print(f"Error: pipeline data not found at {PKL_IN}", file=sys.stderr)
    print(f"Run a source first, e.g.:  python3 run.py --source rss --build", file=sys.stderr)
    sys.exit(1)

with open(PKL_IN, "rb") as f:
    state = pickle.load(f)
items = state["items"]
cutoff_dt = state["cutoff"]
now = datetime.now(timezone.utc)
window_days = (now - cutoff_dt).days

# Normalize lifecycle metadata for older/custom sources. The restrictive TLP
# default prevents an unknown source from being redistributed as public data.
for item in items:
    item.setdefault("source_type", "unknown")
    item.setdefault("source_reliability", "C")
    item.setdefault("tlp", "TLP:AMBER")
    item.setdefault("valid_until", "")
    item.setdefault("revoked", False)
    item.setdefault("analyst_disposition", "unreviewed")

# For OpenCTI runs, enrich item descriptions from the raw GraphQL dump.
# For all other sources, items already carry their descriptions — do NOT
# overwrite them with empty strings when RAW_IN is absent.
try:
    with open(RAW_IN) as f:
        raw = json.load(f)
    id_to_desc = {}
    for e in raw.get("data", {}).get("reports", {}).get("edges", []) or []:
        n = e["node"]
        desc = n.get("description") or ""
        if desc:
            id_to_desc[n["id"]] = re.sub(r"<[^>]+>", " ", desc).strip()
    # Only overwrite if we actually found a description in the OpenCTI dump
    for i in items:
        if i["id"] in id_to_desc:
            i["description"] = id_to_desc[i["id"]]
except FileNotFoundError:
    pass  # Non-OpenCTI sources don't produce RAW_IN — descriptions already in items

# Override OpenCTI ingest timestamp with the report's actual publication date when
# available, so WoW math reflects when news broke instead of when our pipeline
# ingested it. Priority: 1) `published` sidecar from OpenCTI GraphQL, 2) date
# embedded in the article URL. Historical publications older than the dashboard
# window keep their ingest timestamp — they're "newly relevant to us," not
# breaking news, and folding them into last-7d would inflate WoW deltas.
try:
    with open(PUB_IN) as f:
        pub_dates_raw = json.load(f)
except FileNotFoundError:
    pub_dates_raw = {}

URL_DATE_RE = re.compile(r"/(20\d{2})/(\d{2})(?:/(\d{2}))?/")
for i in items:
    candidate = None
    p = pub_dates_raw.get(i["id"])
    if p:
        try:
            candidate = datetime.fromisoformat(p.replace("Z", "+00:00"))
        except ValueError:
            candidate = None
    if candidate is None:
        url = i.get("url", "") or ""
        m = URL_DATE_RE.search(url)
        if m:
            y, mo, d = m.group(1), m.group(2), m.group(3) or "01"
            try:
                candidate = datetime(int(y), int(mo), int(d), tzinfo=timezone.utc)
            except ValueError:
                candidate = None
    if candidate and candidate >= cutoff_dt and candidate < i["created"]:
        i["created"] = candidate

# Threat-actor merges (2026: ShinyHunters/Scattered Spider operate as one cluster)
TA_MERGES = {
    "ShinyHunters":     "ShinyHunters / Scattered Spider",
    "Scattered Spider": "ShinyHunters / Scattered Spider",
}
for i in items:
    merged = []
    for t in i["tas"]:
        m = TA_MERGES.get(t, t)
        if m not in merged:
            merged.append(m)
    i["tas"] = merged

# ---- MITRE ATT&CK lookup ----
# Pattern → list of (technique_id, technique_name) tuples
MITRE_PATTERNS = [
    (re.compile(r"\b(supply chain|npm|package|typosquat|dependency|signed malicious|registry)\b", re.I),
     [("T1195", "Supply Chain Compromise"), ("T1554", "Compromise Client Software Binary")]),
    (re.compile(r"\b(OAuth|access token|session token|saml|sso|federated|oktapus)\b", re.I),
     [("T1528", "Steal Application Access Token"), ("T1078", "Valid Accounts")]),
    (re.compile(r"\b(phishing|spearphish|vishing|smishing|help[- ]?desk|social engineer)\b", re.I),
     [("T1566", "Phishing")]),
    (re.compile(r"\b(ransom\w+|encrypt files|extortion|leak site)\b", re.I),
     [("T1486", "Data Encrypted for Impact"), ("T1567", "Exfiltration Over Web Service")]),
    (re.compile(r"\b(backdoor|webshell|implant|reverse shell|persistence)\b", re.I),
     [("T1543", "Create or Modify System Process"), ("T1505", "Server Software Component")]),
    (re.compile(r"\b(command\s+and\s+control|c2|callback|beacon|exfiltrat\w+)\b", re.I),
     [("T1041", "Exfiltration Over C2 Channel"), ("T1071", "Application Layer Protocol")]),
    (re.compile(r"\b(lateral movement|east-west|pivot|spread to|propagat\w+|worm)\b", re.I),
     [("T1021", "Remote Services"), ("T1570", "Lateral Tool Transfer")]),
    (re.compile(r"\b(privilege escalation|assume[- ]?role|sts|service principal|escalat\w+)\b", re.I),
     [("T1548", "Abuse Elevation Control Mechanism"), ("T1078.004", "Cloud Accounts")]),
    (re.compile(r"\b(kubernetes|k8s|kubelet|pod|container escape|daemon\s*set)\b", re.I),
     [("T1611", "Escape to Host"), ("T1609", "Container Administration Command")]),
    (re.compile(r"\b(vishing|MFA fatigue|sim[\s-]?swap)\b", re.I),
     [("T1621", "Multi-Factor Authentication Request Generation")]),
    (re.compile(r"\b(prompt injection|jailbreak|data poisoning|model poisoning|llm)\b", re.I),
     [("T1059", "Command and Scripting Interpreter")]),
    (re.compile(r"\b(credential|secret|api[\s-]?key|harvest\w+)\b", re.I),
     [("T1552", "Unsecured Credentials"), ("T1078", "Valid Accounts")]),
]

# TA → known TTP packs (operational shortcuts when description thin)
TA_TTPS = {
    "ShinyHunters / Scattered Spider": [("T1078", "Valid Accounts"), ("T1566", "Phishing"), ("T1528", "Steal Application Access Token"), ("T1098.005", "Device Registration")],
    "APT29": [("T1078.004", "Cloud Accounts"), ("T1098", "Account Manipulation"), ("T1505", "Server Software Component")],
    "Volt Typhoon": [("T1078", "Valid Accounts"), ("T1059.001", "PowerShell"), ("T1021.001", "RDP")],
    "Salt Typhoon": [("T1190", "Exploit Public-Facing App"), ("T1505", "Server Software Component")],
    "Cl0p": [("T1190", "Exploit Public-Facing App"), ("T1567", "Exfiltration Over Web Service")],
    "Akira": [("T1486", "Data Encrypted for Impact"), ("T1567", "Exfiltration Over Web Service")],
    "Lazarus": [("T1566", "Phishing"), ("T1059", "Command and Scripting Interpreter")],
    "TeamPCP": [("T1195", "Supply Chain Compromise"), ("T1554", "Compromise Client Software Binary")],
    "Shai-Hulud": [("T1195", "Supply Chain Compromise"), ("T1554", "Compromise Client Software Binary")],
}

def extract_mitre(item):
    """Return list of (id, name) MITRE TTPs for an item. Deduplicated, max 4."""
    seen = set()
    out = []
    text = item["name"] + " " + (item.get("description") or "")[:600]
    for pat, ttps in MITRE_PATTERNS:
        if pat.search(text):
            for tid, tname in ttps:
                if tid not in seen:
                    seen.add(tid)
                    out.append((tid, tname))
    for ta in item.get("tas", []):
        for tid, tname in TA_TTPS.get(ta, []):
            if tid not in seen:
                seen.add(tid)
                out.append((tid, tname))
    return out[:4]

LEGIT_DOMAINS = {
    "thehackernews.com", "bleepingcomputer.com", "infosecurity-magazine.com", "wiz.io",
    "virustotal.com", "blog.virustotal.com", "cisa.gov", "github.com", "openai.com",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com", "microsoft.com",
    "twitter.com", "x.com", "linkedin.com",
    "google.com", "youtube.com", "reuters.com", "wired.com",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,3}(?:com|net|org|io|ai|dev|cloud|app|co|gov|edu|info|biz))\b", re.I)
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b")
HASH_RE = re.compile(r"\b[a-f0-9]{40,64}\b", re.I)

def extract_iocs(text):
    if not text:
        return {"cves": [], "domains": [], "ips": [], "hashes": []}
    cves = sorted(set(CVE_RE.findall(text)))[:5]
    raw_domains = sorted(set(DOMAIN_RE.findall(text)))
    domains = [d for d in raw_domains if d.lower() not in LEGIT_DOMAINS and "@" not in d][:5]
    ips = sorted(set(IP_RE.findall(text)))[:3]
    hashes = sorted(set(HASH_RE.findall(text)))[:2]
    return {"cves": cves, "domains": domains, "ips": ips, "hashes": hashes}

def key_points(text, max_points=3):
    """Pull first ~3 sentence-like fragments from description, stripped of markdown."""
    if not text:
        return []
    # Strip markdown bold/italic/code/footnote-refs
    text = re.sub(r"\*\*([^\*]+)\*\*", r"\1", text)
    text = re.sub(r"__([^_]+)__", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^\*]+)\*(?!\*)", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[[\d,\s]+\]", "", text)
    text = re.sub(r"^[#>\-\*\s]+", "", text, flags=re.M)
    sents = re.split(r"(?<=[.!?])\s+", text.strip())
    out = []
    for s in sents:
        s = re.sub(r"\s+", " ", s).strip()
        if 20 <= len(s) <= 220 and not s.startswith(("Read more", "Source:", "Originally", "D&R focus")):
            out.append(s)
        if len(out) >= max_points:
            break
    return out

# Fix Storm-#### naming: replace placeholder "Storm-" entries with actual matched group(s)
STORM_RE = re.compile(r"\bStorm-(\d{3,4})\b", re.I)
for i in items:
    if "Storm-" in i["tas"]:
        text = i["name"] + " " + (i.get("description") or "")
        real_storms = sorted({f"Storm-{m.group(1)}" for m in STORM_RE.finditer(text)})
        i["tas"] = [t for t in i["tas"] if t != "Storm-"] + real_storms

# Apply MITRE TTPs now that helpers exist
for i in items:
    i["mitre"] = extract_mitre(i)

# Tactic label lookup keyed by technique ID prefix.
# Used to derive mitre_tactics from technique IDs for sources that don't carry them.
_TACTIC_MAP = {
    "T1566": "initial-access",   "T1190": "initial-access",   "T1195": "initial-access",
    "T1554": "initial-access",   "T1078": "defense-evasion",
    "T1528": "credential-access","T1552": "credential-access", "T1621": "credential-access",
    "T1548": "privilege-escalation",
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1041": "exfiltration",     "T1567": "exfiltration",
    "T1486": "impact",
    "T1543": "persistence",      "T1505": "persistence",
    "T1071": "command-and-control",
    "T1041": "exfiltration",
    "T1059": "execution",
    "T1611": "privilege-escalation", "T1609": "execution",
    "T1098": "persistence",
}

def _tid_to_tactic(tid):
    """Return a tactic label for a technique ID, or None if unknown."""
    base = tid.split(".")[0]
    return _TACTIC_MAP.get(base)

# Backfill attack_technique_ids, mitre_tactics, and iocs for sources that don't
# populate them (RSS, Slack, Splunk set these to [] / {} in their item schema).
# This runs after extract_mitre() so mitre results are already in i["mitre"].
for i in items:
    # attack_technique_ids: derive from already-computed i["mitre"] when empty
    if not i.get("attack_technique_ids"):
        i["attack_technique_ids"] = [tid for tid, _name in i.get("mitre", [])]

    # mitre_tactics: derive from attack_technique_ids when empty
    if not i.get("mitre_tactics"):
        tactics = []
        for tid in i.get("attack_technique_ids", []):
            tac = _tid_to_tactic(tid)
            if tac and tac not in tactics:
                tactics.append(tac)
        i["mitre_tactics"] = tactics

    # iocs: run local extraction against title + description when empty.
    # Normalise to the canonical schema {cve, ipv4, domain, url, md5, sha1, sha256}
    # that validate.py and the agent layer expect.  The local extract_iocs() uses a
    # different key set (cves/ips/hashes) — convert here, leaving the HTML rendering
    # code (which uses the old keys) untouched.
    if not i.get("iocs"):
        text = (i.get("description") or "") + " " + (i.get("name") or "")
        raw = extract_iocs(text)
        # Classify hashes by length: 32=md5, 40=sha1, 64=sha256
        md5s, sha1s, sha256s = [], [], []
        for h in raw.get("hashes", []):
            n = len(h)
            if n == 32:   md5s.append(h)
            elif n == 40: sha1s.append(h)
            elif n == 64: sha256s.append(h)
        i["iocs"] = {
            "cve":    raw.get("cves", []),
            "ipv4":   raw.get("ips", []),
            "domain": raw.get("domains", []),
            "url":    [],
            "md5":    md5s,
            "sha1":   sha1s,
            "sha256": sha256s,
        }

def talking_points(item, containment_narrative_map):
    """Generate 3-4 customer/analyst talking points from item metadata."""
    points = []
    tas = item.get("tas", [])
    cloud_tags = [l for l in item["all_labels"] if l.startswith("cloud-")]
    ai_tags = [l for l in item["all_labels"] if l.startswith("ai-")]

    if tas:
        points.append(f"Adversary attribution: {tas[0]}. Pivot via OpenCTI ThreatActor SDO for known IOCs.")
    if cloud_tags:
        clouds = ", ".join(t.replace("cloud-", "").upper() for t in cloud_tags if t != "cloud")
        if clouds:
            points.append(f"Cloud surface impacted: {clouds}. Confirm customer estate exposure first.")
    if ai_tags:
        ai_kinds = ", ".join(t.replace("ai-", "") for t in ai_tags if t != "ai")
        if ai_kinds:
            points.append(f"AI surface: {ai_kinds}. Frame as positioning moment for AI security messaging.")

    nar = containment_narrative_map.get(item["id"])
    if nar:
        points.append(f"Containment angle: {nar}")

    if cloud_tags:
        clouds_q = ", ".join(t.replace("cloud-", "").upper() for t in cloud_tags if t != "cloud")
        points.append(f"Customer ask: \"Do you run anything in {clouds_q or 'these surfaces'}?\" If yes, validate posture against this TTP.")
    else:
        points.append("Customer ask: confirm whether their threat model accounts for this TTP.")

    return points[:4]

# ---- Aggregations ----
n_total = len(items)
n_ai = sum(1 for i in items if any(l == "ai" or l.startswith("ai-") for l in i["all_labels"]))
n_cloud = sum(1 for i in items if any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"]))
n_pubs = len(set(i["publisher"] for i in items))

# Distinct cloud sub-tags
cloud_subtags = Counter()
ai_subtags = Counter()
for i in items:
    for l in i["all_labels"]:
        if l.startswith("cloud-"):
            cloud_subtags[l] += 1
        elif l.startswith("ai-"):
            ai_subtags[l] += 1

# Threat actor counts + WoW delta (last 7d vs prior 7d)
seven_d = now - timedelta(days=7)
fourteen_d = now - timedelta(days=14)
ta_counts = Counter()
ta_last_week = Counter()
ta_prev_week = Counter()
ta_best_example = {}  # ta -> best item (highest confidence, most recent)
for i in items:
    for ta in i["tas"]:
        ta_counts[ta] += 1
        if i["created"] >= seven_d:
            ta_last_week[ta] += 1
        elif i["created"] >= fourteen_d:
            ta_prev_week[ta] += 1
        # Best example: highest confidence, then most recent
        prev = ta_best_example.get(ta)
        if (prev is None
            or i["confidence"] > prev["confidence"]
            or (i["confidence"] == prev["confidence"] and i["created"] > prev["created"])):
            ta_best_example[ta] = i

# Pick top 8 actors by total mentions, but only those with ≥2 hits
top_actors_raw = [(ta, c) for ta, c in ta_counts.most_common() if c >= 2][:8]

def wow_status(ta):
    last = ta_last_week.get(ta, 0)
    prev = ta_prev_week.get(ta, 0)
    delta = last - prev
    if prev == 0 and last > 0:
        return ("new", last, delta)
    if delta > 0:
        return ("up", last, delta)
    if delta < 0:
        return ("down", last, delta)
    return ("flat", last, delta)

# ---- Cloud Threat Watch: cluster + score ----
def cloud_shape_score(item):
    cloud_tags = [l for l in item["all_labels"] if l == "cloud" or l.startswith("cloud-")]
    if not cloud_tags:
        return 0
    return len(cloud_tags) * 7

def industry_reach(items_in_cluster):
    pubs = set(i["publisher"] for i in items_in_cluster)
    cloud_tags = set()
    ai_tags = set()
    for i in items_in_cluster:
        for l in i["all_labels"]:
            if l.startswith("cloud-"):
                cloud_tags.add(l)
            elif l.startswith("ai-"):
                ai_tags.add(l)
    tas = set()
    for i in items_in_cluster:
        for ta in i["tas"]:
            tas.add(ta)
    reach = len(pubs) * 12 + len(cloud_tags) * 7 + len(ai_tags) * 5 + len(tas) * 8
    return min(reach, 100)

# Cluster by shared anchor: TA names. Items with no TA are singletons.
clusters = []
ta_to_cluster = {}
for item in items:
    if not item["tas"]:
        clusters.append([item])
        continue
    # Find existing cluster for any of this item's TAs
    target = None
    for ta in item["tas"]:
        if ta in ta_to_cluster:
            target = ta_to_cluster[ta]
            break
    if target is None:
        target = []
        clusters.append(target)
        for ta in item["tas"]:
            ta_to_cluster[ta] = target
    else:
        for ta in item["tas"]:
            ta_to_cluster.setdefault(ta, target)
    target.append(item)

# Score clusters that contain cloud-shaped stories
cloud_clusters = []
for cluster in clusters:
    has_cloud = any(any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"]) for i in cluster)
    if not has_cloud:
        continue
    reach = industry_reach(cluster)
    # Lead item: highest confidence, then most recent
    lead = max(cluster, key=lambda x: (x["confidence"], x["created"]))
    cloud_tags = sorted(set(l for i in cluster for l in i["all_labels"] if l == "cloud" or l.startswith("cloud-")))
    ai_tags = sorted(set(l for i in cluster for l in i["all_labels"] if l == "ai" or l.startswith("ai-")))
    pubs = sorted(set(i["publisher"] for i in cluster))
    tas_in_cluster = sorted(set(ta for i in cluster for ta in i["tas"]))
    cloud_clusters.append({
        "lead": lead,
        "items": cluster,
        "reach": reach,
        "cloud_tags": cloud_tags,
        "ai_tags": ai_tags,
        "publishers": pubs,
        "tas": tas_in_cluster,
        "size": len(cluster),
    })
cloud_clusters.sort(key=lambda c: (-c["reach"], -c["lead"]["confidence"], -c["lead"]["created"].timestamp()))
TOP_CLOUD = cloud_clusters[:8]

# ---- Cloud Threat Watch overview synthesis ----
def cloud_overview(top_clusters):
    if not top_clusters:
        return None
    total_reports = sum(c["size"] for c in top_clusters)
    high_reach = sum(1 for c in top_clusters if c["reach"] >= 60)
    # Top cloud sub-tags across cluster lead items + cluster aggregates
    surface_counter = Counter()
    for c in top_clusters:
        for tag in c["cloud_tags"]:
            if tag.startswith("cloud-"):
                surface_counter[tag.replace("cloud-", "")] += 1
    top_surfaces = surface_counter.most_common(4)
    # Top adversaries across clusters
    actor_counter = Counter()
    for c in top_clusters:
        for ta in c["tas"]:
            actor_counter[ta] += 1
    top_actors = actor_counter.most_common(3)
    # Top publishers across the displayed clusters
    pub_counter = Counter()
    for c in top_clusters:
        for p in c["publishers"]:
            pub_counter[p] += 1
    top_pubs = pub_counter.most_common(5)
    # Theme detection — count cluster patterns
    theme_counts = {"Supply chain": 0, "Identity / SaaS takeover": 0, "Container / K8s": 0,
                    "Multi-cloud campaigns": 0, "Backdoor / persistence": 0}
    sc_pat = re.compile(r"\b(supply chain|npm|package|typosquat|registry|signed malicious|build pipeline|shai)\b", re.I)
    id_pat = re.compile(r"\b(oauth|salesforce|okta|sso|federated|service principal|sts|assume role|saas|account takeover)\b", re.I)
    k8s_pat = re.compile(r"\b(kubernetes|k8s|kubelet|pod|container|docker|namespace)\b", re.I)
    bd_pat = re.compile(r"\b(backdoor|persistence|implant|webshell|c2|command\s+and\s+control)\b", re.I)
    for c in top_clusters:
        blob = " ".join(i["name"] + " " + i.get("description", "")[:300] for i in c["items"])
        cloud_tag_count = len(set(c["cloud_tags"]) - {"cloud"})
        if cloud_tag_count >= 3:
            theme_counts["Multi-cloud campaigns"] += 1
        if sc_pat.search(blob):
            theme_counts["Supply chain"] += 1
        if id_pat.search(blob):
            theme_counts["Identity / SaaS takeover"] += 1
        if k8s_pat.search(blob):
            theme_counts["Container / K8s"] += 1
        if bd_pat.search(blob):
            theme_counts["Backdoor / persistence"] += 1
    top_themes = sorted(theme_counts.items(), key=lambda x: -x[1])
    top_themes = [(name, cnt) for name, cnt in top_themes if cnt > 0][:3]
    return {
        "total_clusters": len(top_clusters),
        "total_reports": total_reports,
        "high_reach": high_reach,
        "surfaces": top_surfaces,
        "actors": top_actors,
        "publishers": top_pubs,
        "themes": top_themes,
    }

CLOUD_OVERVIEW = cloud_overview(TOP_CLOUD)

# Filter cloud-shaped item IDs to exclude from Industry Pulse
cloud_story_ids = set(i["id"] for c in cloud_clusters for i in c["items"])

# ---- Containment Impact: stories where network-level containment would matter ----
# Heuristic: stories involving lateral movement, supply chain, credential reuse,
# multi-cloud, K8s/container pivot, C2/exfil — the patterns network controls address.
CONTAINMENT_PATTERNS = [
    ("lateral_movement", re.compile(r"\b(lateral movement|east-west|pivot|spread to|propagat\w+|worm)\b", re.I), 25),
    ("supply_chain",     re.compile(r"\b(supply chain|npm|package|typosquat|dependency|registry|signed\s+malicious)\b", re.I), 22),
    ("credential",       re.compile(r"\b(credential|token|oauth|secret|api[\s-]?key|session)\b", re.I), 18),
    ("exfil_c2",         re.compile(r"\b(exfiltrat\w+|command\s+and\s+control|c2|callback|beacon)\b", re.I), 20),
    ("ransomware",       re.compile(r"\b(ransom\w+|encrypt\w+|extortion)\b", re.I), 15),
    ("backdoor",         re.compile(r"\b(backdoor|persistence|implant|webshell|reverse shell)\b", re.I), 18),
    ("k8s_container",    re.compile(r"\b(k8s|kubernetes|kubelet|pod|container|docker|namespace)\b", re.I), 15),
    ("identity",         re.compile(r"\b(privilege escalation|assume[- ]?role|sts|iam|service principal|impersonat\w+)\b", re.I), 18),
]

def containment_score(item):
    score = 0
    matched = []
    blob = item["name"] + " " + " ".join(item.get("tas", []))
    # Also check labels for cloud surface area
    cloud_tags = [l for l in item["all_labels"] if l.startswith("cloud-")]
    if len(cloud_tags) >= 3:
        score += 20
        matched.append("multi-cloud surface")
    if "cloud-k8s" in item["all_labels"] or "cloud-container" in item["all_labels"]:
        score += 15
        matched.append("container/k8s")
    for name, pat, weight in CONTAINMENT_PATTERNS:
        if pat.search(blob):
            score += weight
            matched.append(name)
    if item["tas"]:
        score += 10
        matched.append("named TA")
    return score, matched

_NOUN_BLACKLIST = {"The","With","And","For","From","Into","Over","Under","This","That","Why",
                   "New","Targets","Targeting","Attack","Attacks","Campaign","Incident","Research",
                   "Cloud","Supply","Chain","Cyber","Network","Industry","Group","Company","Team"}

def _key_noun(title):
    """Pull a distinctive technical noun from a report title for narrative variation
    (e.g. 'Shai-Hulud', 'TanStack', 'Trivy', 'SilentBob', 'APT29'). Returns None when
    nothing distinctive is found."""
    if not title:
        return None
    t = re.sub(r"\s*\((Campaign|Incident|Research)\)\s*$", "", title, flags=re.I)
    for w in re.findall(r"\b([A-Z][\w\-]{2,})\b", t):
        if w not in _NOUN_BLACKLIST:
            return w
    return None

# Narrative templates for the Containment Impact rows. Each pattern category holds
# multiple variants so adjacent rows in the section don't repeat verbatim — the
# rendering loop rotates `variant_idx` per category. `{ref}` interpolates an actor
# name when available, otherwise a key noun from the title (e.g. "Shai-Hulud").
_CONTAINMENT_TEMPLATES = {
    "k8s": [
        "East-west microsegmentation between K8s namespaces would have stopped {ref}'s pivot before it reached the control plane.",
        "Pod-to-pod network policy on the affected cluster would have isolated {ref}'s entry workload from the cluster API.",
        "Identity-bound segmentation around K8s service accounts would have blocked {ref}'s lateral spread inside the cluster.",
    ],
    "container": [
        "Container egress policy would have caught {ref} the moment it tried to reach out from the build host.",
        "Restricting CI/CD outbound traffic to allowlisted destinations would have neutered {ref}'s post-install callback.",
        "Image-pull and registry-egress gates would have flagged {ref}'s tampered container before it ran in production.",
    ],
    "lateral_other": [
        "Workload-to-workload segmentation would have contained {ref}'s lateral movement to a single tier.",
        "Identity-aware east-west policy would have stopped {ref} from chaining accounts across the estate.",
    ],
    "supply_chain": [
        "Egress policy on CI/CD pipelines would have blocked {ref}'s outbound callback before any credential left the runner.",
        "An identity-aware egress wall around the build cluster severs {ref}'s C2 — the dependency could install, but couldn't phone home.",
        "Inline package-registry inspection plus build-host allowlisting would have caught {ref}'s preinstall script the moment it fetched its payload.",
        "Microsegmentation between the build pipeline and prod cloud accounts would have kept {ref} from reaching production secrets through the dependency graph.",
    ],
    "identity_saas": [
        "OAuth-aware network policy would have flagged {ref}'s cross-tenant token replay.",
        "Conditional access tied to network identity would have rejected {ref}'s session reuse from an out-of-policy origin.",
    ],
    "identity": [
        "Identity-aware network gates would have caught {ref}'s credential reuse across cloud accounts.",
        "Cross-account egress controls would have surfaced {ref}'s assume-role chain as anomalous traffic.",
    ],
    "exfil_c2": [
        "Egress filtering and DNS-policy enforcement would have severed {ref}'s C2 channel before exfil completed.",
        "Outbound destination allowlisting on the affected tier would have starved {ref}'s beacon traffic.",
    ],
    "ransomware": [
        "Network-level kill switches on encryption-style traffic would have caught {ref} mid-encrypt and bought response time.",
        "East-west policy enforcement would have isolated {ref}'s blast radius to a single segment before the ransom note dropped.",
    ],
    "backdoor": [
        "Microsegmentation between tiers would have prevented {ref}'s backdoor from reaching the crown jewels.",
        "Inline egress inspection on the compromised host would have surfaced {ref}'s implant on its first callback.",
    ],
    "multicloud": [
        "Cross-cloud network policy would have contained {ref} to a single platform instead of letting it ride hybrid trust paths.",
        "A unified network plane across AWS/Azure/GCP would have shut down {ref}'s multi-cloud reach at the first pivot.",
    ],
    "generic": [
        "Network-level controls would have reduced {ref}'s blast radius.",
        "Inline egress plus identity-aware policy would have constrained {ref}'s footprint to the compromised tier.",
    ],
}

def _containment_category(item, matched):
    """Pick the most specific narrative bucket for an item."""
    labels = item["all_labels"]
    cloud_tags = [l for l in labels if l.startswith("cloud-")]
    if "lateral_movement" in matched or "k8s_container" in matched:
        if "cloud-k8s" in labels:
            return "k8s"
        if "cloud-container" in labels:
            return "container"
        return "lateral_other"
    if "supply_chain" in matched:
        return "supply_chain"
    if "credential" in matched or "identity" in matched:
        return "identity_saas" if "cloud-saas" in labels else "identity"
    if "exfil_c2" in matched:
        return "exfil_c2"
    if "ransomware" in matched:
        return "ransomware"
    if "backdoor" in matched:
        return "backdoor"
    if len(cloud_tags) >= 3:
        return "multicloud"
    return "generic"

def containment_narrative(item, matched, variant_idx=0):
    """Render a one-line 'if contained at network level' narrative for a story.

    `variant_idx` rotates through the templates available for the item's primary
    category so the Containment Impact section doesn't show the same sentence on
    adjacent rows. The story's threat actor (or, failing that, a key noun from
    its title) is interpolated as `{ref}` so each line names what it's about.
    """
    cat = _containment_category(item, matched)
    variants = _CONTAINMENT_TEMPLATES[cat]
    tpl = variants[variant_idx % len(variants)]
    actor = item.get("tas", [None])[0] if item.get("tas") else None
    noun = _key_noun(item.get("name", ""))
    ref = actor or noun or "this campaign"
    return tpl.format(ref=ref)

containment_candidates = []
for i in items:
    score, matched = containment_score(i)
    if score >= 30 and matched:
        containment_candidates.append({"item": i, "score": score, "matched": matched})
containment_candidates.sort(key=lambda x: (-x["score"], -x["item"]["confidence"], -x["item"]["created"].timestamp()))
# Dedupe by TA (so we don't show 5 Scattered Spider stories)
seen_anchors = set()
TOP_CONTAINMENT = []
category_idx_counter = Counter()  # rotates narrative variants per category
for c in containment_candidates:
    it = c["item"]
    anchor = tuple(it["tas"]) if it["tas"] else (it["id"],)
    if anchor in seen_anchors:
        continue
    seen_anchors.add(anchor)
    cat = _containment_category(it, c["matched"])
    variant = category_idx_counter[cat]
    category_idx_counter[cat] += 1
    c["narrative"] = containment_narrative(it, c["matched"], variant)
    TOP_CONTAINMENT.append(c)
    if len(TOP_CONTAINMENT) >= 6:
        break

# Build a per-item containment-narrative lookup so any item can borrow the angle.
# Popovers show one narrative per item, so use variant 0 for stability.
containment_narrative_map = {}
for i in items:
    score, matched = containment_score(i)
    if score >= 30 and matched:
        containment_narrative_map[i["id"]] = containment_narrative(i, matched, 0)

# ---- Containment value stat (page banner) ----
# Honest framing: we score reports against patterns that network controls TARGET — not "prevented"
cloud_relevant_items = [i for i in items if any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"])]
containment_matched_items = [i for i in cloud_relevant_items if i["id"] in containment_narrative_map]
containment_pct = round(100 * len(containment_matched_items) / max(len(cloud_relevant_items), 1))

# Cluster-level math: how many of the TOP cloud-threat clusters involve containment-relevant patterns?
# This is the more defensible value claim because each cluster represents a coherent story (not a single report)
containment_cluster_count = 0
for c in TOP_CLOUD:
    if any(it["id"] in containment_narrative_map for it in c["items"]):
        containment_cluster_count += 1
containment_cluster_total = len(TOP_CLOUD)

# ---- Industry Trends: bucket stories by attack pattern ----
TREND_BUCKETS = {
    "Supply chain as initial access": {
        "pattern": re.compile(r"\b(supply chain|npm|package|typosquat|malicious\s+(?:hugging|github|npm|pypi|registry|dependency)|signed\s+malicious|build\s+pipeline)\b", re.I),
        "icon": "🔗",
        "narrative_template": "{count} reports in 30 days show adversaries injecting payloads upstream of the victim — bypassing perimeter detection entirely.",
    },
    "Identity-driven cloud takeover": {
        "pattern": re.compile(r"\b(OAuth|session\s+token|salesforce|okta|sso|federated|service\s+principal|assume[- ]?role|sts|takeover)\b", re.I),
        "icon": "🔑",
        "narrative_template": "{count} reports involve adversaries living off identity tokens rather than exploits. Help-desk vishing, OAuth abuse, and federated trust are the new beachheads.",
    },
    "AI ecosystem under attack": {
        "pattern": re.compile(r"\b(LLM|MCP|prompt\s+injection|hugging\s*face|openai|agentic|jailbreak|deepfake|model\s+poisoning|claude|gpt-?\d)\b", re.I),
        "icon": "🤖",
        "narrative_template": "{count} reports target AI infrastructure itself — model registries, MCP servers, agentic toolchains. AI is now both target and attack vector.",
    },
    "Ransomware → data extortion": {
        "pattern": re.compile(r"\b(ransom\w+|data\s+(?:extortion|leak|theft)|encrypt\w+|double[- ]?extortion|leak\s+site)\b", re.I),
        "icon": "💰",
        "narrative_template": "{count} reports show ransomware actors prioritizing data theft over encryption. The pressure point has shifted from \"recover your files\" to \"keep this off the leak site\".",
    },
    "State-aligned cloud espionage": {
        "pattern": re.compile(r"\b(typhoon|kimsuky|lazarus|apt2[89]|apt4[01]|sandworm|mustang panda|nation[- ]?state|state[- ]?aligned|china|russia|north korea|iran)\b", re.I),
        "icon": "🌐",
        "narrative_template": "{count} reports tie to state-aligned threat actors targeting cloud infrastructure. Persistent, long-dwell, intel-gathering posture rather than smash-and-grab.",
    },
    "Container and K8s exploitation": {
        "pattern": re.compile(r"\b(kubernetes|k8s|kubelet|pod|container|docker|namespace|daemon\s*set|sidecar)\b", re.I),
        "icon": "📦",
        "narrative_template": "{count} reports involve container/Kubernetes compromise. Build-time injection and runtime escape are converging as twin attack surfaces.",
    },
}

trends = []
for trend_name, conf in TREND_BUCKETS.items():
    matched = []
    for i in items:
        blob = i["name"] + " " + " ".join(i["tas"])
        if conf["pattern"].search(blob):
            matched.append(i)
    if len(matched) >= 3:
        # Top 3 example stories from this trend, by confidence then recency
        matched.sort(key=lambda x: (-x["confidence"], -x["created"].timestamp()))
        trends.append({
            "name": trend_name,
            "icon": conf["icon"],
            "count": len(matched),
            "narrative": conf["narrative_template"].format(count=len(matched)),
            "examples": matched[:3],
            # Wider candidate pool for the Executive Overview imperatives —
            # the trend-card UI still uses examples[:3], but the imperatives
            # picker needs more to choose from to find a threat-shaped title.
            "all_matched": matched[:25],
            # Preserve the bucket's keyword regex so the picker can prefer
            # examples that actually evidence *this* trend (not some other one).
            "pattern": conf["pattern"],
            "last7": sum(1 for m in matched if m["created"] >= seven_d),
            "prev7": sum(1 for m in matched if fourteen_d <= m["created"] < seven_d),
        })
trends.sort(key=lambda x: -x["count"])
TOP_TRENDS = trends[:6]

# ---- Industry Pulse: non-cloud-clustered, top 15 by recency × confidence ----
pulse_candidates = [
    i for i in items
    if i["id"] not in cloud_story_ids
    and i["labels"]
    and i["confidence"] >= 70
]
pulse_candidates.sort(key=lambda x: (-x["confidence"], -x["created"].timestamp()))
TOP_PULSE = pulse_candidates[:15]

# ---- Industry Pulse narrative (replace 15-row list with synthesized paragraph) ----
def pulse_narrative(pulse_items):
    if not pulse_items:
        return "<em>Broader signal was quiet this period.</em>"
    buckets = defaultdict(list)
    for it in pulse_items:
        t = it["name"].lower() + " " + " ".join(it.get("tas", [])).lower()
        if any(k in t for k in ["llm", "openai", "agent", "mcp", "deepfake", "huggingface", "ai ", "agentic"]):
            buckets["ai"].append(it)
        elif any(k in t for k in ["ransom", "extortion", "leak site"]):
            buckets["ransom"].append(it)
        elif any(k in t for k in ["phish", "oauth", "credential", "token", "session", "okta", "salesforce"]):
            buckets["identity"].append(it)
        elif any(k in t for k in ["supply chain", "npm", "package", "registry", "typosquat"]):
            buckets["supply"].append(it)
        else:
            buckets["other"].append(it)
    def first_link(its):
        x = its[0]
        url = x.get("url") or "#"
        return f'<em><a href="{esc(url)}" target="_blank">{esc(x["name"][:90])}{"…" if len(x["name"])>90 else ""}</a></em>'
    parts = []
    if buckets["ai"]:
        parts.append(f"<strong>AI-shaped reporting</strong> continued ({len(buckets['ai'])} items), led by {first_link(buckets['ai'])}.")
    if buckets["supply"]:
        parts.append(f"<strong>Supply-chain stories</strong> stayed active ({len(buckets['supply'])} items), including {first_link(buckets['supply'])}.")
    if buckets["identity"]:
        parts.append(f"<strong>Identity / credential-driven</strong> attacks ran across {len(buckets['identity'])} reports — {first_link(buckets['identity'])}.")
    if buckets["ransom"]:
        parts.append(f"<strong>Ransomware / extortion</strong> coverage remained {('elevated' if len(buckets['ransom'])>=3 else 'steady')} with {len(buckets['ransom'])} items.")
    if buckets["other"]:
        parts.append(f"{len(buckets['other'])} additional industry stories rounded out the period's signal.")
    return " ".join(parts) or "<em>Broader signal was quiet this period.</em>"

PULSE_NARRATIVE = pulse_narrative(TOP_PULSE)

# ---- Vendor Watch ----
vendor_t1_hits = defaultdict(list)
vendor_t2_hits = defaultdict(list)
for i in items:
    for v in i["t1_vendors"]:
        vendor_t1_hits[v].append(i)
    for v in i["t2_vendors"]:
        vendor_t2_hits[v].append(i)
top_t1 = sorted(vendor_t1_hits.items(), key=lambda x: -len(x[1]))[:8]
top_t2 = sorted(vendor_t2_hits.items(), key=lambda x: -len(x[1]))[:8]

# ---- Executive Overview (replaces the old TL;DR) ----
# Thesis sentence built from cloud-weighted trends + most-active CLOUD adversary.
# Re-score trends by their cloud overlap so the opening leads with cloud-specific forces.
cloud_trends_ranked = []
for trend_name, conf in TREND_BUCKETS.items():
    matched = [i for i in items if conf["pattern"].search(i["name"] + " " + " ".join(i["tas"]))]
    cloud_matched = [i for i in matched if any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"])]
    if len(cloud_matched) >= 3:
        cloud_trends_ranked.append({
            "name": trend_name,
            "cloud_count": len(cloud_matched),
            "total": len(matched),
        })
cloud_trends_ranked.sort(key=lambda x: -x["cloud_count"])

# Most-active CLOUD adversary: filter top_actors_raw to those whose reports include cloud labels
cloud_actor = None
for ta, _ in top_actors_raw:
    cloud_report_count = sum(
        1 for i in items
        if ta in i["tas"]
        and any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"])
    )
    if cloud_report_count >= 2:
        cloud_actor = (ta, cloud_report_count)
        break

top_actor_name = cloud_actor[0] if cloud_actor else (top_actors_raw[0][0] if top_actors_raw else None)
top_actor_last7 = ta_last_week.get(top_actor_name, 0) if top_actor_name else 0

forces = [t["name"].lower() for t in cloud_trends_ranked[:3]]

if len(forces) >= 3 and top_actor_name:
    thesis_sentence = (
        f"The cloud-threat landscape is now defined by three forces: "
        f"<strong>{esc(forces[0])}</strong>, <strong>{esc(forces[1])}</strong>, "
        f"and <strong>{esc(forces[2])}</strong>. "
        f"<strong>{esc(top_actor_name)}</strong> remain the most active cloud-targeting adversary cluster, "
        f"appearing in {top_actor_last7} report{'s' if top_actor_last7 != 1 else ''} in the last 7 days."
    )
elif len(forces) >= 2 and top_actor_name:
    thesis_sentence = (
        f"Cloud-threat reporting this month centers on "
        f"<strong>{esc(forces[0])}</strong> and <strong>{esc(forces[1])}</strong>. "
        f"<strong>{esc(top_actor_name)}</strong> remain the most active cloud-targeting cluster."
    )
else:
    thesis_sentence = (
        f"{n_total} cloud- and AI-relevant reports landed across {n_pubs} publishers in the last {window_days} days. "
        "Detail below."
    )

# Three executive stats
exec_stats = [
    {"value": str(n_cloud), "label": f"cloud-relevant reports tracked / {window_days}d", "kind": "num"},
    {"value": top_actor_name or "—", "label": "most-active cloud-targeting cluster", "kind": "text"},
    {"value": cloud_trends_ranked[0]["name"] if cloud_trends_ranked else (TOP_TRENDS[0]["name"] if TOP_TRENDS else "—"),
     "label": f"#1 cloud attack vector · {cloud_trends_ranked[0]['cloud_count']} cloud reports / {window_days}d" if cloud_trends_ranked else "—",
     "kind": "text"},
]

# Lead story — highest-reach cluster
lead_cluster = TOP_CLOUD[0] if TOP_CLOUD else None
if lead_cluster:
    lead_story = {
        "title": lead_cluster["lead"]["name"],
        "url": lead_cluster["lead"]["url"] or "#",
        "pubs": len(lead_cluster["publishers"]),
        "reach": lead_cluster["reach"],
        "actor": lead_cluster["tas"][0] if lead_cluster["tas"] else None,
        "mitre": [],
    }
    seen_tid = set()
    for it in lead_cluster["items"]:
        for tid, tname in it.get("mitre", []):
            if tid not in seen_tid:
                seen_tid.add(tid)
                lead_story["mitre"].append((tid, tname))
            if len(lead_story["mitre"]) >= 3:
                break
        if len(lead_story["mitre"]) >= 3:
            break
else:
    lead_story = None

_THREAT_WORDS = re.compile(
    r"\b(attack|compromis|exploit|malicious|breach|campaign|targets?|vulnerab|"
    r"backdoor|stolen|leaked|ransom|threat|abus(?:e|ing)|hijack|worm|"
    r"data\s+theft|extort|cryptomin)\b",
    re.I,
)
_DEFENSIVE_WORDS = re.compile(
    r"\b(launch(?:es|ed)?|announce|secure by design|partnership|release|"
    r"introduce|unveil|press release|why\s+\w+\s+is)\b",
    re.I,
)

def _pick_threat_example(examples, prefer_pattern=None):
    """Choose the most threat-shaped example for an imperative.

    Scoring rationale (in priority order):
      • +80 named threat actor on the report — it's a real campaign story, not
        a generic mention. This is the strongest signal that the article is
        evidencing adversary behaviour rather than commentary.
      • +50 threat-shaped vocabulary in the title (attack/breach/campaign/etc.).
      • +40 the trend's *own* keyword regex matches the title (so a 'ransomware'
        trend prefers a title containing 'ransom', not just 'data theft').
      • -60 defensive/announcement vocabulary (e.g. "OpenAI Launches Daybreak").
    """
    if not examples:
        return None
    best = None
    best_score = -10**9
    for ex in examples:
        name = ex.get("name", "") or ""
        score = ex.get("confidence", 0) or 0
        if ex.get("tas"):
            score += 80
        if _THREAT_WORDS.search(name):
            score += 50
        if prefer_pattern and prefer_pattern.search(name):
            score += 40
        if _DEFENSIVE_WORDS.search(name):
            score -= 60
        if score > best_score:
            best_score = score
            best = ex
    return best

# Three "On your radar" items — all pure threat-intel signal (no operational guidance).
# Each expands on a different slice of the corpus so they don't repeat the exec stats.
imperatives = []

# 1) Adversary watch — surface & latest campaign for the top actor cluster.
#    Exec stat #2 already names the actor; this imperative tells the reader
#    *where* they're operating and *which named campaign* anchors their activity.
if top_actor_name:
    actor_total = ta_counts.get(top_actor_name, 0)
    actor_last7 = ta_last_week.get(top_actor_name, 0)
    actor_items = [i for i in items if top_actor_name in i["tas"]]
    surface_counter = Counter()
    for it in actor_items:
        for l in it["all_labels"]:
            if l.startswith("cloud-") and l != "cloud":
                surface_counter[l.replace("cloud-", "").upper()] += 1
    top_surfaces = [s for s, _ in surface_counter.most_common(2)]
    surface_phrase = ""
    if top_surfaces:
        surface_phrase = f" Primary surface: <strong>{esc(' / '.join(top_surfaces))}</strong>."
    actor_lead = ta_best_example.get(top_actor_name)
    lead_phrase = ""
    if actor_lead:
        lead_title = actor_lead["name"][:80] + ("…" if len(actor_lead["name"]) > 80 else "")
        lead_phrase = f' Lead campaign: <em>"{esc(lead_title)}"</em>.'
    imperatives.append({
        "label": "Adversary watch",
        "body": (
            f"<strong>{esc(top_actor_name)}</strong> — {actor_total} report"
            f"{'s' if actor_total != 1 else ''} / 30d, {actor_last7} in the last 7 days."
            f"{surface_phrase}{lead_phrase}"
        ),
    })

# 2) Vector watch — shape of the dominant attack pattern (count + publisher
#    diversity + canonical story). Exec stat #3 names the vector; this gives
#    the reader the publisher footprint and a specific story to point at.
if TOP_TRENDS:
    t = TOP_TRENDS[0]
    # Prefer a story whose title matches the trend's own keyword regex so the
    # representative actually evidences this vector — using a global keyword
    # union would let cross-trend matches (e.g. "prompt" in a ransomware title)
    # win out over a real ransom story.
    rep = _pick_threat_example(
        t.get("all_matched") or t.get("examples") or [],
        prefer_pattern=t.get("pattern"),
    )
    pubs_in_trend = {e["publisher"] for e in (t.get("all_matched") or t.get("examples") or [])}
    pub_phrase = (
        f" across {len(pubs_in_trend)} publisher{'s' if len(pubs_in_trend) != 1 else ''}"
        if pubs_in_trend else ""
    )
    rep_phrase = ""
    if rep:
        rep_title = rep["name"][:80] + ("…" if len(rep["name"]) > 80 else "")
        rep_phrase = f' Representative: <em>"{esc(rep_title)}"</em>.'
    imperatives.append({
        "label": "Vector watch",
        "body": (
            f"<strong>{esc(t['name'])}</strong> — {t['count']} reports / 30d{pub_phrase}."
            f"{rep_phrase}"
        ),
    })

# 3) AI ecosystem watch — pulled out as its own item because it's strategically
#    distinct from the cloud-incident mix and otherwise gets buried in Industry
#    Trends. Falls back to the second-ranked trend if no AI-tagged trend
#    crossed threshold.
ai_trend = next(
    (t for t in TOP_TRENDS if "AI" in t["name"] or "ai" in t["name"].lower().split()),
    None,
)
emerging = ai_trend or (TOP_TRENDS[1] if len(TOP_TRENDS) > 1 else None)
if emerging:
    label = "AI ecosystem watch" if emerging is ai_trend else "Emerging signal"
    # Demote defensive announcements (e.g. "OpenAI Launches Daybreak") so the
    # 'Watch' example points at an actual adversary story. Trend-specific
    # keyword regex (preserved on the trend dict) keeps the boost honest.
    rep = _pick_threat_example(
        emerging.get("all_matched") or emerging.get("examples") or [],
        prefer_pattern=emerging.get("pattern"),
    )
    rep_phrase = ""
    if rep:
        rep_title = rep["name"][:80] + ("…" if len(rep["name"]) > 80 else "")
        rep_phrase = f' Watch: <em>"{esc(rep_title)}"</em>.'
    if emerging is ai_trend:
        body = (
            f"<strong>{esc(emerging['name'])}</strong> — {emerging['count']} reports / 30d "
            f"targeting AI infrastructure (model registries, MCP servers, agentic toolchains)."
            f"{rep_phrase}"
        )
    else:
        body = (
            f"<strong>{esc(emerging['name'])}</strong> — {emerging['count']} reports / 30d."
            f"{rep_phrase}"
        )
    imperatives.append({"label": label, "body": body})

imperatives = imperatives[:3]

pub_counts = Counter(i["publisher"] for i in items)

# ---- Render HTML ----

def tag_html(label, cls=None):
    if cls is None:
        if label.startswith("cloud") or label == "cloud":
            cls = "cloud"
        elif label.startswith("ai") or label == "ai":
            cls = "ai"
        else:
            cls = ""
    return f'<span class="tag {cls}">{esc(label)}</span>'

def fmt_mitre(ttps):
    """Render up to 5 MITRE TTP chips. Each shows tid with name as tooltip."""
    if not ttps:
        return ""
    chips = "".join(
        f'<a class="mitre-chip" href="https://attack.mitre.org/techniques/{esc(tid.replace(".", "/"))}/" target="_blank" title="{esc(name)}">{esc(tid)}</a>'
        for tid, name in ttps[:5]
    )
    return f'<div class="card-mitre"><span class="mitre-label">MITRE</span>{chips}</div>'

def fmt_pubs(pubs):
    if len(pubs) == 1:
        return esc(pubs[0])
    if len(pubs) <= 3:
        return " · ".join(esc(p) for p in pubs)
    return f"{esc(pubs[0])} · {esc(pubs[1])} · +{len(pubs)-2} more"

# Hero stats with comparison vs prior month (we don't have prior month data; show absolute)
today_str = now.strftime("%Y-%m-%d")
window_label = f"Past {window_days} days"

# Executive overview HTML
exec_stats_html = "".join(
    f'''<div class="exec-stat exec-stat-{s["kind"]}">
        <div class="exec-stat-val">{esc(s["value"])}</div>
        <div class="exec-stat-lbl">{esc(s["label"])}</div>
      </div>'''
    for s in exec_stats
)

if lead_story:
    lead_mitre_html = " ".join(
        f'<a class="exec-lead-ttp" href="https://attack.mitre.org/techniques/{esc(tid.replace(".", "/"))}/" target="_blank" title="{esc(tname)}">{esc(tid)}</a>'
        for tid, tname in lead_story["mitre"]
    )
    actor_chip = f'<span class="exec-lead-actor">⚡ {esc(lead_story["actor"])}</span>' if lead_story["actor"] else ""
    lead_block = f'''
    <div class="exec-lead">
      <div class="exec-lead-label">This week's lead</div>
      <a class="exec-lead-title" href="{esc(lead_story["url"])}" target="_blank">{esc(lead_story["title"])}</a>
      <div class="exec-lead-meta">
        {lead_story["pubs"]} source{"s" if lead_story["pubs"] != 1 else ""} · Industry Reach <strong>{lead_story["reach"]}</strong>
        {actor_chip}
        <span class="exec-lead-ttps">{lead_mitre_html}</span>
      </div>
    </div>'''
else:
    lead_block = ""

imperatives_html = "".join(
    f'''<li>
        <span class="exec-imp-label">{esc(imp["label"])}</span>
        <span class="exec-imp-body">{imp["body"]}</span>
      </li>'''
    for imp in imperatives
)

# Cloud Threat Watch cards
def popover_html(item, containment_narrative_map, publishers=None, report_count=None, cluster_items=None, mitre=None):
    """Build inline popover with key points, IOCs, sources, MITRE, and talking points."""
    desc = item.get("description", "")
    iocs = extract_iocs(desc + " " + item["name"])
    kpts = key_points(desc, max_points=3)
    tpts = talking_points(item, containment_narrative_map)
    kpts_html = "".join(f"<li>{esc(p)}</li>" for p in kpts) or "<li class='dim'>No description available.</li>"
    ioc_chunks = []
    if iocs["cves"]:
        ioc_chunks.append("<div class='ioc-group'><span class='ioc-label'>CVEs</span>" +
                          "".join(f"<code>{esc(c)}</code>" for c in iocs["cves"]) + "</div>")
    if iocs["domains"]:
        ioc_chunks.append("<div class='ioc-group'><span class='ioc-label'>Domains</span>" +
                          "".join(f"<code>{esc(d)}</code>" for d in iocs["domains"]) + "</div>")
    if iocs["ips"]:
        ioc_chunks.append("<div class='ioc-group'><span class='ioc-label'>IPs</span>" +
                          "".join(f"<code>{esc(p)}</code>" for p in iocs["ips"]) + "</div>")
    if iocs["hashes"]:
        ioc_chunks.append("<div class='ioc-group'><span class='ioc-label'>Hashes</span>" +
                          "".join(f"<code>{esc(h[:16])}…</code>" for h in iocs["hashes"]) + "</div>")
    ioc_section = "".join(ioc_chunks) or "<div class='dim'>No IOCs extracted from description text.</div>"
    tpts_html = "".join(f"<li>{esc(p)}</li>" for p in tpts)
    # Sources section
    if publishers is None:
        publishers = [item.get("publisher", "Unknown")]
    pubs_unique = list(dict.fromkeys(publishers))
    if report_count is None:
        report_count = len(publishers)
    if len(pubs_unique) != report_count:
        sources_header = f"📰 Sources · {len(pubs_unique)} publisher{'s' if len(pubs_unique)!=1 else ''} across {report_count} report{'s' if report_count!=1 else ''}"
    else:
        sources_header = f"📰 Sources ({len(pubs_unique)})"

    if cluster_items:
        # Show every article as a clickable row, grouped by publisher then by recency
        sorted_items = sorted(cluster_items, key=lambda x: (x["publisher"], -x["created"].timestamp()))
        MAX_LINKS = 8
        shown = sorted_items[:MAX_LINKS]
        more = len(sorted_items) - len(shown)
        article_rows = []
        for s in shown:
            title = s["name"][:90] + ("…" if len(s["name"]) > 90 else "")
            url = s["url"] or "#"
            article_rows.append(
                f'<a class="pop-article" href="{esc(url)}" target="_blank">'
                f'<span class="pop-article-pub">{esc(s["publisher"])}</span>'
                f'<span class="pop-article-title">{esc(title)}</span>'
                f'</a>'
            )
        sources_html = "".join(article_rows)
        if more > 0:
            sources_html += f'<div class="pop-more">+ {more} more report{"s" if more != 1 else ""} in this cluster</div>'
    else:
        # Fallback: publisher pills (no per-article info)
        sources_html = "<div class='pop-sources'>" + "".join(
            f"<span class='pop-source'>{esc(p)}</span>" for p in pubs_unique
        ) + "</div>"

    # MITRE section
    if mitre is None:
        mitre = item.get("mitre", [])
    if mitre:
        mitre_rows = "".join(
            f'<a class="pop-mitre" href="https://attack.mitre.org/techniques/{esc(tid.replace(".", "/"))}/" target="_blank"><code>{esc(tid)}</code><span>{esc(name)}</span></a>'
            for tid, name in mitre[:6]
        )
        mitre_block = f'<div class="pop-section"><h4>🎯 MITRE ATT&CK</h4><div class="pop-mitre-list">{mitre_rows}</div></div>'
    else:
        mitre_block = ""

    return f"""<div class="card-popover">
        <div class="pop-section"><h4>📌 Key points</h4><ul>{kpts_html}</ul></div>
        {mitre_block}
        <div class="pop-section"><h4>🧪 IOCs</h4>{ioc_section}</div>
        <div class="pop-section"><h4>{sources_header}</h4>{sources_html}</div>
        <div class="pop-section"><h4>💬 Talking points</h4><ul>{tpts_html}</ul></div>
      </div>"""

cloud_cards_html = []
CEO_CLOUD_TOP_N = 3
for idx, c in enumerate(TOP_CLOUD):
    lead = c["lead"]
    cluster_pubs = len(c["publishers"])
    cluster_reports = c["size"]
    if cluster_pubs > 1 and cluster_reports > 1:
        pub_badge = f'{cluster_pubs} sources · {cluster_reports} reports'
    elif cluster_reports > 1:
        pub_badge = f'{cluster_reports} reports'
    else:
        pub_badge = fmt_pubs(c["publishers"])
    pub_byline = fmt_pubs(c["publishers"]) if cluster_reports > 1 else esc(lead["publisher"])
    tags_render = "".join(tag_html(l, "cloud") for l in c["cloud_tags"]) + "".join(tag_html(l, "ai") for l in c["ai_tags"])
    data_tags = " ".join(c["cloud_tags"] + c["ai_tags"])
    actor_chip = ""
    if c["tas"]:
        actor_chip = f' <span class="actor-chip">⚡ {esc(c["tas"][0])}</span>'
    url = lead["url"] or "#"
    # Aggregate MITRE TTPs across cluster items, dedupe by tid
    cluster_mitre = []
    seen_tid = set()
    for it in c["items"]:
        for tid, tname in it.get("mitre", []):
            if tid not in seen_tid:
                seen_tid.add(tid)
                cluster_mitre.append((tid, tname))
    mitre_render = fmt_mitre(cluster_mitre)
    pop = popover_html(lead, containment_narrative_map, publishers=c["publishers"], report_count=cluster_reports, cluster_items=c["items"], mitre=cluster_mitre)
    # Cards beyond the top-3 collapse to a single "and N more" hint in the CEO Brief
    # to keep that view scannable. Class-based gating (rather than data-views) so the
    # tag/reach filter logic doesn't fight with the view selector.
    extra_class = "" if idx < CEO_CLOUD_TOP_N else " ceo-hide"
    cloud_cards_html.append(f"""
      <article class="threat-card{extra_class}" data-tags="{esc(data_tags)}" data-reach="{c["reach"]}">
        <div class="card-meta">
          <span class="pub-badge">{esc(pub_badge)}</span>
          <span>{pub_byline}{actor_chip}</span>
        </div>
        <h3 class="card-title"><a href="{esc(url)}" target="_blank">{esc(lead["name"])}</a></h3>
        <div class="card-tags">{tags_render}</div>
        {mitre_render}
        <div class="card-footer">
          <div class="reach-bar">
            <span class="reach-label">Industry Reach</span>
            <div class="reach-meter"><div class="reach-fill" style="width:{c["reach"]}%"></div></div>
            <span class="reach-score">{c["reach"]}</span>
          </div>
          <a class="cta-arrow" href="{esc(url)}" target="_blank">Read →</a>
        </div>
        {pop}
      </article>""")
ceo_overflow_count = max(0, len(TOP_CLOUD) - CEO_CLOUD_TOP_N)
if ceo_overflow_count > 0:
    cloud_cards_html.append(f"""
      <div class="ceo-overflow ceo-only">
        + {ceo_overflow_count} more cluster{'s' if ceo_overflow_count != 1 else ''} in this window —
        switch to <strong>CISO Brief</strong> for the full landscape.
      </div>""")
cloud_cards_section = "\n".join(cloud_cards_html) if cloud_cards_html else '<div class="filter-empty" style="display:block">No cloud-shaped stories in this window.</div>'

# Cloud Threat Watch overview block
def cloud_overview_html(ov):
    if not ov:
        return ""
    themes_html = "".join(
        f'<span class="overview-pill"><span class="overview-pill-name">{esc(name)}</span><span class="overview-pill-count">{cnt}</span></span>'
        for name, cnt in ov["themes"]
    ) or '<span class="dim">no dominant pattern</span>'
    surfaces_html = "".join(
        f'<span class="overview-pill cloud"><span class="overview-pill-name">{esc(s.upper())}</span><span class="overview-pill-count">{c}</span></span>'
        for s, c in ov["surfaces"]
    ) or '<span class="dim">none</span>'
    actors_html = "".join(
        f'<span class="overview-pill actor"><span class="overview-pill-name">{esc(a)}</span><span class="overview-pill-count">{c}</span></span>'
        for a, c in ov["actors"]
    ) or '<span class="dim">no named adversaries</span>'
    sources_html = "".join(
        f'<span class="overview-pill source"><span class="overview-pill-name">{esc(p)}</span><span class="overview-pill-count">{c}</span></span>'
        for p, c in ov["publishers"]
    ) or '<span class="dim">none</span>'
    return f"""
    <div class="overview-block">
      <div class="overview-stats">
        <div class="overview-stat">
          <div class="overview-stat-value">{ov["total_clusters"]}</div>
          <div class="overview-stat-label">active clusters</div>
        </div>
        <div class="overview-stat">
          <div class="overview-stat-value">{ov["total_reports"]}</div>
          <div class="overview-stat-label">reports aggregated</div>
        </div>
        <div class="overview-stat">
          <div class="overview-stat-value">{ov["high_reach"]}<span class="overview-stat-suffix">/{ov["total_clusters"]}</span></div>
          <div class="overview-stat-label">high-reach (≥60)</div>
        </div>
      </div>
      <div class="overview-rows">
        <div class="overview-row">
          <span class="overview-label">Dominant patterns</span>
          <div class="overview-pills">{themes_html}</div>
        </div>
        <div class="overview-row">
          <span class="overview-label">Top cloud surfaces</span>
          <div class="overview-pills">{surfaces_html}</div>
        </div>
        <div class="overview-row">
          <span class="overview-label">Most-active adversaries</span>
          <div class="overview-pills">{actors_html}</div>
        </div>
        <div class="overview-row">
          <span class="overview-label">Reporting sources</span>
          <div class="overview-pills">{sources_html}</div>
        </div>
      </div>
    </div>"""

cloud_overview_section = cloud_overview_html(CLOUD_OVERVIEW)

# Threat Actor Watch
actor_cards_html = []
for ta, total in top_actors_raw:
    status, last7, delta = wow_status(ta)
    best = ta_best_example.get(ta)
    # Only render a WoW delta when there is a comparable prior week — otherwise the
    # number is just ingestion bias, not adversary acceleration.
    if status == "up":
        delta_html = f'<span class="actor-stat-value up">↑{delta}</span>'
    elif status == "down":
        delta_html = f'<span class="actor-stat-value down">↓{abs(delta)}</span>'
    elif status == "flat":
        delta_html = f'<span class="actor-stat-value flat">→</span>'
    else:
        # status == "new" => prev_week == 0 => no baseline to compare against.
        delta_html = ""
    best_title = (best["name"][:75] + "…") if best and len(best["name"]) > 75 else (best["name"] if best else "")
    best_url = best["url"] if best and best["url"] else "#"
    actor_reports = [i for i in items if ta in i["tas"]] if best else []
    actor_pubs = list(dict.fromkeys(i["publisher"] for i in actor_reports))
    # Aggregate MITRE from all reports mentioning this TA
    actor_mitre_seen = set()
    actor_mitre = []
    for it in actor_reports:
        for tid, tname in it.get("mitre", []):
            if tid not in actor_mitre_seen:
                actor_mitre_seen.add(tid)
                actor_mitre.append((tid, tname))
    actor_pop = popover_html(best, containment_narrative_map, publishers=actor_pubs, report_count=len(actor_reports), cluster_items=actor_reports, mitre=actor_mitre) if best else ""
    # Subtitle: top 3 TTPs if any, else recency
    if actor_mitre:
        subtitle = "TTPs: " + " · ".join(t[0] for t in actor_mitre[:3])
    elif best:
        subtitle = f"Last seen: {best['created'].strftime('%Y-%m-%d')}"
    else:
        subtitle = ""
    actor_cards_html.append(f"""
      <div class="actor-card">
        <div class="actor-name">{esc(ta)} {delta_html}</div>
        <div class="actor-aliases">{esc(subtitle)}</div>
        <div class="actor-stats">
          <span class="actor-stat-label">Mentions 30d</span>
          <span class="actor-stat-value">{total}</span>
        </div>
        <div class="actor-stats">
          <span class="actor-stat-label">Last 7d</span>
          <span class="actor-stat-value">{last7}</span>
        </div>
        <div class="actor-best"><a href="{esc(best_url)}" target="_blank">{esc(best_title)}</a></div>
        {actor_pop}
      </div>""")
actor_cards_section = "\n".join(actor_cards_html) if actor_cards_html else "<div>No named actors in this window.</div>"

# Containment Impact rows
containment_html = []
for idx, c in enumerate(TOP_CONTAINMENT, 1):
    it = c["item"]
    url = it["url"] or "#"
    matched_tags = "".join(f'<span class="tag">{esc(m.replace("_", " "))}</span>' for m in c["matched"][:5])
    actor_chip_html = f'<span class="actor-chip">⚡ {esc(it["tas"][0])}</span>' if it["tas"] else ""
    cloud_tags_for_story = sorted(set(l for l in it["all_labels"] if l == "cloud" or l.startswith("cloud-")))[:3]
    story_tags = "".join(tag_html(l, "cloud") for l in cloud_tags_for_story)
    containment_html.append(f"""
      <div class="containment-row">
        <div class="containment-rank">{idx}</div>
        <div class="containment-story">
          <div class="containment-story-pub">{esc(it["publisher"])}</div>
          <div class="containment-story-title"><a href="{esc(url)}" target="_blank">{esc(it["name"])}</a></div>
          <div class="containment-meta-row">{story_tags}{actor_chip_html}</div>
        </div>
        <div class="containment-impact">
          <div class="containment-impact-label">If contained at the network</div>
          <div class="containment-narrative">{esc(c["narrative"])}</div>
          <div class="containment-matched">{matched_tags}</div>
        </div>
      </div>""")
containment_section = "\n".join(containment_html) if containment_html else '<div class="filter-empty" style="display:block">No containment-relevant stories scored above threshold in this window.</div>'

# Industry Trends cards
trends_html = []
for t in TOP_TRENDS:
    last7 = t["last7"]
    prev7 = t["prev7"]
    delta = last7 - prev7
    if prev7 > 0:
        if delta > 0:
            wow_chip = f'<span class="trend-wow up">↑{delta} WoW</span>'
        elif delta < 0:
            wow_chip = f'<span class="trend-wow down">↓{abs(delta)} WoW</span>'
        else:
            wow_chip = f'<span class="trend-wow flat">→ flat</span>'
    else:
        # No comparable prior-week activity yet — don't fabricate a 🆕 delta.
        wow_chip = ""
    examples_html = []
    for ex in t["examples"]:
        url = ex["url"] or "#"
        title = ex["name"][:90] + ("…" if len(ex["name"]) > 90 else "")
        examples_html.append(f"""
          <div class="trend-example">
            <span class="trend-example-pub">{esc(ex["publisher"])}</span><a href="{esc(url)}" target="_blank">{esc(title)}</a>
          </div>""")
    trends_html.append(f"""
      <div class="trend-card">
        <div class="trend-head">
          <span class="trend-icon">{t["icon"]}</span>
          <span class="trend-title">{esc(t["name"])}</span>
          <span class="trend-count"><strong>{t["count"]}</strong> reports{wow_chip}</span>
        </div>
        <div class="trend-narrative">{esc(t["narrative"])}</div>
        <div class="trend-examples">
          <div class="trend-examples-label">Representative reports</div>
          {"".join(examples_html)}
        </div>
      </div>""")
trends_section = "\n".join(trends_html) if trends_html else "<div>No trends crossed threshold.</div>"

# Industry Pulse
pulse_rows_html = []
for it in TOP_PULSE:
    focus_tags = [l for l in it["all_labels"] if l in ("cloud", "ai") or l.startswith("cloud-") or l.startswith("ai-")]
    tags_render = "".join(tag_html(l) for l in focus_tags[:4])
    data_tags = " ".join(focus_tags)
    url = it["url"] or "#"
    pulse_rows_html.append(f"""
      <div class="pulse-row" data-tags="{esc(data_tags)}">
        <span class="pulse-pub">{esc(it["publisher"])}</span>
        <span class="pulse-title"><a href="{esc(url)}" target="_blank">{esc(it["name"])}</a></span>
        <span class="pulse-tags">{tags_render}</span>
        <span class="pulse-conf">conf {it["confidence"]}</span>
      </div>""")
pulse_section = "\n".join(pulse_rows_html)

# Vendor Watch
def vendor_items_html(vendors, panel_class):
    if not vendors:
        return f'<div class="vendor-empty"><div class="quiet">🌙</div><div>No mentions in this window.</div></div>'
    rows = []
    for v, hits in vendors:
        best = max(hits, key=lambda x: (x["confidence"], x["created"]))
        rows.append(f"""
          <div class="vendor-item">
            <span class="vendor-item-name">{esc(v)}</span>
            <span class="vendor-item-meta">{len(hits)} mention{"s" if len(hits) != 1 else ""} · latest: {esc(best["name"][:55])}{"…" if len(best["name"]) > 55 else ""}</span>
          </div>""")
    return f'<div class="vendor-list">{"".join(rows)}</div>'

vendor_t1_html = vendor_items_html(top_t1, "tier-1")
vendor_t2_html = vendor_items_html(top_t2, "tier-2")

# Filter chip counts — count from RENDERED cards/rows only, so chip-N matches visible-N
visible_tag_sets = []
for c in TOP_CLOUD:
    card_tags = set(c["cloud_tags"]) | set(c["ai_tags"])
    visible_tag_sets.append(card_tags)
for it in TOP_PULSE:
    row_tags = set(l for l in it["all_labels"] if l in ("cloud", "ai") or l.startswith("cloud-") or l.startswith("ai-"))
    visible_tag_sets.append(row_tags)

chip_counts = {"all": len(visible_tag_sets)}
ALL_FILTER_TAGS = ["cloud", "cloud-aws", "cloud-azure", "cloud-gcp", "cloud-k8s", "cloud-container",
                   "cloud-saas", "ai", "ai-llm", "ai-agentic", "ai-mcp", "ai-deepfake",
                   "ai-prompt-injection", "ai-data-poisoning"]
for tag in ALL_FILTER_TAGS:
    chip_counts[tag] = sum(1 for tags in visible_tag_sets if tag in tags)

def chip(tag, label, cls=""):
    cnt = chip_counts.get(tag, 0)
    active = ' active' if tag == "all" else ''
    return f'<button class="filter-chip {cls}{active}" data-tag="{tag}">{label}<span class="filter-chip-count">{cnt}</span></button>'

# Reach-range chips (cloud section only)
reach_buckets = [
    ("any",  "any reach",  "any",   len(TOP_CLOUD)),
    ("80+",  "critical",   "80+",   sum(1 for c in TOP_CLOUD if c["reach"] >= 80)),
    ("60",   "high",       "60-79", sum(1 for c in TOP_CLOUD if 60 <= c["reach"] < 80)),
    ("40",   "medium",     "40-59", sum(1 for c in TOP_CLOUD if 40 <= c["reach"] < 60)),
    ("0",    "low",        "<40",   sum(1 for c in TOP_CLOUD if c["reach"] < 40)),
]
def reach_chip(key, label, range_label, cnt):
    active = ' active' if key == "any" else ''
    return f'<button class="filter-chip reach-chip{active}" data-reach="{key}">{label} <span class="filter-chip-range">{range_label}</span><span class="filter-chip-count">{cnt}</span></button>'

reach_chips_html = "".join(reach_chip(*b) for b in reach_buckets)

cloud_chips = [
    chip("cloud", "cloud", "cloud"),
    chip("cloud-aws", "aws", "cloud"),
    chip("cloud-azure", "azure", "cloud"),
    chip("cloud-gcp", "gcp", "cloud"),
    chip("cloud-k8s", "k8s", "cloud"),
    chip("cloud-container", "container", "cloud"),
    chip("cloud-saas", "saas", "cloud"),
]
ai_chips = [
    chip("ai", "ai", "ai"),
    chip("ai-llm", "llm", "ai"),
    chip("ai-agentic", "agentic", "ai"),
    chip("ai-mcp", "mcp", "ai"),
    chip("ai-deepfake", "deepfake", "ai"),
    chip("ai-prompt-injection", "prompt-inj", "ai"),
    chip("ai-data-poisoning", "data-poison", "ai"),
]

# Footer stats
total_publishers_str = ", ".join(p for p, _ in pub_counts.most_common(6))

# ---- Base CSS (self-contained — no dependency on a prior output file) ----
css_block = """
    :root {
      --bg:        #050e1a;
      --bg-card:   #081525;
      --bg-elev:   #0d1e30;
      --border:    rgba(255,255,255,0.08);
      --text:      #e8edf4;
      --text-dim:  #9aafc0;
      --text-fade: #5a7080;
      --accent:    #ff6b35;
      --accent-2:  #ff8c5a;
      --cloud:     #4ad6ff;
      --ai:        #b97cff;
      --good:      #3ee08f;
      --bad:       #ff5e5e;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 16px; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.6;
      min-height: 100vh;
    }
    a { color: inherit; }
    .topbar {
      position: sticky; top: 0; z-index: 500;
      background: rgba(5, 14, 26, 0.92);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 0 28px;
    }
    .topbar-inner {
      max-width: 1280px; margin: 0 auto;
      display: flex; align-items: center;
      height: 52px; gap: 24px;
    }
    .brand {
      display: flex; align-items: center; gap: 10px;
      font-weight: 700; letter-spacing: 0.06em;
      font-size: 13px;
    }
    .brand-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--accent);
      box-shadow: 0 0 8px var(--accent);
      animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.65; transform: scale(0.9); }
    }
    .brand-name { color: var(--text); }
    .brand-product {
      font-weight: 400; color: var(--text-fade); font-size: 12px;
    }
    .brand-sep { color: var(--text-fade); margin: 0 4px; }
    .nav-links {
      display: flex; gap: 4px; align-items: center;
      margin-left: auto;
    }
    .nav-links a {
      font-size: 12px; font-weight: 500;
      color: var(--text-dim);
      text-decoration: none;
      padding: 5px 11px;
      border-radius: 5px;
      transition: all 0.12s;
    }
    .nav-links a:hover { color: var(--text); background: rgba(255,255,255,0.05); }
    .nav-status {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
      display: flex; align-items: center; gap: 4px;
    }
    .status-dot {
      display: inline-block; width: 7px; height: 7px;
      border-radius: 50%; background: var(--good);
      animation: pulse 2s ease-in-out infinite;
    }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 36px 28px 80px; }
    .section {
      margin-bottom: 60px;
      scroll-margin-top: 70px;
    }
    .section-head {
      display: flex; align-items: baseline;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      padding-bottom: 14px;
      margin-bottom: 26px;
      flex-wrap: wrap; gap: 10px;
    }
    .section-head h2 {
      font-size: 20px; font-weight: 700;
      letter-spacing: -0.01em;
    }
    .section-sub {
      font-size: 13px; color: var(--text-dim);
      line-height: 1.55; margin-bottom: 18px;
    }
    .section-meta {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
    }
    .kicker {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.16em;
      color: var(--accent);
      padding: 3px 8px;
      background: rgba(255, 107, 53, 0.1);
      border: 1px solid rgba(255, 107, 53, 0.25);
      border-radius: 4px;
    }
    .count {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
    }

    /* Hero */
    .hero {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 40px;
      align-items: center;
      padding: 40px 0 36px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 48px;
    }
    .hero-headline {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.18em;
      color: var(--accent);
      margin-bottom: 12px;
    }
    .hero-title {
      font-size: 42px; font-weight: 800;
      line-height: 1.1; letter-spacing: -0.02em;
      margin-bottom: 16px;
    }
    .accent { color: var(--accent-2); }
    .hero-sub {
      font-size: 15px; color: var(--text-dim);
      line-height: 1.6; max-width: 560px;
      margin-bottom: 16px;
    }
    .hero-meta {
      display: flex; align-items: center;
      gap: 10px; flex-wrap: wrap;
      font-size: 12px; color: var(--text-fade);
      font-family: 'JetBrains Mono', monospace;
    }
    .dot {
      width: 3px; height: 3px;
      background: var(--text-fade);
      border-radius: 50%;
    }
    .stat-panel {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      min-width: 200px;
    }
    .stat {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 18px;
    }
    .stat.ai { border-color: rgba(185,124,255,0.3); }
    .stat.cloud { border-color: rgba(74,214,255,0.3); }
    .stat-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
      margin-bottom: 6px;
    }
    .stat-value {
      font-size: 32px; font-weight: 800;
      color: var(--text);
      line-height: 1;
    }
    .stat.ai .stat-value { color: var(--ai); }
    .stat.cloud .stat-value { color: var(--cloud); }

    /* Industry Pulse list */
    .pulse-list {
      display: flex; flex-direction: column;
      gap: 0;
    }
    .pulse-row {
      display: grid;
      grid-template-columns: 90px 1fr 90px 60px;
      gap: 14px;
      align-items: baseline;
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      font-size: 13px;
      transition: background 0.1s;
    }
    .pulse-row:first-child {
      border-top: 1px solid var(--border);
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.1em;
      color: var(--text-fade);
    }
    .pulse-row:hover { background: rgba(255,255,255,0.02); }
    .pulse-pub {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
      text-transform: uppercase; letter-spacing: 0.06em;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .pulse-title a {
      color: var(--text); text-decoration: none;
    }
    .pulse-title a:hover { color: var(--accent-2); }
    .pulse-conf {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
      text-align: right;
    }

    /* Filter bar */
    .filter-head {
      display: flex; align-items: center;
      justify-content: space-between;
      width: 100%;
      font-size: 12px; font-weight: 600;
      color: var(--text-dim);
      margin-bottom: 10px;
    }
    .filter-row {
      display: flex; align-items: center;
      flex-wrap: wrap; gap: 8px;
      width: 100%;
    }
    .filter-divider {
      width: 1px; height: 18px;
      background: var(--border); flex-shrink: 0;
    }
    .reset {
      font-size: 11px; color: var(--text-fade);
      cursor: pointer; transition: color 0.12s;
    }
    .reset:hover { color: var(--accent); }

    /* Footer */
    .footer {
      background: var(--bg-elev);
      border-top: 1px solid var(--border);
      padding: 40px 28px;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 32px;
      font-size: 13px; color: var(--text-dim);
      max-width: 1280px; margin: 0 auto;
    }
    .footer h4 {
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
      margin-bottom: 12px;
    }
    .footer ul {
      list-style: none;
      display: flex; flex-direction: column; gap: 6px;
    }
    .footer ul li { font-size: 12px; color: var(--text-dim); }
    .footer-stat {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px; color: var(--text-dim);
      padding: 4px 0;
    }

    /* Cloud Threat Watch grid */
    .cloud-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 18px;
    }
    .threat-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px 24px;
      display: flex; flex-direction: column;
      transition: border-color 0.15s ease;
      cursor: default;
    }
    .threat-card:hover { border-color: rgba(255, 107, 53, 0.45); }
    .card-eyebrow {
      display: flex; align-items: center;
      gap: 8px; margin-bottom: 12px;
    }
    .card-pub {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; color: var(--text-fade);
      text-transform: uppercase; letter-spacing: 0.1em;
      font-weight: 700;
      flex: 1;
    }
    .confidence-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .confidence-dot.high { background: var(--good); }
    .confidence-dot.medium { background: var(--accent); }
    .confidence-dot.low { background: var(--text-fade); }
    .card-title {
      font-size: 15px; font-weight: 700;
      line-height: 1.35; margin-bottom: 12px; flex: 1;
    }
    .card-title a {
      text-decoration: none;
      color: var(--text);
      transition: color 0.12s;
    }
    .card-title a:hover { color: var(--accent-2); }
    .card-tags {
      display: flex; flex-wrap: wrap; gap: 6px;
      margin-bottom: 10px;
    }
    .tag {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 10px;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      border: 1px solid transparent;
    }
    .tag.cloud-tag {
      background: rgba(74, 214, 255, 0.1);
      color: var(--cloud);
      border-color: rgba(74, 214, 255, 0.25);
    }
    .tag.ai-tag {
      background: rgba(185, 124, 255, 0.1);
      color: var(--ai);
      border-color: rgba(185, 124, 255, 0.25);
    }
    .tag.threat-tag {
      background: rgba(255, 107, 53, 0.1);
      color: var(--accent-2);
      border-color: rgba(255, 107, 53, 0.25);
    }
    .tag.neutral-tag {
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-fade);
      border-color: rgba(255, 255, 255, 0.1);
    }
    .card-reach {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; color: var(--text-fade);
      text-transform: uppercase; letter-spacing: 0.08em;
      margin-top: auto;
      padding-top: 12px;
    }
    .card-reach strong { color: var(--text); }

    /* Threat Actor grid */
    .actor-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 16px;
    }
    .actor-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent-2);
      border-radius: 10px;
      padding: 18px 20px;
      cursor: default;
      transition: border-color 0.15s ease;
    }
    .actor-card:hover { border-color: var(--accent); }
    .actor-name {
      font-size: 16px; font-weight: 700;
      margin-bottom: 8px; line-height: 1.25;
    }
    .actor-stat {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
      display: flex; gap: 14px; flex-wrap: wrap;
    }
    .actor-stat strong { color: var(--text); font-weight: 700; }
    .delta-html {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 1px 6px;
      border-radius: 3px;
    }
    .delta-up { background: rgba(255,94,94,0.12); color: var(--bad); }
    .delta-down { background: rgba(62,224,143,0.12); color: var(--good); }
    .delta-flat { color: var(--text-fade); }
    .delta-new {
      background: rgba(185, 124, 255, 0.15);
      color: var(--ai);
      border-radius: 3px;
      padding: 1px 6px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    /* Filter chips */
    .filter-bar {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 28px;
      display: flex; flex-direction: column; gap: 10px;
    }
    .filter-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
    }
    .filter-chip {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      padding: 4px 12px;
      border-radius: 12px;
      background: rgba(255,255,255,0.04);
      color: var(--text-dim);
      border: 1px solid var(--border);
      cursor: pointer;
      transition: all 0.12s;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .filter-chip:hover { color: var(--text); background: rgba(255,255,255,0.08); }
    .filter-chip.active-tag {
      background: rgba(74, 214, 255, 0.15);
      color: var(--cloud);
      border-color: rgba(74, 214, 255, 0.4);
    }
    .filter-chip.active-tag.ai-active {
      background: rgba(185, 124, 255, 0.15);
      color: var(--ai);
      border-color: rgba(185, 124, 255, 0.4);
    }
    .filter-chip.active-tag.actor-active {
      background: rgba(255, 107, 53, 0.15);
      color: var(--accent-2);
      border-color: rgba(255, 107, 53, 0.4);
    }
    .reach-chip {
      background: rgba(62, 224, 143, 0.06);
      color: var(--good);
      border-color: rgba(62, 224, 143, 0.25);
    }
    .reach-chip:hover { background: rgba(62, 224, 143, 0.12); }
    .filter-sep {
      width: 1px; height: 18px;
      background: var(--border); flex-shrink: 0;
    }
    .filter-empty {
      display: none;
      grid-column: 1 / -1;
      padding: 40px;
      text-align: center;
      color: var(--text-fade);
      font-size: 14px;
    }

    /* Archive table */
    .archive-table {
      width: 100%; border-collapse: collapse;
      font-size: 13px;
    }
    .archive-table th {
      text-align: left;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
    }
    .archive-table td {
      padding: 10px 14px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      vertical-align: top;
    }
    .archive-table tr:hover td { background: rgba(255,255,255,0.02); }
    .archive-date {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
      white-space: nowrap;
    }
    .archive-title a {
      color: var(--text);
      text-decoration: none;
    }
    .archive-title a:hover { color: var(--accent-2); }

    /* Vendor watch */
    .vendor-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    .vendor-panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px 24px;
    }
    .vendor-panel h3 {
      font-size: 14px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.1em;
      margin-bottom: 4px;
    }
    .tier-1 h3, h3.tier-1 { color: var(--accent-2); }
    .tier-2 h3, h3.tier-2 { color: var(--ai); }
    .vendor-sub {
      font-size: 12px; color: var(--text-fade);
      margin-bottom: 16px;
    }
    .vendor-list { display: flex; flex-direction: column; gap: 10px; }
    .vendor-item {
      display: flex; align-items: baseline;
      justify-content: space-between;
      padding: 8px 12px;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 7px;
    }
    .vendor-item-name {
      font-weight: 600; font-size: 13px;
    }
    .vendor-item-meta {
      font-size: 11px; color: var(--text-fade);
      font-family: 'JetBrains Mono', monospace;
    }
    .vendor-empty {
      text-align: center; padding: 30px 20px;
      color: var(--text-fade); font-size: 13px;
    }

    /* On your radar */
    .radar-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 20px;
    }
    .radar-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px 24px;
    }
    .radar-icon { font-size: 26px; margin-bottom: 10px; }
    .radar-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--text-fade); margin-bottom: 8px;
    }
    .radar-head {
      font-size: 15px; font-weight: 700;
      margin-bottom: 10px; line-height: 1.3;
    }
    .radar-body {
      font-size: 13px; color: var(--text-dim);
      line-height: 1.6;
    }

    /* Card meta row (publisher + actor chip) */
    .card-meta {
      display: flex; align-items: center;
      justify-content: space-between;
      flex-wrap: wrap; gap: 6px;
      margin-bottom: 10px;
      font-size: 12px; color: var(--text-dim);
    }
    .pub-badge {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.06em;
      color: var(--text-fade);
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 2px 7px;
    }
    /* Card footer with reach bar */
    .card-footer {
      margin-top: auto;
      padding-top: 14px;
      border-top: 1px solid rgba(255,255,255,0.05);
      display: flex; align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .reach-bar {
      display: flex; align-items: center; gap: 8px;
      flex: 1;
    }
    .reach-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; color: var(--text-fade);
      text-transform: uppercase; letter-spacing: 0.08em;
      white-space: nowrap;
    }
    .reach-meter {
      flex: 1; height: 4px;
      background: rgba(255,255,255,0.07);
      border-radius: 2px;
      overflow: hidden;
    }
    .reach-fill {
      height: 100%;
      background: linear-gradient(90deg, var(--good), var(--cloud));
      border-radius: 2px;
    }
    .reach-score {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      color: var(--good);
      min-width: 28px; text-align: right;
    }
    .cta-arrow {
      font-size: 12px; font-weight: 600;
      color: var(--accent-2);
      text-decoration: none;
      white-space: nowrap;
      transition: color 0.12s;
    }
    .cta-arrow:hover { color: var(--accent); }

    /* Actor cards */
    .actor-stats {
      display: flex; align-items: baseline;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .actor-stats:last-of-type { border-bottom: none; }
    .actor-stat-label {
      font-size: 11px; color: var(--text-fade);
    }
    .actor-stat-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px; font-weight: 700;
      color: var(--text);
    }
    .actor-stat-value.down { color: var(--good); }
    .actor-stat-value.up   { color: var(--bad); }
    .actor-aliases {
      font-size: 11px; color: var(--text-fade);
      font-family: 'JetBrains Mono', monospace;
      margin-bottom: 10px; margin-top: 4px;
    }
    .actor-best {
      padding-top: 10px;
      font-size: 12px; color: var(--text-dim);
      line-height: 1.45;
    }
    .actor-best a { color: var(--text-dim); text-decoration: none; }
    .actor-best a:hover { color: var(--accent-2); }

    /* Overview block */
    .overview-stats {
      display: flex; gap: 28px;
      flex-wrap: wrap;
      padding: 18px 0;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .overview-stat { display: flex; flex-direction: column; }
    .overview-stat-value {
      font-size: 28px; font-weight: 800;
      color: var(--cloud); line-height: 1.1;
    }
    .overview-stat-label {
      font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.1em; color: var(--text-fade);
      margin-top: 4px;
    }

    /* exec-stat sub-types */
    .exec-stat-num, .exec-stat-text { padding: 0 22px; }
    .exec-stat-num:first-child, .exec-stat-text:first-child { padding-left: 0; }
    .exec-stat-num:last-child,  .exec-stat-text:last-child  { padding-right: 0; }
    .exec-stat-num + .exec-stat-num, .exec-stat-num + .exec-stat-text,
    .exec-stat-text + .exec-stat-num, .exec-stat-text + .exec-stat-text {
      border-left: 1px solid var(--border);
    }
    .exec-stat-num .exec-stat-val { font-size: 48px; color: var(--good); }
    .exec-stat-text .exec-stat-val { font-size: 20px; color: var(--accent-2); }

    /* filter-chip extras */
    .filter-chip-count {
      font-size: 10px; opacity: 0.7;
      margin-left: 4px;
    }
    .filter-chip-range {
      font-size: 9px; opacity: 0.6;
      margin-left: 4px;
    }

    /* pulse-title */
    .pulse-title { font-size: 13px; color: var(--text); }
    .pulse-title a { color: var(--text); text-decoration: none; }
    .pulse-title a:hover { color: var(--accent-2); }

    /* CEO-only / CEO-hide visibility helpers */
    .ceo-only { display: none; }
    body.view-ceo .ceo-hide { display: none !important; }
    body.view-ceo .ceo-only { display: inline-block; }
    .ceo-overflow {
      grid-column: 1 / -1;
      text-align: center;
      padding: 12px 0 4px;
      font-size: 12px;
      color: var(--text-fade);
      font-family: 'JetBrains Mono', monospace;
    }

    @media (max-width: 900px) {
      .cloud-grid { grid-template-columns: 1fr; }
      .actor-grid  { grid-template-columns: 1fr; }
      .vendor-grid { grid-template-columns: 1fr; }
      .radar-grid  { grid-template-columns: 1fr; }
      .hero { grid-template-columns: 1fr; }
      .stat-panel { grid-template-columns: 1fr 1fr; }
      .wrap { padding: 20px 16px 60px; }
      .footer { grid-template-columns: 1fr 1fr; }
    }
"""
# Replace JS with a richer filter that handles both tag, reach, and view-preset toggling
js_block = """
  (function() {
    const tagChips = document.querySelectorAll('.filter-chip[data-tag]');
    const reachChips = document.querySelectorAll('.filter-chip[data-reach]');
    const filterable = document.querySelectorAll('[data-tags]');
    const cloudCards = document.querySelectorAll('.threat-card[data-reach]');
    const emptyStates = document.querySelectorAll('.filter-empty');
    const resetBtn = document.querySelector('[data-reset]');
    const viewBtns = document.querySelectorAll('.view-btn[data-view]');
    const viewableSections = document.querySelectorAll('[data-views]');

    function applyView(view) {
      // Drive view-scoped CSS (`.ceo-hide` / `.ceo-only`) via a body class so
      // we don't fight with the per-card filter logic for `style.display`.
      document.body.classList.remove('view-full','view-ceo','view-ciso','view-analyst');
      document.body.classList.add('view-' + view);
      viewBtns.forEach(b => b.classList.toggle('active', b.dataset.view === view));
      viewableSections.forEach(sec => {
        const allowed = sec.dataset.views.split(' ');
        sec.style.display = allowed.includes(view) ? '' : 'none';
      });
    }
    viewBtns.forEach(b => b.addEventListener('click', () => applyView(b.dataset.view)));
    // Initialize body class so CSS rules apply on first paint
    document.body.classList.add('view-full');

    let currentTag = 'all';
    let currentReach = 'any';

    function inReachRange(score, key) {
      if (key === 'any') return true;
      if (key === '80+') return score >= 80;
      if (key === '60')  return score >= 60 && score < 80;
      if (key === '40')  return score >= 40 && score < 60;
      if (key === '0')   return score < 40;
      return true;
    }

    function applyFilters() {
      tagChips.forEach(c => c.classList.toggle('active', c.dataset.tag === currentTag));
      reachChips.forEach(c => c.classList.toggle('active', c.dataset.reach === currentReach));

      // Tag filter applies to all items with data-tags
      filterable.forEach(el => {
        const matchTag = currentTag === 'all' || el.dataset.tags.split(' ').includes(currentTag);
        // Reach filter only narrows cloud cards
        let matchReach = true;
        if (el.dataset.reach !== undefined) {
          matchReach = inReachRange(parseInt(el.dataset.reach, 10), currentReach);
        }
        el.style.display = (matchTag && matchReach) ? '' : 'none';
      });

      // Per-section empty states
      const cloudVisible = [...document.querySelectorAll('.cloud-grid .threat-card')]
        .some(el => el.style.display !== 'none');
      const pulseVisible = [...document.querySelectorAll('.pulse-list .pulse-row')]
        .some(el => el.style.display !== 'none');
      emptyStates.forEach(es => {
        if (es.dataset.empty === 'cloud') es.style.display = cloudVisible ? 'none' : 'block';
        if (es.dataset.empty === 'pulse') es.style.display = pulseVisible ? 'none' : 'block';
      });
    }

    tagChips.forEach(c => c.addEventListener('click', () => {
      currentTag = c.dataset.tag;
      applyFilters();
    }));
    reachChips.forEach(c => c.addEventListener('click', () => {
      currentReach = c.dataset.reach;
      applyFilters();
    }));
    if (resetBtn) resetBtn.addEventListener('click', () => {
      currentTag = 'all';
      currentReach = 'any';
      applyFilters();
    });
  })();
"""

# Add styles for actor-chip, containment, trends sections
extra_css = """
    .actor-chip {
      display: inline-block;
      margin-left: 6px;
      padding: 2px 8px;
      background: rgba(255, 107, 53, 0.15);
      color: var(--accent-2);
      border-radius: 10px;
      font-size: 11px;
      font-weight: 600;
      font-family: 'JetBrains Mono', monospace;
      border: 1px solid rgba(255, 107, 53, 0.3);
    }

    /* ---------- containment impact ---------- */
    .containment-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
    }
    .containment-row {
      display: grid;
      grid-template-columns: 60px 1fr 1fr;
      gap: 22px;
      align-items: stretch;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid var(--good);
      border-radius: 12px;
      padding: 20px 24px;
      transition: border-color 0.15s ease;
    }
    .containment-row:hover { border-color: var(--good); }
    .containment-rank {
      font-size: 32px; font-weight: 800;
      color: var(--good);
      font-family: 'JetBrains Mono', monospace;
      display: flex; align-items: center; justify-content: center;
    }
    .containment-story {
      border-right: 1px solid var(--border);
      padding-right: 22px;
    }
    .containment-story-pub {
      font-size: 11px; color: var(--text-fade);
      font-family: 'JetBrains Mono', monospace;
      text-transform: uppercase; letter-spacing: 0.08em;
      margin-bottom: 6px;
    }
    .containment-story-title {
      font-size: 15px; font-weight: 700;
      margin-bottom: 8px; line-height: 1.35;
    }
    .containment-meta-row {
      display: flex; gap: 6px; flex-wrap: wrap;
      align-items: center;
    }
    .containment-impact {
      display: flex; flex-direction: column;
      justify-content: center;
    }
    .containment-impact-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--good);
      margin-bottom: 8px;
      display: flex; align-items: center; gap: 6px;
    }
    .containment-impact-label::before {
      content: "🛡"; font-size: 14px;
    }
    .containment-narrative {
      font-size: 14px; color: var(--text);
      line-height: 1.5; font-weight: 500;
    }
    .containment-matched {
      margin-top: 10px;
      display: flex; gap: 4px; flex-wrap: wrap;
    }
    .containment-matched .tag {
      font-size: 10px;
      background: rgba(62, 224, 143, 0.08);
      color: var(--good);
      border: 1px solid rgba(62, 224, 143, 0.25);
    }

    /* ---------- industry trends ---------- */
    .trends-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 18px;
    }
    .trend-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px 24px;
      transition: border-color 0.15s ease;
      position: relative;
    }
    .trend-card:hover { border-color: var(--ai); }
    .trend-card::before {
      content: ""; position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, var(--ai), var(--cloud));
      border-radius: 12px 12px 0 0;
    }
    .trend-head {
      display: flex; align-items: baseline; gap: 12px;
      margin-bottom: 10px;
    }
    .trend-icon {
      font-size: 24px; line-height: 1;
    }
    .trend-title {
      font-size: 17px; font-weight: 700; flex: 1;
    }
    .trend-count {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px; color: var(--text-fade);
    }
    .trend-count strong {
      color: var(--ai); font-size: 16px; font-weight: 800;
    }
    .trend-wow {
      display: inline-block;
      font-size: 11px; font-weight: 700;
      padding: 2px 7px; border-radius: 3px;
      margin-left: 6px;
      font-family: 'JetBrains Mono', monospace;
    }
    .trend-wow.up { background: rgba(255, 94, 94, 0.12); color: var(--bad); }
    .trend-wow.down { background: rgba(62, 224, 143, 0.12); color: var(--good); }
    .trend-wow.flat { color: var(--text-fade); }
    .trend-narrative {
      font-size: 14px; color: var(--text-dim);
      line-height: 1.55; margin-bottom: 14px;
    }
    .trend-examples {
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }
    .trend-examples-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
      margin-bottom: 8px;
    }
    .trend-example {
      font-size: 13px; line-height: 1.45;
      padding: 4px 0;
      color: var(--text);
    }
    .trend-example a:hover { color: var(--ai); text-decoration: none; }
    .trend-example-pub {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; color: var(--text-fade);
      margin-right: 6px;
      text-transform: uppercase;
    }

    /* ---------- section overview ---------- */
    .overview-block {
      background:
        linear-gradient(135deg, rgba(74, 214, 255, 0.12), rgba(255, 107, 53, 0.06)),
        var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid var(--cloud);
      border-radius: 12px;
      padding: 22px 26px;
      margin-bottom: 24px;
      position: relative;
      z-index: 2;
    }
    .overview-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 18px;
      padding-bottom: 18px;
      margin-bottom: 18px;
      border-bottom: 1px solid var(--border);
    }
    .overview-stat-value {
      font-size: 30px; font-weight: 800;
      color: var(--cloud);
      line-height: 1.1;
    }
    .overview-stat-suffix {
      font-size: 16px; font-weight: 600;
      color: var(--text-fade);
    }
    .overview-stat-label {
      font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.12em; color: var(--text-fade);
      margin-top: 6px;
    }
    .overview-rows {
      display: flex; flex-direction: column; gap: 10px;
    }
    .overview-row {
      display: grid;
      grid-template-columns: 180px 1fr;
      gap: 16px;
      align-items: center;
    }
    .overview-label {
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
    }
    .overview-pills {
      display: flex; gap: 8px; flex-wrap: wrap;
    }
    .overview-pill {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 10px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--border);
      border-radius: 16px;
      font-size: 12px;
    }
    .overview-pill-name {
      font-weight: 600; color: var(--text);
    }
    .overview-pill-count {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
    }
    .overview-pill.cloud {
      background: rgba(74, 214, 255, 0.08);
      border-color: rgba(74, 214, 255, 0.25);
    }
    .overview-pill.cloud .overview-pill-name { color: var(--cloud); }
    .overview-pill.actor {
      background: rgba(255, 107, 53, 0.08);
      border-color: rgba(255, 107, 53, 0.25);
    }
    .overview-pill.actor .overview-pill-name { color: var(--accent-2); }
    .overview-pill.source {
      background: rgba(185, 124, 255, 0.08);
      border-color: rgba(185, 124, 255, 0.25);
    }
    .overview-pill.source .overview-pill-name { color: var(--ai); }

    /* ---------- card popover ---------- */
    .cloud-grid, .actor-grid { position: relative; }
    .threat-card { overflow: visible; z-index: 1; }
    .actor-card  { overflow: visible; position: relative; z-index: 1; }
    .threat-card:hover, .actor-card:hover { z-index: 100; }
    .card-popover {
      position: absolute;
      top: calc(100% + 8px);
      left: -8px; right: -8px;
      background: #0a1428;
      border: 1px solid var(--accent);
      border-radius: 12px;
      padding: 20px 22px;
      box-shadow: 0 16px 50px rgba(0,0,0,0.85), 0 0 0 1px rgba(255, 107, 53, 0.15);
      z-index: 200;
      display: none;
      animation: popfade 0.15s ease;
    }
    @keyframes popfade {
      from { opacity: 0; transform: translateY(-4px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .threat-card:hover .card-popover,
    .actor-card:hover .card-popover { display: block; }
    .pop-section { margin-bottom: 14px; }
    .pop-section:last-child { margin-bottom: 0; }
    .pop-section h4 {
      font-size: 11px; text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--accent); font-weight: 700;
      margin-bottom: 8px;
    }
    .pop-section ul {
      list-style: none; padding: 0; margin: 0;
    }
    .pop-section ul li {
      font-size: 13px; line-height: 1.5;
      color: var(--text-dim);
      padding: 4px 0 4px 14px;
      position: relative;
    }
    .pop-section ul li::before {
      content: "▸"; color: var(--accent);
      position: absolute; left: 0; top: 4px;
      font-size: 11px;
    }
    .pop-section ul li.dim { color: var(--text-fade); font-style: italic; }
    .pop-section ul li.dim::before { content: ""; }
    .ioc-group {
      display: flex; flex-wrap: wrap; align-items: center;
      gap: 6px; margin-bottom: 6px;
    }
    .ioc-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; color: var(--text-fade);
      text-transform: uppercase; letter-spacing: 0.1em;
      margin-right: 4px;
    }
    .ioc-group code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 2px 8px;
      background: rgba(255, 107, 53, 0.08);
      border: 1px solid rgba(255, 107, 53, 0.2);
      color: var(--accent-2);
      border-radius: 4px;
      word-break: break-all;
    }
    .dim { color: var(--text-fade); font-style: italic; font-size: 12px; }
    .pop-sources {
      display: flex; flex-wrap: wrap; gap: 6px;
    }
    .pop-source {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 3px 9px;
      background: rgba(185, 124, 255, 0.08);
      border: 1px solid rgba(185, 124, 255, 0.25);
      color: var(--ai);
      border-radius: 4px;
      font-weight: 600;
    }
    .pop-article {
      display: grid;
      grid-template-columns: 110px 1fr;
      gap: 12px;
      align-items: baseline;
      padding: 8px 12px;
      background: rgba(185, 124, 255, 0.04);
      border: 1px solid rgba(185, 124, 255, 0.15);
      border-radius: 5px;
      font-size: 12px;
      text-decoration: none !important;
      color: var(--text);
      line-height: 1.45;
      margin-bottom: 5px;
      transition: background 0.1s ease, border-color 0.1s ease;
    }
    .pop-article:last-child { margin-bottom: 0; }
    .pop-article:hover {
      background: rgba(185, 124, 255, 0.14);
      border-color: var(--ai);
    }
    .pop-article-pub {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: var(--ai);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .pop-article-title {
      color: var(--text);
      font-weight: 500;
    }
    .pop-article:hover .pop-article-title {
      color: var(--text);
      text-decoration: underline;
    }
    .pop-more {
      font-size: 11px;
      color: var(--text-fade);
      font-style: italic;
      padding: 6px 12px 0;
    }

    /* ---------- MITRE chips ---------- */
    .card-mitre {
      display: flex; flex-wrap: wrap; align-items: center;
      gap: 6px;
      margin-bottom: 12px;
      padding-top: 6px;
    }
    .mitre-label {
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--text-fade);
    }
    .mitre-chip {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      padding: 2px 7px;
      background: rgba(255, 94, 94, 0.08);
      border: 1px solid rgba(255, 94, 94, 0.28);
      color: var(--bad);
      border-radius: 3px;
      text-decoration: none !important;
    }
    .mitre-chip:hover {
      background: rgba(255, 94, 94, 0.18);
      border-color: var(--bad);
    }
    .pop-mitre-list {
      display: flex; flex-direction: column; gap: 4px;
    }
    .pop-mitre {
      display: grid;
      grid-template-columns: 80px 1fr;
      gap: 12px;
      align-items: baseline;
      padding: 4px 8px;
      font-size: 12px;
      text-decoration: none !important;
      border-radius: 4px;
    }
    .pop-mitre code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      color: var(--bad);
      background: rgba(255, 94, 94, 0.08);
      padding: 2px 6px;
      border-radius: 3px;
    }
    .pop-mitre span { color: var(--text); }
    .pop-mitre:hover { background: rgba(255, 94, 94, 0.06); }

    /* ---------- containment value banner ---------- */
    .value-banner {
      background: linear-gradient(135deg, rgba(62, 224, 143, 0.16), rgba(74, 214, 255, 0.10));
      border: 1px solid rgba(62, 224, 143, 0.4);
      border-left: 6px solid var(--good);
      border-radius: 14px;
      padding: 26px 32px;
      margin-bottom: 40px;
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 28px;
      align-items: center;
    }
    .value-stat-num {
      font-size: 64px; font-weight: 800;
      color: var(--good);
      line-height: 1; letter-spacing: -0.02em;
      white-space: nowrap;
    }
    .value-stat-num .pct { font-size: 36px; vertical-align: super; }
    .value-stat-frac {
      font-size: 32px;
      color: rgba(62, 224, 143, 0.55);
      font-weight: 700;
    }
    .value-stat-desc {
      font-size: 18px; font-weight: 600;
      color: var(--text);
      line-height: 1.35;
    }
    .value-stat-detail {
      display: block;
      font-size: 13px; font-weight: 400;
      color: var(--text-dim);
      margin-top: 8px;
      line-height: 1.5;
    }
    .value-stat-detail em {
      color: var(--text-fade);
      font-style: italic;
      font-size: 12px;
    }

    /* ---------- view-scoped visibility ---------- */
    /* `.ceo-hide` collapses non-essential detail in CEO Brief.
       `.ceo-only` reveals CEO-specific affordances (overflow hints, compact counts). */
    .ceo-only { display: none; }
    body.view-ceo .ceo-hide { display: none !important; }
    body.view-ceo .ceo-only { display: inline-block; }
    body.view-ceo .ceo-overflow { display: block; }
    .ceo-overflow {
      grid-column: 1 / -1;
      margin: 12px 0 0;
      padding: 14px 18px;
      background: rgba(255,255,255,0.03);
      border: 1px dashed var(--border);
      border-radius: 8px;
      color: var(--text-dim);
      font-size: 13px;
      text-align: center;
    }
    .ceo-overflow strong { color: var(--text); }

    /* ---------- view selector ---------- */
    .view-bar {
      display: flex; align-items: center; gap: 12px;
      margin: 0 0 24px 0;
      padding: 12px 18px;
      background: var(--bg-elev);
      border: 1px solid var(--border);
      border-radius: 10px;
    }
    .view-label {
      font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.12em; color: var(--text-fade);
      font-weight: 700;
      margin-right: 6px;
    }
    .view-btn {
      font-family: 'Inter', sans-serif;
      font-size: 12px; font-weight: 600;
      padding: 6px 14px;
      border-radius: 6px;
      background: rgba(255,255,255,0.03);
      color: var(--text-dim);
      border: 1px solid var(--border);
      cursor: pointer;
      transition: all 0.12s ease;
    }
    .view-btn:hover { color: var(--text); background: rgba(255,255,255,0.06); }
    .view-btn.active {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }

    /* ---------- industry pulse narrative ---------- */
    .pulse-narrative {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-left: 4px solid var(--ai);
      border-radius: 12px;
      padding: 24px 28px;
      font-size: 15px;
      line-height: 1.7;
      color: var(--text-dim);
    }
    .pulse-narrative strong { color: var(--text); font-weight: 600; }
    .pulse-narrative em {
      color: var(--ai);
      font-style: normal;
      font-weight: 500;
    }
    .pulse-narrative em a:hover { text-decoration: underline; }

    /* ---------- Executive Overview ---------- */
    .exec-overview {
      background:
        linear-gradient(180deg, rgba(255, 107, 53, 0.10) 0%, rgba(10, 20, 40, 0) 50%),
        var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 34px 40px 32px;
      margin-bottom: 48px;
      box-shadow: 0 8px 40px rgba(0, 0, 0, 0.4);
      position: relative;
      overflow: hidden;
    }
    .exec-overview::before {
      content: ""; position: absolute;
      top: 0; left: 0; right: 0; height: 4px;
      background: linear-gradient(90deg, var(--accent), var(--cloud), var(--ai), var(--accent));
    }
    .exec-eyebrow {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 22px;
      flex-wrap: wrap; gap: 10px;
    }
    .exec-eyebrow-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.18em;
      color: var(--accent);
    }
    .exec-eyebrow-meta {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; color: var(--text-fade);
    }
    .exec-thesis {
      font-size: 24px; line-height: 1.45;
      font-weight: 500;
      color: var(--text);
      margin-bottom: 28px;
      letter-spacing: -0.01em;
    }
    .exec-thesis strong {
      color: var(--accent-2);
      font-weight: 700;
    }
    .exec-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0;
      margin-bottom: 28px;
      padding: 22px 0;
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }
    .exec-stat { padding: 0 22px; }
    .exec-stat:first-child { padding-left: 0; }
    .exec-stat:last-child { padding-right: 0; }
    .exec-stat + .exec-stat { border-left: 1px solid var(--border); }
    .exec-stat-val {
      font-weight: 800;
      color: var(--text);
      line-height: 1.1;
      letter-spacing: -0.02em;
      margin-bottom: 8px;
    }
    .exec-stat-num .exec-stat-val {
      font-size: 56px;
      color: var(--good);
    }
    .exec-stat-text .exec-stat-val {
      font-size: 22px;
      color: var(--accent-2);
    }
    .exec-stat-lbl {
      font-size: 12px; color: var(--text-dim);
      line-height: 1.4;
      text-transform: none;
      letter-spacing: 0;
    }

    /* lead story block */
    .exec-lead {
      background: rgba(10, 20, 40, 0.65);
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 10px;
      padding: 20px 24px;
      margin-bottom: 26px;
    }
    .exec-lead-label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.16em;
      color: var(--accent);
      margin-bottom: 10px;
    }
    .exec-lead-title {
      display: block;
      font-size: 22px; font-weight: 700;
      color: var(--text);
      line-height: 1.3;
      margin-bottom: 12px;
      text-decoration: none !important;
    }
    .exec-lead-title:hover { color: var(--accent-2); }
    .exec-lead-meta {
      display: flex; align-items: center; flex-wrap: wrap; gap: 12px;
      font-size: 12px; color: var(--text-dim);
      font-family: 'JetBrains Mono', monospace;
    }
    .exec-lead-meta strong { color: var(--text); font-weight: 700; }
    .exec-lead-actor {
      background: rgba(255, 107, 53, 0.15);
      color: var(--accent-2);
      padding: 3px 10px;
      border-radius: 10px;
      font-size: 11px;
      border: 1px solid rgba(255, 107, 53, 0.3);
    }
    .exec-lead-ttps { display: inline-flex; gap: 4px; }
    .exec-lead-ttp {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; font-weight: 700;
      padding: 2px 6px;
      background: rgba(255, 94, 94, 0.10);
      color: var(--bad);
      border: 1px solid rgba(255, 94, 94, 0.28);
      border-radius: 3px;
      text-decoration: none !important;
    }
    .exec-lead-ttp:hover { background: rgba(255, 94, 94, 0.2); }

    /* imperatives */
    .exec-imperatives { padding-top: 4px; }
    .exec-imp-head {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.16em;
      color: var(--text-fade);
      margin-bottom: 14px;
    }
    .exec-imp-list {
      list-style: none;
      counter-reset: imp;
      padding: 0; margin: 0;
      display: flex; flex-direction: column; gap: 12px;
    }
    .exec-imp-list li {
      counter-increment: imp;
      display: grid;
      grid-template-columns: 32px 160px 1fr;
      gap: 14px;
      align-items: baseline;
      font-size: 14px;
      line-height: 1.55;
    }
    .exec-imp-list li::before {
      content: counter(imp);
      font-family: 'JetBrains Mono', monospace;
      font-size: 20px; font-weight: 800;
      color: var(--accent);
    }
    .exec-imp-label {
      font-size: 11px; font-weight: 700;
      text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--accent-2);
      font-family: 'JetBrains Mono', monospace;
    }
    .exec-imp-body { color: var(--text); }
    .exec-imp-body strong { color: var(--text); font-weight: 700; }
    .exec-imp-body code {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--bad);
      background: rgba(255, 94, 94, 0.08);
      padding: 1px 5px;
      border-radius: 3px;
    }

    @media (max-width: 900px) {
      .exec-stats { grid-template-columns: 1fr; gap: 14px; }
      .exec-stat + .exec-stat { border-left: none; border-top: 1px solid var(--border); padding-top: 14px; padding-left: 0; }
      .exec-imp-list li { grid-template-columns: 1fr; gap: 4px; }
    }

    /* ---------- reach chips ---------- */
    .filter-label-hint {
      font-weight: 500; text-transform: none;
      letter-spacing: 0; color: var(--text-fade);
      margin-left: 4px;
    }
    .reach-chip.active {
      background: var(--good); color: #021624; border-color: var(--good);
    }
    .filter-chip-range {
      font-size: 9px; opacity: 0.6;
      margin-left: 4px;
    }

    @media (max-width: 1024px) {
      .containment-row { grid-template-columns: 40px 1fr; }
      .containment-story { border-right: none; padding-right: 0; }
      .containment-impact { padding-top: 14px; border-top: 1px solid var(--border); grid-column: 2; }
      .trends-grid { grid-template-columns: 1fr; }
      .card-popover { position: static; margin-top: 12px; }
    }
"""
css_block += extra_css

# Build final HTML
generated_at = now.strftime("%Y-%m-%d %H:%M UTC")

OUT = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Threat Watch — {window_label}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>{css_block}</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-dot"></span>
      <span class="brand-name">THREAT INTEL</span>
      <span class="brand-sep">/</span>
      <span class="brand-product">Threat Watch</span>
    </div>
    <nav class="nav-links">
      <a href="#cloud">Cloud</a>
      <a href="#containment">Containment</a>
      <a href="#actors">Actors</a>
      <a href="#pulse">Industry</a>
      <a href="#trends">Trends</a>
      <a href="#vendors">Vendors</a>
    </nav>
    <div class="nav-status">
      <span class="status-dot"></span>
      <span>LIVE · refreshed {esc(generated_at)}</span>
    </div>
  </div>
</div>

<main class="wrap">

  <!-- VIEW SELECTOR -->
  <section class="view-bar" data-views="full ceo ciso analyst">
    <span class="view-label">Preset views</span>
    <button class="view-btn active" data-view="full">Full</button>
    <button class="view-btn" data-view="ceo">CEO Brief</button>
    <button class="view-btn" data-view="ciso">CISO Brief</button>
    <button class="view-btn" data-view="analyst">Analyst Brief</button>
  </section>

  <!-- EXECUTIVE OVERVIEW (replaces old TL;DR) -->
  <section class="exec-overview" data-views="full ceo ciso analyst">
    <div class="exec-eyebrow">
      <span class="exec-eyebrow-tag">Executive Overview</span>
      <span class="exec-eyebrow-meta">{esc(window_label)} · refreshed {esc(generated_at)}</span>
    </div>
    <p class="exec-thesis">{thesis_sentence}</p>
    <div class="exec-stats">{exec_stats_html}</div>
    {lead_block}
    <div class="exec-imperatives">
      <div class="exec-imp-head">On your radar</div>
      <ol class="exec-imp-list">{imperatives_html}</ol>
    </div>
  </section>

  <!-- HERO -->
  <section class="hero" data-views="full ceo ciso analyst">
    <div>
      <div class="hero-headline">Threat Watch · {esc(window_label)}</div>
      <h1 class="hero-title">
        {n_total} reports tracked.<br>
        <span class="accent">{len(top_actors_raw)} named actors</span> in motion.
      </h1>
      <p class="hero-sub">
        Cloud- and AI-relevant threat intelligence aggregated from {n_pubs} publishers
        over the last {window_days} days, enriched with threat-actor, malware, and campaign
        SDOs from OpenCTI.
      </p>
      <div class="hero-meta">
        <span>{len(cloud_subtags)} cloud sub-tags</span><span class="dot"></span>
        <span>{len(ai_subtags)} AI sub-tags</span><span class="dot"></span>
        <span>{sum(ta_counts.values())} actor mentions</span><span class="dot"></span>
        <span>{len(TOP_CLOUD)} active clusters</span>
      </div>
    </div>

    <div class="stat-panel">
      <div class="stat">
        <div class="stat-label">Reports / {window_days}d</div>
        <div class="stat-value">{n_total}</div>
      </div>
      <div class="stat ai">
        <div class="stat-label">AI-relevant</div>
        <div class="stat-value">{n_ai}</div>
      </div>
      <div class="stat cloud">
        <div class="stat-label">Cloud-relevant</div>
        <div class="stat-value">{n_cloud}</div>
      </div>
      <div class="stat">
        <div class="stat-label">Publishers</div>
        <div class="stat-value">{n_pubs}</div>
      </div>
    </div>
  </section>

  <!-- CONTAINMENT VALUE BANNER -->
  <section class="value-banner" data-views="full ceo ciso analyst">
    <div class="value-stat-num">{containment_cluster_count}<span class="value-stat-frac">/{containment_cluster_total}</span></div>
    <div class="value-stat-desc">
      top cloud-threat clusters this month involve attack techniques network-level controls directly address.
      <span class="value-stat-detail">
        {len(containment_matched_items)} of {len(cloud_relevant_items)} cloud-relevant reports score against lateral-movement, supply-chain, identity-reuse, or C2 patterns — the surfaces microsegmentation, egress filtering, and identity-aware policy actively target. <em>Heuristic scoring, not retroactive attribution.</em>
      </span>
    </div>
  </section>

  <!-- FILTER BAR -->
  <section class="filter-bar" data-views="full ciso analyst">
    <div class="filter-head">
      <span>Filter by topic</span>
      <span class="reset" data-reset>reset</span>
    </div>
    <div class="filter-row">
      {chip("all", "all")}
      <div class="filter-divider"></div>
      <span class="filter-label">☁ Cloud</span>
      {"".join(cloud_chips)}
      <div class="filter-divider"></div>
      <span class="filter-label">🤖 AI</span>
      {"".join(ai_chips)}
    </div>
    <div class="filter-row" style="margin-top:10px">
      <span class="filter-label">📊 Reach <span class="filter-label-hint">(cloud cards only)</span></span>
      {reach_chips_html}
    </div>
  </section>

  <!-- CLOUD THREAT WATCH -->
  <section class="section" id="cloud" data-views="full ceo ciso analyst">
    <div class="section-head">
      <span class="kicker">Lead</span>
      <h2>Cloud Threat Watch</h2>
      <span class="count ceo-hide">{len(TOP_CLOUD)} clusters · ranked by Industry Reach</span>
      <span class="count ceo-only">Top {min(CEO_CLOUD_TOP_N, len(TOP_CLOUD))} of {len(TOP_CLOUD)} · ranked by Industry Reach</span>
    </div>
    <p class="section-sub">
      Cloud-shaped incidents from the last {window_days} days, clustered by shared threat
      actor and weighted by publisher reach, sector breadth, and architecture diversity.
    </p>
    {cloud_overview_section}
    <div class="cloud-grid">{cloud_cards_section}
    </div>
    <div class="filter-empty" data-empty="cloud">No Cloud Threat Watch stories match this filter.</div>
  </section>

  <!-- CONTAINMENT IMPACT -->
  <section class="section" id="containment" data-views="full ceo ciso analyst">
    <div class="section-head">
      <span class="kicker">Where We Would Have Mattered</span>
      <h2>Containment Impact</h2>
      <span class="count">{len(TOP_CONTAINMENT)} stories · network controls would have changed the outcome</span>
    </div>
    <p class="section-sub">
      Incidents from the last {window_days} days where network controls —
      microsegmentation, identity-aware egress, cross-cloud policy — would have stopped
      or limited the attack. Use these in briefings and analyst conversations.
    </p>
    <div class="containment-grid">{containment_section}
    </div>
  </section>

  <!-- THREAT ACTOR WATCH -->
  <section class="section" id="actors" data-views="full ciso analyst">
    <div class="section-head">
      <span class="kicker">Adversaries</span>
      <h2>Threat Actor Watch</h2>
      <span class="count">Top {len(top_actors_raw)} by mentions · 30d</span>
    </div>
    <p class="section-sub">
      Named adversaries with detected activity in the last {window_days} days.
      WoW deltas (↑/↓) appear only for actors that had reportable activity in the
      prior week, so we never show a fake "spike" caused by recently-ingested
      historical context.
    </p>
    <div class="actor-grid">{actor_cards_section}
    </div>
  </section>

  <!-- INDUSTRY PULSE — single-paragraph narrative -->
  <section class="section" id="pulse" data-views="full analyst">
    <div class="section-head">
      <span class="kicker">Broader Signal</span>
      <h2>Industry Pulse</h2>
      <span class="count">synthesized from {len(TOP_PULSE)} non-cloud stories</span>
    </div>
    <p class="section-sub">
      A single-paragraph narrative of broader industry signal — context for customer
      and analyst conversations even when stories don't land directly on cloud workloads.
    </p>
    <div class="pulse-narrative">{PULSE_NARRATIVE}</div>
  </section>

  <!-- INDUSTRY TRENDS -->
  <section class="section" id="trends" data-views="full ceo analyst">
    <div class="section-head">
      <span class="kicker">2026 Patterns</span>
      <h2>Industry Trends</h2>
      <span class="count">{len(TOP_TRENDS)} active trends · synthesized across {n_total} reports</span>
    </div>
    <p class="section-sub">
      How the threat landscape is moving in {now.year}. Trends synthesized by clustering
      report titles + threat-actor attribution + tag patterns across the {window_days}-day window.
      WoW deltas (↑/↓) appear once a trend has a comparable prior-week baseline — until then,
      the absolute 30-day count is the honest signal.
    </p>
    <div class="trends-grid">{trends_section}
    </div>
  </section>

  <!-- VENDOR WATCH -->
  <section class="section" id="vendors" data-views="full ciso analyst">
    <div class="section-head">
      <span class="kicker">Customer Stack</span>
      <h2>Vendor Watch</h2>
      <span class="count">{len(top_t1)} Tier 1 / {len(top_t2)} Tier 2 mentions · {window_days}d</span>
    </div>
    <p class="section-sub">
      Vendor mentions across the last {window_days} days.
      Tier 1 = every mention; Tier 2 = breach-shaped events only.
    </p>
    <div class="vendor-grid">
      <div class="vendor-panel">
        <h3 class="tier-1">Tier 1 · top mentions</h3>
        <div class="vendor-sub">High-touch SaaS / IaaS / EDR / SIEM</div>
        {vendor_t1_html}
      </div>
      <div class="vendor-panel">
        <h3 class="tier-2">Tier 2 · top mentions</h3>
        <div class="vendor-sub">DevTools, observability, secrets, infra-as-code</div>
        {vendor_t2_html}
      </div>
    </div>
  </section>

  <!-- ARCHIVE -->
  <section class="section" id="archive" data-views="full">
    <div class="section-head">
      <span class="kicker">Lookback</span>
      <h2>Recent briefings</h2>
    </div>
    <div class="pulse-list">
      <div class="pulse-row">
        <span class="pulse-pub">{esc(generated_at[:10])}</span>
        <span class="pulse-title">This briefing · 30-day rollup ({n_total} reports)</span>
        <span></span>
        <span class="pulse-conf">live</span>
      </div>
    </div>
  </section>

</main>

<footer class="footer">
  <div>
    <h4>Coverage</h4>
    <div class="footer-stat">{n_pubs} feeds</div>
    <div class="footer-stat">{sum(ta_counts.values())} actor mentions</div>
    <div class="footer-stat">{n_cloud} cloud reports</div>
    <div class="footer-stat">{n_ai} AI reports</div>
  </div>
  <div>
    <h4>Sources</h4>
    <ul>{"".join(f"<li>{esc(p)}</li>" for p, _ in pub_counts.most_common(6))}</ul>
  </div>
  <div>
    <h4>Briefing</h4>
    <ul>
      <li>Window: {esc(window_label)}</li>
      <li>Refreshed: {esc(generated_at)}</li>
      <li>Powered by OpenCTI + RSS</li>
    </ul>
  </div>
  <div>
    <h4>Methodology</h4>
    <ul>
      <li>Industry Reach Index (pubs × sectors × architecture diversity)</li>
      <li>Threat-actor merge tracking</li>
      <li>MITRE ATT&CK mapping per story</li>
      <li>Containment-relevance scoring</li>
    </ul>
  </div>
</footer>

<script>{js_block}</script>
</body>
</html>"""

with open(HTML_OUT, "w") as f:
    f.write(OUT)

print(f"Wrote {HTML_OUT} ({len(OUT)} bytes)")
print(f"  Reports: {n_total}  (cloud {n_cloud} / AI {n_ai})")
print(f"  Publishers: {n_pubs}")
print(f"  Cloud clusters: {len(TOP_CLOUD)} (showing {len(TOP_CLOUD)})")
print(f"  Containment Impact: {len(TOP_CONTAINMENT)} stories")
print(f"  Threat actors: {len(top_actors_raw)} cards")
print(f"  Industry pulse: {len(TOP_PULSE)} rows")
print(f"  Industry Trends: {len(TOP_TRENDS)} cards")
for t in TOP_TRENDS:
    print(f"    · {t['name']}: {t['count']} reports (last7={t['last7']}, prev7={t['prev7']})")
print(f"  Vendors: T1={len(top_t1)} T2={len(top_t2)}")
print(f"  Executive overview: thesis + {len(exec_stats)} stats + lead + {len(imperatives)} imperatives")

# ── Structured JSON export (threat-watch-data.json) ──────────────────────────
# Single canonical dataset consumed by digest agents, threat hunter, and any
# downstream tool — avoids every consumer re-querying OpenCTI independently.

def _dt(obj):
    """Serialize datetime → ISO string; leave everything else unchanged."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

seven_d_iso  = (now - timedelta(days=7)).isoformat()
now_iso      = now.isoformat()
cutoff_iso   = cutoff_dt.isoformat()

# last_24h slice — items ingested in the last 24 hours
last_24h_cutoff = now - timedelta(hours=24)
last_24h_items  = [i for i in items if i["created"] >= last_24h_cutoff]
last_24h_cloud  = sum(1 for i in last_24h_items if any(l == "cloud" or l.startswith("cloud-") for l in i["all_labels"]))
last_24h_ai     = sum(1 for i in last_24h_items if any(l == "ai" or l.startswith("ai-") for l in i["all_labels"]))
last_24h_vendor_hits = sorted(set(
    v for i in last_24h_items for v in (i.get("t1_vendors", []) + i.get("t2_vendors", []))
))

tw_data = {
    # ── Meta ────────────────────────────────────────────────────────────────
    "generated_at":  now_iso,
    "window_days":   window_days,
    "cutoff":        cutoff_iso,
    "schema_version": "1.1",

    # ── Summary counts ───────────────────────────────────────────────────────
    "summary": {
        "total_reports": n_total,
        "cloud":         n_cloud,
        "ai":            n_ai,
        "publishers":    n_pubs,
        "threat_actors": len(top_actors_raw),
        "cloud_clusters": len(TOP_CLOUD),
        "containment_pct": containment_pct,
    },

    # ── Executive overview ───────────────────────────────────────────────────
    "executive_overview": {
        "thesis": thesis_sentence,
        "stats": exec_stats,
        "imperatives": [
            {"label": imp["label"], "body": imp["body"]}
            for imp in imperatives
        ],
    },

    # ── Cloud clusters (top 8 by Industry Reach) ────────────────────────────
    "cloud_clusters": [
        {
            "reach_score":  c["reach"],
            "size":         c["size"],
            "cloud_tags":   c["cloud_tags"],
            "ai_tags":      c["ai_tags"],
            "publishers":   c["publishers"],
            "threat_actors": c["tas"],
            "lead": {
                "id":          c["lead"]["id"],
                "name":        c["lead"]["name"],
                "url":         c["lead"].get("url", ""),
                "publisher":   c["lead"]["publisher"],
                "confidence":  c["lead"]["confidence"],
                "created":     c["lead"]["created"],
                "labels":      c["lead"]["all_labels"],
                "description": c["lead"].get("description", ""),
                "source_type": c["lead"].get("source_type", "unknown"),
                "source_reliability": c["lead"].get("source_reliability", "C"),
                "tlp": c["lead"].get("tlp", "TLP:AMBER"),
            },
            "reports": [
                {
                    "id":                   i["id"],
                    "name":                 i["name"],
                    "url":                  i.get("url", ""),
                    "publisher":            i["publisher"],
                    "confidence":           i["confidence"],
                    "created":              i["created"],
                    "intel_published":      i["created"].isoformat(),
                    "labels":               i["all_labels"],
                    "tas":                  i["tas"],
                    "description":          i.get("description", ""),
                    "iocs":                 i.get("iocs", {}),
                    "attack_technique_ids": i.get("attack_technique_ids", []),
                    "mitre_tactics":        i.get("mitre_tactics", []),
                    "source_type":          i.get("source_type", "unknown"),
                    "source_reliability":   i.get("source_reliability", "C"),
                    "tlp":                  i.get("tlp", "TLP:AMBER"),
                    "valid_until":          i.get("valid_until", ""),
                    "revoked":              i.get("revoked", False),
                    "analyst_disposition":  i.get("analyst_disposition", "unreviewed"),
                }
                for i in c["items"]
            ],
        }
        for c in TOP_CLOUD
    ],

    # ── Threat actors (top 8, ≥2 reports) ───────────────────────────────────
    "threat_actors": [
        {
            "name":    ta,
            "count":   count,
            "last7":   ta_last_week.get(ta, 0),
            "prev7":   ta_prev_week.get(ta, 0),
            "wow":     (
                "up"   if ta_last_week.get(ta, 0) > ta_prev_week.get(ta, 0) else
                "down" if ta_last_week.get(ta, 0) < ta_prev_week.get(ta, 0) else
                "flat"
            ),
        }
        for ta, count in top_actors_raw
    ],

    # ── Vendor watch (T1 + T2, top 8 each) ──────────────────────────────────
    "vendor_watch": {
        "tier1": [
            {
                "vendor": v,
                "count":  len(hits),
                "reports": [
                    {"id": i["id"], "name": i["name"], "url": i.get("url",""),
                     "publisher": i["publisher"], "created": i["created"]}
                    for i in hits[:5]
                ],
            }
            for v, hits in top_t1
        ],
        "tier2": [
            {
                "vendor": v,
                "count":  len(hits),
                "reports": [
                    {"id": i["id"], "name": i["name"], "url": i.get("url",""),
                     "publisher": i["publisher"], "created": i["created"]}
                    for i in hits[:5]
                ],
            }
            for v, hits in top_t2
        ],
    },

    # ── Industry trends (top 6 by report count) ──────────────────────────────
    "industry_trends": [
        {
            "name":      t["name"],
            "icon":      t["icon"],
            "count":     t["count"],
            "last7":     t["last7"],
            "prev7":     t["prev7"],
            "narrative": t["narrative"],
            "examples":  [
                {"id": i["id"], "name": i["name"], "url": i.get("url",""),
                 "publisher": i["publisher"], "created": i["created"]}
                for i in t["examples"]
            ],
        }
        for t in TOP_TRENDS
    ],

    # ── Containment impact (top 6 network-control-relevant stories) ──────────
    "containment_impact": [
        {
            "score":     c["score"],
            "matched":   c["matched"],
            "narrative": c["narrative"],
            "report": {
                "id":         c["item"]["id"],
                "name":       c["item"]["name"],
                "url":        c["item"].get("url", ""),
                "publisher":  c["item"]["publisher"],
                "confidence": c["item"]["confidence"],
                "created":    c["item"]["created"],
                "labels":     c["item"]["all_labels"],
                "tas":        c["item"]["tas"],
            },
        }
        for c in TOP_CONTAINMENT
    ],

    # ── Last 24 hours slice (digest-ready) ───────────────────────────────────
    # Agents reading this endpoint get the last_24h block pre-filtered —
    # no need to re-query OpenCTI or apply their own time filter.
    "last_24h": {
        "cutoff":       last_24h_cutoff.isoformat(),
        "count":        len(last_24h_items),
        "cloud_count":  last_24h_cloud,
        "ai_count":     last_24h_ai,
        "vendor_hits":  last_24h_vendor_hits,
        "reports": [
            {
                "id":                   i["id"],
                "name":                 i["name"],
                "url":                  i.get("url", ""),
                "publisher":            i["publisher"],
                "confidence":           i["confidence"],
                "created":              i["created"],
                "intel_published":      i["created"].isoformat(),
                "published":            i.get("published", ""),
                "labels":               i["all_labels"],
                "tas":                  i["tas"],
                "t1_vendors":           i.get("t1_vendors", []),
                "t2_vendors":           i.get("t2_vendors", []),
                "description":          i.get("description", ""),
                "iocs":                 i.get("iocs", {}),
                "attack_technique_ids": i.get("attack_technique_ids", []),
                "mitre_tactics":        i.get("mitre_tactics", []),
                "source_type":          i.get("source_type", "unknown"),
                "source_reliability":   i.get("source_reliability", "C"),
                "tlp":                  i.get("tlp", "TLP:AMBER"),
                "valid_until":          i.get("valid_until", ""),
                "revoked":              i.get("revoked", False),
                "analyst_disposition":  i.get("analyst_disposition", "unreviewed"),
            }
            for i in sorted(last_24h_items, key=lambda x: -x["created"].timestamp())
        ],
    },
}

with open(JSON_OUT, "w") as f:
    json.dump(tw_data, f, default=_dt, indent=2)

print(f"Wrote {JSON_OUT} ({len(tw_data['last_24h']['reports'])} last-24h reports, "
      f"{len(tw_data['cloud_clusters'])} clusters, "
      f"{len(tw_data['threat_actors'])} actors, "
      f"{len(tw_data['vendor_watch']['tier1'])} T1 vendor hits)")
