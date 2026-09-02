"""Curated default RSS/Atom feed list for the threat intel pipeline.

Used by sources/rss.py when RSS_FEEDS env var is not set.

Imported as:
    from sources.feeds import DEFAULT_FEEDS, FEED_CATEGORIES
"""

# ── Government / CERT ─────────────────────────────────────────────────────────
_GOVT = [
    # CISA — all advisories (ICS, alerts, analysis reports)
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    # CISA news
    "https://www.cisa.gov/news.xml",
    # NCSC (UK) alerts & advisories
    "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    # NVD legacy RSS was retired in 2023; NVD 2.0 API (JSON only) requires a dedicated source module
    # CISA advisories above already cover critical CVEs via the all.xml feed
]

# ── Threat Intel Vendors ──────────────────────────────────────────────────────
_VENDORS = [
    # Palo Alto Networks Unit 42
    "https://unit42.paloaltonetworks.com/feed/",
    # Mandiant (Google Cloud)
    "https://www.mandiant.com/resources/blog/rss.xml",
    # CrowdStrike blog
    "https://www.crowdstrike.com/blog/feed/",
    # Recorded Future — Insikt Group
    "https://www.recordedfuture.com/feed",
    # Kaspersky Securelist
    "https://securelist.com/feed/",
    # Rapid7 blog
    "https://www.rapid7.com/blog/rss.xml",
    # Tenable (Research & blog)
    "https://www.tenable.com/blog/feed",
    # SentinelOne Labs (primary research feed)
    "https://www.sentinelone.com/labs/feed/",
    # Cisco Talos
    "https://feeds.feedburner.com/feedburner/Talos",
    # Bitdefender Labs
    "https://www.bitdefender.com/nuxt/api/en-us/rss/labs/",
    # VirusTotal Blog
    "https://blog.virustotal.com/feeds/posts/default",
    # SOC Prime Blog
    "https://socprime.com/blog/feed/",
    # Trend Micro research
    "https://feeds.trendmicro.com/Anti-MalwareBlog",
    # The DFIR Report (hands-on incident investigations)
    "https://feeds.feedburner.com/TheDfirReport",
    # Malware Traffic Analysis (PCAP-backed malware reports)
    "https://www.malware-traffic-analysis.net/blog-entries.rss",
]

# ── Security News ─────────────────────────────────────────────────────────────
_NEWS = [
    # The Hacker News
    "https://feeds.feedburner.com/TheHackersNews",
    # BleepingComputer
    "https://bleepingcomputer.com/feed/",
    # Krebs on Security
    "https://krebsonsecurity.com/feed/",
    # The Record (Recorded Future News)
    "https://therecord.media/feed/",
    # Dark Reading
    "https://www.darkreading.com/rss.xml",
    # SecurityWeek
    "https://feeds.feedburner.com/Securityweek",
    # CyberScoop
    "https://cyberscoop.com/feed/",
    # Wired — Security section
    "https://www.wired.com/feed/category/security/latest/rss",
    # Ars Technica — Security section
    "https://feeds.arstechnica.com/arstechnica/security",
    # Infosecurity Magazine
    "https://www.infosecurity-magazine.com/rss/news/",
    # Help Net Security
    "https://www.helpnetsecurity.com/feed/",
]

# ── Cloud / AI Security ───────────────────────────────────────────────────────
_CLOUD_AI = [
    # Wiz Cloud Threat Landscape (confirmed working feed)
    "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml",
    # AWS Security Blog
    "https://aws.amazon.com/blogs/security/feed/",
    # Google Cloud Security Blog (Atom)
    "https://cloud.google.com/feeds/security-bulletins.xml",
    # Google Project Zero
    "https://googleprojectzero.blogspot.com/feeds/posts/default",
    # Microsoft Security Response Center
    "https://msrc.microsoft.com/blog/feed",
    # Cloudflare Blog — security category
    "https://blog.cloudflare.com/tag/security/rss/",
    # Snyk security research
    "https://snyk.io/blog/feed/",
    # Trail of Bits
    "https://blog.trailofbits.com/feed/",
    # Socket.dev blog (supply-chain / npm security) — no confirmed feed URL
    # "https://socket.dev/blog/rss.xml",
    # Datadog Security Labs — no confirmed public feed
    # "https://securitylabs.datadoghq.com/feed/",
]

# ── Vulnerability Feeds ───────────────────────────────────────────────────────
_VULN = [
    # GitHub Security Advisories (GHSA) — Atom feed
    "https://github.com/advisories.atom",
    # Exploit-DB (known exploited) — RSS
    "https://www.exploit-db.com/rss.xml",
    # Packet Storm Security latest advisories
    "https://rss.packetstormsecurity.com/files/tags/advisory/",
]

# ── ISAC / Community ──────────────────────────────────────────────────────────
_ISAC = [
    # SANS Internet Storm Center (full feed with diary entries)
    "https://isc.sans.edu/rssfeed_full.xml",
    # Threatpost (community/news) — kept for broad coverage
    "https://threatpost.com/feed/",
]

# ── Public aggregates ─────────────────────────────────────────────────────────
FEED_CATEGORIES = {
    "government_cert":       _GOVT,
    "threat_intel_vendors":  _VENDORS,
    "security_news":         _NEWS,
    "cloud_ai_security":     _CLOUD_AI,
    "vulnerability_feeds":   _VULN,
    "isac_community":        _ISAC,
}

# Small first-run set. These span government, vendor, news, and cloud reporting
# without making a new user wait on every feed in the full catalog.
STARTER_FEEDS: list[str] = [
    _GOVT[0],
    _VENDORS[0],
    _NEWS[1],
    _CLOUD_AI[1],
]

# Full catalog — select with RSS_FEED_SET=full.
DEFAULT_FEEDS: list[str] = (
    _GOVT
    + _VENDORS
    + _NEWS
    + _CLOUD_AI
    + _VULN
    + _ISAC
)
