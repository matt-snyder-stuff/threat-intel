#!/usr/bin/env python3
"""Seed a live OpenCTI instance with the same 10 threat reports used in mock tests.

Waits for OpenCTI to be ready, then creates Labels, ThreatActors, and Reports
via GraphQL mutations.  No external Python dependencies.

Usage:
  python3 tests/seed_opencti.py
  OPENCTI_URL=http://localhost:8080 OPENCTI_TOKEN=demo-api-token-opencti-2024 python3 tests/seed_opencti.py

Defaults match tests/docker-compose.opencti.yml.
"""
import json, os, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta

OPENCTI_URL   = os.environ.get("OPENCTI_URL",   "http://localhost:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "8ac2c1f9-0b3d-4f24-a621-4c9b1f2e5a37")
GRAPHQL       = f"{OPENCTI_URL}/graphql"

now = datetime.now(timezone.utc)


def ts(hours_ago=0):
    return (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


REPORTS = [
    {
        "name":        "APT29 OAuth Device Code Phishing Campaign Targeting Cloud Tenants",
        "description": "APT29 (Cozy Bear) abused OAuth 2.0 device code flow to harvest tokens from Microsoft 365 "
                       "and Azure AD tenants. C2 infrastructure at 198.51.100.47. CVE-2024-21413 leveraged for "
                       "initial foothold. SHA256: " + "a" * 64,
        "published":   ts(2),
        "labels":      ["cloud", "cloud-azure"],
        "confidence":  90,
        "url":         "https://www.cisa.gov/apt29-oauth",
        "actors":      ["APT29", "Cozy Bear"],
    },
    {
        "name":        "LockBit 3.0 Exploits Citrix Bleed CVE-2023-4966 in Financial Sector",
        "description": "LockBit 3.0 affiliates exploited CVE-2023-4966 to hijack authenticated sessions without "
                       "credentials. Ransomware deployed after lateral movement. Domain: update-cdn[.]net observed "
                       "in C2 traffic.",
        "published":   ts(5),
        "labels":      ["cloud", "ransomware"],
        "confidence":  88,
        "url":         "https://www.cisa.gov/lockbit-citrix",
        "actors":      ["LockBit"],
    },
    {
        "name":        "Prompt Injection via Malicious MCP Server Responses in Agentic LLM Pipelines",
        "description": "Researchers demonstrated prompt injection through MCP server tool responses in agentic AI "
                       "pipelines. AI agents can be redirected to exfiltrate data or invoke unintended tool calls. "
                       "CVE-2024-99999 assigned. Affects systems using model context protocol.",
        "published":   ts(10),
        "labels":      ["ai", "ai-mcp", "ai-prompt-injection"],
        "confidence":  78,
        "url":         "https://research.checkpoint.com/mcp-injection",
        "actors":      [],
    },
    {
        "name":        "Volt Typhoon Pre-Positions in US Critical Infrastructure via Living-off-the-Land",
        "description": "Volt Typhoon used LOTL techniques including certutil, ntdsutil, and wmic to maintain "
                       "persistent access in OT-adjacent network segments. No custom malware deployed. Targeting "
                       "SCADA-adjacent systems across energy and water sectors. IP 192.0.2.77 observed in "
                       "enumeration activity.",
        "published":   ts(18),
        "labels":      ["cloud", "ics-ot"],
        "confidence":  91,
        "url":         "https://www.cisa.gov/volt-typhoon",
        "actors":      ["Volt Typhoon"],
    },
    {
        "name":        "Scattered Spider Targets Okta and Salesforce via MFA Push Bombing",
        "description": "UNC3944 / Scattered Spider conducted MFA push bombing attacks against Okta and Salesforce "
                       "administrator accounts followed by SIM swapping. IPs 203.0.113.12 and 203.0.113.44 used "
                       "in phishing infrastructure. Cloud SaaS platforms targeted across tech and retail sectors.",
        "published":   ts(24),
        "labels":      ["cloud", "cloud-saas"],
        "confidence":  85,
        "url":         "https://crowdstrike.com/scattered-spider",
        "actors":      ["Scattered Spider", "UNC3944"],
    },
    {
        "name":        "RansomHub EDRKillShifter Disables Endpoint Security Before Encryption",
        "description": "RansomHub affiliates deploy a custom driver-based EDR disabler before ransomware execution. "
                       "Hash: " + "b" * 64 + ". AWS S3 buckets used for exfiltration staging. "
                       "CVE-2024-1234 exploited for driver signing bypass.",
        "published":   ts(30),
        "labels":      ["cloud", "cloud-aws", "ransomware"],
        "confidence":  83,
        "url":         "https://sentinelone.com/ransomhub",
        "actors":      ["RansomHub"],
    },
    {
        "name":        "GitHub Actions Dependency Confusion Attack via Compromised Workflow Steps",
        "description": "Threat actors compromised multiple GitHub Actions third-party dependencies used in CI/CD "
                       "pipelines. CVE-2025-30066 enables arbitrary code execution during workflow runs. Attacker "
                       "domain actions-cdn[.]io used for payload delivery. Affects Kubernetes and container build "
                       "pipelines.",
        "published":   ts(36),
        "labels":      ["cloud", "cloud-k8s", "supply-chain"],
        "confidence":  87,
        "url":         "https://github.blog/supply-chain-actions",
        "actors":      [],
    },
    {
        "name":        "Lazarus BlueNoroff Distributes Backdoored npm Packages to Crypto Developers",
        "description": "Lazarus Group BlueNoroff sub-cluster distributed trojanized npm packages targeting blockchain "
                       "and cryptocurrency developers. Package hxxps://registry.npmjs[.]org/crypt0-utils downloaded "
                       "over 14,000 times before removal. Supply chain compromise used for credential and key theft.",
        "published":   ts(48),
        "labels":      ["cloud", "supply-chain"],
        "confidence":  84,
        "url":         "https://mandiant.com/lazarus-npm",
        "actors":      ["Lazarus", "BlueNoroff"],
    },
    {
        "name":        "Kubernetes API Server Exposed via Misconfigured EKS RBAC Allows Container Escape",
        "description": "Multiple cloud-hosted Kubernetes clusters exposed admin API servers due to misconfigured "
                       "RBAC. Attackers exploited CVE-2022-3294 to deploy cryptomining containers and perform "
                       "container escape. IP 45.33.32.156 used as C2 beacon endpoint.",
        "published":   ts(60),
        "labels":      ["cloud", "cloud-k8s", "cloud-container"],
        "confidence":  80,
        "url":         "https://wiz.io/k8s-api-exposure",
        "actors":      [],
    },
    {
        "name":        "Storm-0558 Forges Azure AD Tokens Using Stolen MSA Consumer Signing Key",
        "description": "Storm-0558 acquired an inactive Microsoft account consumer signing key and used it to forge "
                       "authentication tokens providing access to OWA and Outlook.com. Attack affected 25 "
                       "organizations globally. Related to CVE-2023-36884 exploit chain.",
        "published":   ts(72),
        "labels":      ["cloud", "cloud-azure"],
        "confidence":  92,
        "url":         "https://msrc.microsoft.com/storm0558",
        "actors":      ["Storm-0558"],
    },
]


def gql(query, variables=None):
    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        GRAPHQL,
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENCTI_TOKEN}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    if "errors" in body:
        raise RuntimeError(f"GraphQL error: {body['errors']}")
    return body.get("data", {})


def wait_for_opencti(timeout=300):
    deadline = time.time() + timeout
    print(f"Waiting for OpenCTI at {OPENCTI_URL} ...")
    while time.time() < deadline:
        try:
            # Probe via GraphQL — simpler than /health which requires auth header
            data = gql("{ about { version } }")
            if data.get("about", {}).get("version"):
                print(f"  OpenCTI {data['about']['version']} is ready.")
                return True
        except Exception:
            pass
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(5)
    print("\nTimed out waiting for OpenCTI.")
    return False


def ensure_label(value):
    """Create a label if it doesn't exist; return its id."""
    data = gql(
        """query CheckLabel($value: String!) {
             label(id: $value) { id value }
           }
        """,
        {"value": value},
    )
    if data.get("label"):
        return data["label"]["id"]
    data = gql(
        """mutation CreateLabel($value: String!, $color: String!) {
             labelAdd(input: { value: $value, color: $color }) { id value }
           }
        """,
        {"value": value, "color": "#aaaaaa"},
    )
    return data["labelAdd"]["id"]


def ensure_threat_actor(name):
    """Return existing or create a ThreatActorGroup with this name."""
    data = gql(
        """query FindActor($filters: FilterGroup) {
             threatActorsGroup(filters: $filters) {
               edges { node { id name } }
             }
           }
        """,
        {
            "filters": {
                "mode": "and",
                "filters": [{"key": "name", "values": [name], "operator": "eq", "mode": "or"}],
                "filterGroups": [],
            }
        },
    )
    edges = data.get("threatActorsGroup", {}).get("edges", [])
    if edges:
        return edges[0]["node"]["id"]
    data = gql(
        """mutation CreateActor($name: String!) {
             threatActorGroupAdd(input: { name: $name }) { id name }
           }
        """,
        {"name": name},
    )
    return data["threatActorGroupAdd"]["id"]


def create_report(report, label_ids, actor_ids):
    """Create the report and attach labels + actors."""
    # Build objectRefs list: all actor IDs
    object_refs = actor_ids[:]
    data = gql(
        """mutation CreateReport(
             $name: String!, $description: String!, $published: DateTime!,
             $confidence: Int, $objectLabel: [String!], $objectRefs: [String!]
           ) {
             reportAdd(input: {
               name: $name,
               description: $description,
               published: $published,
               confidence: $confidence,
               objectLabel: $objectLabel,
               objects: $objectRefs
             }) { id name }
           }
        """,
        {
            "name":        report["name"],
            "description": report["description"],
            "published":   report["published"],
            "confidence":  report["confidence"],
            "objectLabel": list({r["name"] for r in [{"name": l} for l in report["labels"]]}),
            "objectRefs":  object_refs,
        },
    )
    return data["reportAdd"]["id"]


def main():
    if not wait_for_opencti():
        sys.exit(1)

    print(f"\nSeeding {len(REPORTS)} reports into {OPENCTI_URL} ...")

    # Collect all unique labels and actors
    all_labels = sorted({l for r in REPORTS for l in r["labels"]})
    all_actors = sorted({a for r in REPORTS for a in r["actors"]})

    print(f"\nEnsuring {len(all_labels)} labels ...")
    label_map = {}
    for lbl in all_labels:
        label_map[lbl] = ensure_label(lbl)
        print(f"  label '{lbl}' → {label_map[lbl]}")

    print(f"\nEnsuring {len(all_actors)} threat actors ...")
    actor_map = {}
    for actor in all_actors:
        actor_map[actor] = ensure_threat_actor(actor)
        print(f"  actor '{actor}' → {actor_map[actor]}")

    print(f"\nCreating reports ...")
    for i, report in enumerate(REPORTS, 1):
        actor_ids = [actor_map[a] for a in report["actors"]]
        rid = create_report(
            report,
            [label_map[l] for l in report["labels"]],
            actor_ids,
        )
        print(f"  [{i:02d}/{len(REPORTS)}] {report['name'][:70]} → {rid}")

    print(f"\nDone. Open {OPENCTI_URL} and log in with:")
    print("  Email:    admin@opencti.io")
    print("  Password: ChangeMe1234!")
    print(f"\nNavigate to: {OPENCTI_URL}/dashboard/analyses/reports")


if __name__ == "__main__":
    main()
