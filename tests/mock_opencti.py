#!/usr/bin/env python3
"""Minimal OpenCTI GraphQL mock server for pipeline validation.

Returns a realistic set of cloud/AI threat reports matching the exact
schema that sources/opencti.py expects. No external dependencies.

Usage:
  python3 tests/mock_opencti.py [--port 18080]
  export OPENCTI_URL=http://localhost:18080/graphql
  export OPENCTI_TOKEN=mock-token
  python3 run.py --source opencti --build
"""
import json, argparse, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta

now = datetime.now(timezone.utc)


def _ts(hours_ago=0):
    return (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


MOCK_REPORTS = [
    {
        "id": "report--001",
        "name": "APT29 OAuth Device Code Phishing Campaign Targeting Cloud Tenants",
        "description": "APT29 (Cozy Bear) abused OAuth 2.0 device code flow to harvest tokens from Microsoft 365 and Azure AD tenants. C2 infrastructure at 198.51.100.47. CVE-2024-21413 leveraged for initial foothold. SHA256: " + "a" * 64,
        "published": _ts(2),
        "created_at": _ts(2),
        "confidence": 90,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-azure"}],
        "externalReferences": {"edges": [{"node": {"url": "https://www.cisa.gov/apt29-oauth"}}]},
        "objects": {"edges": [{"node": {"name": "APT29"}}, {"node": {"name": "Cozy Bear"}}]},
    },
    {
        "id": "report--002",
        "name": "LockBit 3.0 Exploits Citrix Bleed CVE-2023-4966 in Financial Sector",
        "description": "LockBit 3.0 affiliates exploited CVE-2023-4966 to hijack authenticated sessions without credentials. Ransomware deployed after lateral movement. Domain: update-cdn[.]net observed in C2 traffic.",
        "published": _ts(5),
        "created_at": _ts(5),
        "confidence": 88,
        "objectLabel": [{"value": "cloud"}, {"value": "ransomware"}],
        "externalReferences": {"edges": [{"node": {"url": "https://www.cisa.gov/lockbit-citrix"}}]},
        "objects": {"edges": [{"node": {"name": "LockBit"}}]},
    },
    {
        "id": "report--003",
        "name": "Prompt Injection via Malicious MCP Server Responses in Agentic LLM Pipelines",
        "description": "Researchers demonstrated prompt injection through MCP server tool responses in agentic AI pipelines. AI agents can be redirected to exfiltrate data or invoke unintended tool calls. CVE-2024-99999 assigned. Affects systems using model context protocol.",
        "published": _ts(10),
        "created_at": _ts(10),
        "confidence": 78,
        "objectLabel": [{"value": "ai"}, {"value": "ai-mcp"}, {"value": "ai-prompt-injection"}],
        "externalReferences": {"edges": [{"node": {"url": "https://research.checkpoint.com/mcp-injection"}}]},
        "objects": {"edges": []},
    },
    {
        "id": "report--004",
        "name": "Volt Typhoon Pre-Positions in US Critical Infrastructure via Living-off-the-Land",
        "description": "Volt Typhoon used LOTL techniques including certutil, ntdsutil, and wmic to maintain persistent access in OT-adjacent network segments. No custom malware deployed. Targeting SCADA-adjacent systems across energy and water sectors. IP 192.0.2.77 observed in enumeration activity.",
        "published": _ts(18),
        "created_at": _ts(18),
        "confidence": 91,
        "objectLabel": [{"value": "cloud"}, {"value": "ics-ot"}],
        "externalReferences": {"edges": [{"node": {"url": "https://www.cisa.gov/volt-typhoon"}}]},
        "objects": {"edges": [{"node": {"name": "Volt Typhoon"}}]},
    },
    {
        "id": "report--005",
        "name": "Scattered Spider Targets Okta and Salesforce via MFA Push Bombing",
        "description": "UNC3944 / Scattered Spider conducted MFA push bombing attacks against Okta and Salesforce administrator accounts followed by SIM swapping. IPs 203.0.113.12 and 203.0.113.44 used in phishing infrastructure. Cloud SaaS platforms targeted across tech and retail sectors.",
        "published": _ts(24),
        "created_at": _ts(24),
        "confidence": 85,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-saas"}],
        "externalReferences": {"edges": [{"node": {"url": "https://crowdstrike.com/scattered-spider"}}]},
        "objects": {"edges": [{"node": {"name": "Scattered Spider"}}, {"node": {"name": "UNC3944"}}]},
    },
    {
        "id": "report--006",
        "name": "RansomHub EDRKillShifter Disables Endpoint Security Before Encryption",
        "description": "RansomHub affiliates deploy a custom driver-based EDR disabler before ransomware execution. Hash: " + "b" * 64 + ". AWS S3 buckets used for exfiltration staging. CVE-2024-1234 exploited for driver signing bypass.",
        "published": _ts(30),
        "created_at": _ts(30),
        "confidence": 83,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-aws"}, {"value": "ransomware"}],
        "externalReferences": {"edges": [{"node": {"url": "https://sentinelone.com/ransomhub"}}]},
        "objects": {"edges": [{"node": {"name": "RansomHub"}}]},
    },
    {
        "id": "report--007",
        "name": "GitHub Actions Dependency Confusion Attack via Compromised Workflow Steps",
        "description": "Threat actors compromised multiple GitHub Actions third-party dependencies used in CI/CD pipelines. CVE-2025-30066 enables arbitrary code execution during workflow runs. Attacker domain actions-cdn[.]io used for payload delivery. Affects Kubernetes and container build pipelines.",
        "published": _ts(36),
        "created_at": _ts(36),
        "confidence": 87,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-k8s"}],
        "externalReferences": {"edges": [{"node": {"url": "https://github.blog/supply-chain-actions"}}]},
        "objects": {"edges": []},
    },
    {
        "id": "report--008",
        "name": "Lazarus BlueNoroff Distributes Backdoored npm Packages to Crypto Developers",
        "description": "Lazarus Group BlueNoroff sub-cluster distributed trojanized npm packages targeting blockchain and cryptocurrency developers. Package hxxps://registry.npmjs[.]org/crypt0-utils downloaded over 14,000 times before removal. Supply chain compromise used for credential and key theft.",
        "published": _ts(48),
        "created_at": _ts(48),
        "confidence": 84,
        "objectLabel": [{"value": "cloud"}, {"value": "supply-chain"}],
        "externalReferences": {"edges": [{"node": {"url": "https://mandiant.com/lazarus-npm"}}]},
        "objects": {"edges": [{"node": {"name": "Lazarus"}}, {"node": {"name": "BlueNoroff"}}]},
    },
    {
        "id": "report--009",
        "name": "Kubernetes API Server Exposed via Misconfigured EKS RBAC Allows Container Escape",
        "description": "Multiple cloud-hosted Kubernetes clusters exposed admin API servers due to misconfigured RBAC. Attackers exploited CVE-2022-3294 to deploy cryptomining containers and perform container escape. IP 45.33.32.156 used as C2 beacon endpoint.",
        "published": _ts(60),
        "created_at": _ts(60),
        "confidence": 80,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-k8s"}, {"value": "cloud-container"}],
        "externalReferences": {"edges": [{"node": {"url": "https://wiz.io/k8s-api-exposure"}}]},
        "objects": {"edges": []},
    },
    {
        "id": "report--010",
        "name": "Storm-0558 Forges Azure AD Tokens Using Stolen MSA Consumer Signing Key",
        "description": "Storm-0558 acquired an inactive Microsoft account consumer signing key and used it to forge authentication tokens providing access to OWA and Outlook.com. Attack affected 25 organizations globally. Related to CVE-2023-36884 exploit chain.",
        "published": _ts(72),
        "created_at": _ts(72),
        "confidence": 92,
        "objectLabel": [{"value": "cloud"}, {"value": "cloud-azure"}],
        "externalReferences": {"edges": [{"node": {"url": "https://msrc.microsoft.com/storm0558"}}]},
        "objects": {"edges": [{"node": {"name": "Storm-0558"}}]},
    },
]


def _reports_response(page_size=500, after=None):
    """Return the reports query response. Single page (all fits in one response)."""
    edges = [{"node": r} for r in MOCK_REPORTS]
    return {
        "data": {
            "reports": {
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": None,
                    "globalCount": len(MOCK_REPORTS),
                },
                "edges": edges,
            }
        }
    }


def _published_response():
    edges = [{"node": {"id": r["id"], "published": r["published"]}} for r in MOCK_REPORTS]
    return {
        "data": {
            "reports": {
                "pageInfo": {"hasNextPage": False, "endCursor": None},
                "edges": edges,
            }
        }
    }


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress default access log noise; print a terse line instead
        print(f"  [mock-opencti] {self.command} {self.path} → {args[1] if len(args)>1 else '?'}")

    def do_POST(self):
        if self.path != "/graphql":
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Bad JSON")
            return

        query = payload.get("query", "")
        # Route by query shape: published sidecar query vs main reports query
        if "objectLabel" in query and 'values: ["rss"]' in query:
            response = _published_response()
        else:
            variables = payload.get("variables", {})
            response  = _reports_response(
                page_size=variables.get("first", 500),
                after=variables.get("after"),
            )

        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description="Mock OpenCTI GraphQL server for pipeline validation")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), MockHandler)
    print(f"Mock OpenCTI listening on http://{args.host}:{args.port}/graphql")
    print(f"Serving {len(MOCK_REPORTS)} reports (cloud + AI labels)")
    print("Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
