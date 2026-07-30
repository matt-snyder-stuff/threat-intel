from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
import time
from pathlib import Path

import pdfplumber


ROOT = Path(__file__).resolve().parent
INPUTS = ROOT / "inputs"
OUT = ROOT / "outputs"


IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9][a-z0-9-]{0,62}(?:\.|\[\.\]))+[a-z]{2,}\b", re.I)


SOURCES = [
    {
        "id": "aa26_097a",
        "source": "CISA AA26-097A",
        "title": "Iranian-affiliated actors exploit PLCs",
        "actor": "CyberAv3ngers / Iranian-affiliated actors",
        "input": INPUTS / "aa26-097a-cyberav3ngers-sample.txt",
        "telemetry": ["Network_Traffic", "Endpoint", "OT asset inventory"],
        "ports": [44818, 2222, 502, 22],
        "focus": "OT/PLC",
    },
    {
        "id": "ic3_260702",
        "source": "FBI IC3 FLASH 260702",
        "title": "TeamPCP software supply-chain compromise",
        "actor": "TeamPCP",
        "input": INPUTS / "260702-teampcp.pdf",
        "telemetry": ["Endpoint", "DNS", "Proxy", "CI/CD", "Package manager"],
        "ports": [443],
        "focus": "CI/CD",
    },
]


def read_input(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        chunks: list[str] = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                chunks.append(page.extract_text() or "")
        return "\n".join(chunks)
    return path.read_text()


def normalize_domain(value: str) -> str:
    return value.lower().replace("[.]", ".")


def extract_iocs(text: str) -> dict[str, list[str]]:
    ignored_domain_suffixes = ("fbi.gov", "ic3.gov", "paloaltonetworks.com")
    ignored_domain_tlds = {"tgz"}
    ips = sorted(set(IP_RE.findall(text)))
    domains = sorted(
        {
            domain
            for domain in (normalize_domain(x) for x in DOMAIN_RE.findall(text))
            if not domain.endswith(ignored_domain_suffixes)
            and domain.rsplit(".", 1)[-1] not in ignored_domain_tlds
        }
    )
    sha256 = sorted({x.lower() for x in SHA256_RE.findall(text)})
    sha1 = sorted({x.lower() for x in SHA1_RE.findall(text)} - set(sha256))
    md5 = sorted({x.lower() for x in MD5_RE.findall(text)} - set(sha256) - set(sha1))
    cves = sorted({x.upper() for x in CVE_RE.findall(text)})
    repos = sorted(set(re.findall(r"\b(?:tpcp-docs|docs-tpcp|Exfil-Repo)\b", text, re.I)))
    return {
        "ip": ips,
        "domain": domains,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "cve": cves,
        "repo": repos,
    }


def make_key(*parts: str) -> str:
    raw = "|".join(parts).encode()
    return hashlib.sha1(raw).hexdigest()[:16]


def build_intel() -> tuple[list[dict], list[dict]]:
    advisories = []
    ioc_rows = []
    generated_at = datetime.now(timezone.utc).isoformat()
    for spec in SOURCES:
        text = read_input(spec["input"])
        iocs = extract_iocs(text)
        counts = {k: len(v) for k, v in iocs.items() if v}
        advisories.append(
            {
                "id": spec["id"],
                "source": spec["source"],
                "title": spec["title"],
                "actor": spec["actor"],
                "focus": spec["focus"],
                "telemetry": spec["telemetry"],
                "ports": spec["ports"],
                "ioc_counts": counts,
                "iocs": iocs,
                "detection_objective": detection_objective(spec),
                "generated_at": generated_at,
            }
        )
        for ioc_type, values in iocs.items():
            for value in values:
                ioc_rows.append(
                    {
                        "_key": make_key(spec["id"], ioc_type, value),
                        "source_id": spec["id"],
                        "source": spec["source"],
                        "actor": spec["actor"],
                        "focus": spec["focus"],
                        "type": ioc_type,
                        "value": value,
                        "confidence": 90 if spec["source"].startswith("CISA") or spec["source"].startswith("FBI") else 75,
                        "first_seen": generated_at,
                    }
                )
    return advisories, ioc_rows


def detection_objective(spec: dict) -> str:
    if spec["id"] == "aa26_097a":
        return "Find suspicious external access to PLC networks and OT management ports, enriched with IOC and asset context."
    return "Find CI runners or developer hosts that install suspicious packages, connect to advisory infrastructure, and touch secrets."


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if not rows:
        path.write_text("")
        return
    names = fieldnames or list(rows[0].keys())
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=names, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def make_seed_events(advisories: list[dict], ioc_rows: list[dict]) -> list[dict]:
    by_source_type = defaultdict(list)
    for row in ioc_rows:
        by_source_type[(row["source_id"], row["type"])].append(row["value"])

    cyber_ips = by_source_type[("aa26_097a", "ip")]
    cyber_hashes = by_source_type[("aa26_097a", "sha256")] + by_source_type[("aa26_097a", "md5")] + by_source_type[("aa26_097a", "sha1")]
    team_ips = by_source_type[("ic3_260702", "ip")]
    team_domains = by_source_type[("ic3_260702", "domain")]
    team_hashes = by_source_type[("ic3_260702", "sha256")]

    def preferred(values: list[str], target: str) -> str:
        return target if target in values else values[0]

    team_dns_domain = preferred(team_domains, "scan.aquasecurtiy.org")
    team_payload_domain = preferred(team_domains, "checkmarx.zone")

    events = [
        {
            "sourcetype": "demo:network",
            "source": "firewall",
            "event": {
                "src_ip": cyber_ips[0],
                "dest_ip": "10.42.7.21",
                "dest_port": 44818,
                "action": "allowed",
                "zone": "ot",
                "asset_type": "PLC",
                "ioc": cyber_ips[0],
                "demo_case": "CyberAv3ngers",
            },
        },
        {
            "sourcetype": "demo:network",
            "source": "firewall",
            "event": {
                "src_ip": cyber_ips[1],
                "dest_ip": "10.42.7.21",
                "dest_port": 502,
                "action": "blocked",
                "zone": "ot",
                "asset_type": "PLC",
                "ioc": cyber_ips[1],
                "demo_case": "CyberAv3ngers",
            },
        },
        {
            "sourcetype": "demo:endpoint",
            "source": "edr",
            "event": {
                "host": "eng-ws-07",
                "dest_ip": "10.42.7.21",
                "file_hash": cyber_hashes[0],
                "process_name": "plc_project_loader.exe",
                "asset_type": "engineering_workstation",
                "ioc": cyber_hashes[0],
                "demo_case": "CyberAv3ngers",
            },
        },
        {
            "sourcetype": "demo:dns",
                "source": "dns",
                "event": {
                    "host": "ci-runner-03",
                    "query": team_dns_domain,
                    "answer": team_ips[0],
                    "ioc": team_dns_domain,
                    "demo_case": "TeamPCP",
                },
            },
        {
            "sourcetype": "demo:proxy",
            "source": "proxy",
                "event": {
                    "host": "ci-runner-03",
                    "dest_ip": team_ips[1],
                    "url": f"https://{team_payload_domain}/static/checkmarx-util-1.0.4.tgz",
                    "http_method": "GET",
                    "ioc": team_ips[1],
                    "demo_case": "TeamPCP",
            },
        },
        {
            "sourcetype": "demo:cicd",
            "source": "github_actions",
            "event": {
                "host": "ci-runner-03",
                "repo": "payments-api",
                    "package": "litellm",
                    "package_version": "compromised-demo",
                    "secret_accessed": "AWS_ACCESS_KEY_ID",
                    "outbound_domain": team_payload_domain,
                    "repo_created": "tpcp-docs",
                    "ioc": team_payload_domain,
                    "demo_case": "TeamPCP",
                },
            },
        {
            "sourcetype": "demo:endpoint",
            "source": "edr",
            "event": {
                "host": "ci-runner-03",
                "file_hash": team_hashes[0],
                "process_name": "python",
                "parent_process": "pip",
                "ioc": team_hashes[0],
                "demo_case": "TeamPCP",
            },
        },
        {
            "sourcetype": "demo:network",
            "source": "firewall",
            "event": {
                "src_ip": "203.0.113.10",
                "dest_ip": "10.42.7.21",
                "dest_port": 443,
                "action": "allowed",
                "zone": "it",
                "asset_type": "web",
                "demo_case": "benign_background",
            },
        },
    ]

    now = time.time()
    out = []
    for item in events:
        event = {"time": now, "index": "demo_threat", **item}
        out.append(event)
    return out


def make_spl(advisories: list[dict]) -> dict[str, str]:
    return {
        "01_ioc_starter.spl": """index=demo_threat sourcetype=demo:* ioc=*
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type confidence
| where isnotnull(intel_source)
| stats count values(sourcetype) as sourcetypes values(type) as ioc_types values(confidence) as confidence by demo_case actor intel_source ioc
| sort -count""",
        "02_cyberav3ngers_plc_behavior.spl": """index=demo_threat (sourcetype=demo:network OR sourcetype=demo:endpoint)
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type as ioc_type confidence
| lookup ot_assets.csv dest_ip OUTPUT asset_type owner zone
| eval plc_port=if(dest_port IN (44818,2222,502,22),1,0)
| where demo_case="CyberAv3ngers" OR plc_port=1 OR asset_type="PLC"
| fillnull value="-" src_ip dest_ip host asset_type owner zone intel_source actor
| stats count max(plc_port) as plc_port values(dest_port) as dest_ports values(ioc_type) as ioc_types values(process_name) as processes by src_ip dest_ip host asset_type owner zone intel_source actor
| eval risk_score=case(intel_source!="-",90, asset_type="PLC" AND plc_port=1,70, asset_type="PLC",40, true(),30)
| sort -risk_score""",
        "03_teampcp_cicd_behavior.spl": """index=demo_threat (sourcetype=demo:cicd OR sourcetype=demo:dns OR sourcetype=demo:proxy OR sourcetype=demo:endpoint)
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type as ioc_type confidence
| lookup cicd_assets.csv host OUTPUT team asset_role
| eval secret_touch=if(isnotnull(secret_accessed) OR like(_raw,"%AWS_ACCESS_KEY_ID%"),1,0)
| eval package_activity=if(isnotnull(package) OR like(url,"%checkmarx-util%"),1,0)
| where demo_case="TeamPCP" OR secret_touch=1 OR package_activity=1
| fillnull value="-" host team asset_role intel_source actor
| stats count max(secret_touch) as secret_touch max(package_activity) as package_activity values(ioc_type) as ioc_types values(query) as dns values(url) as urls values(package) as packages values(secret_accessed) as secrets values(repo_created) as repo_created by host team asset_role intel_source actor
| eval risk_score=case(intel_source!="-" AND secret_touch=1,95, intel_source!="-" AND package_activity=1,85, true(),50)
| sort -risk_score""",
        "04_kv_store_check.spl": """| inputlookup threat_iocs.csv
| stats count by source actor type
| sort source type""",
        "05_telemetry_readiness.spl": """| inputlookup telemetry_readiness.csv
| eval status=case(readiness="ready","OK",readiness="missing","GAP",true(),"CHECK")
| table status detection data_source sourcetype required_fields events_seen confidence_impact analyst_note
| sort status detection""",
        "06_detection_confidence.spl": """| inputlookup telemetry_readiness.csv
| eval search_outcome=if(events_seen>0,"evidence available","zero hits are inconclusive")
| eval confidence_score=case(readiness="ready" AND match(detection,"TeamPCP"),88,readiness="ready",82,true(),35)
| eval confidence_band=case(confidence_score>=85,"high",confidence_score>=60,"medium",true(),"low")
| eval review_decision=case(readiness="missing","do not close; fix telemetry",confidence_score>=85,"promote to notable draft",true(),"analyst review")
| table detection search_outcome readiness events_seen confidence_score confidence_band analyst_note review_decision
| sort -confidence_score""",
    }


def write_splunk_artifacts(advisories: list[dict], ioc_rows: list[dict], events: list[dict]) -> None:
    lookup_rows = [
        {k: row[k] for k in ["source_id", "source", "actor", "focus", "type", "value", "confidence", "first_seen"]}
        for row in ioc_rows
    ]
    write_csv(OUT / "threat_iocs.csv", lookup_rows)
    write_csv(
        OUT / "ot_assets.csv",
        [
            {"dest_ip": "10.42.7.21", "asset_type": "PLC", "owner": "water-ops", "zone": "ot"},
            {"dest_ip": "10.42.7.22", "asset_type": "HMI", "owner": "water-ops", "zone": "ot"},
        ],
    )
    write_csv(
        OUT / "cicd_assets.csv",
        [
            {"host": "ci-runner-03", "team": "platform-engineering", "asset_role": "github_actions_runner"},
            {"host": "dev-mac-14", "team": "appsec", "asset_role": "developer_workstation"},
        ],
    )
    write_csv(
        OUT / "telemetry_readiness.csv",
        [
            {
                "detection": "CyberAv3ngers OT access",
                "data_source": "Firewall / network",
                "sourcetype": "demo:network",
                "required_fields": "src_ip,dest_ip,dest_port,action",
                "events_seen": 3,
                "readiness": "ready",
                "confidence_impact": "+35",
                "analyst_note": "Can validate external access to PLC management ports.",
            },
            {
                "detection": "CyberAv3ngers loader hash",
                "data_source": "EDR",
                "sourcetype": "demo:endpoint",
                "required_fields": "host,file_hash,process_name",
                "events_seen": 2,
                "readiness": "ready",
                "confidence_impact": "+25",
                "analyst_note": "Can corroborate network activity with endpoint evidence.",
            },
            {
                "detection": "TeamPCP package staging",
                "data_source": "DNS / proxy",
                "sourcetype": "demo:dns,demo:proxy",
                "required_fields": "host,query,url,dest_ip",
                "events_seen": 2,
                "readiness": "ready",
                "confidence_impact": "+30",
                "analyst_note": "Can connect runner activity to advisory infrastructure.",
            },
            {
                "detection": "TeamPCP secret access",
                "data_source": "CI/CD logs",
                "sourcetype": "demo:cicd",
                "required_fields": "host,package,secret_accessed,repo_created",
                "events_seen": 1,
                "readiness": "ready",
                "confidence_impact": "+30",
                "analyst_note": "Can distinguish package install from pipeline impact.",
            },
            {
                "detection": "Kubernetes token exfiltration",
                "data_source": "Kubernetes audit",
                "sourcetype": "demo:kubernetes",
                "required_fields": "user,verb,resource,secret_name",
                "events_seen": 0,
                "readiness": "missing",
                "confidence_impact": "-45",
                "analyst_note": "Zero results are inconclusive because audit telemetry is absent.",
            },
            {
                "detection": "Cloud credential abuse",
                "data_source": "CloudTrail / cloud control plane",
                "sourcetype": "demo:cloudtrail",
                "required_fields": "user,eventName,sourceIPAddress,errorCode",
                "events_seen": 0,
                "readiness": "missing",
                "confidence_impact": "-40",
                "analyst_note": "Cannot prove or disprove cloud abuse without control-plane logs.",
            },
        ],
    )
    write_csv(
        OUT / "confidence_scores.csv",
        [
            {
                "detection_name": "IOC starter search",
                "search_outcome": "hit",
                "evidence_summary": "7 direct IOC matches across network, DNS, proxy, endpoint, and CI/CD",
                "data_readiness": "high",
                "confidence_score": 90,
                "review_decision": "analyst review",
            },
            {
                "detection_name": "CyberAv3ngers OT behavior",
                "search_outcome": "hit",
                "evidence_summary": "PLC asset + advisory IP/hash + OT ports",
                "data_readiness": "high",
                "confidence_score": 88,
                "review_decision": "promote to notable draft",
            },
            {
                "detection_name": "TeamPCP CI/CD behavior",
                "search_outcome": "hit",
                "evidence_summary": "runner host + package activity + secret access + advisory infrastructure",
                "data_readiness": "high",
                "confidence_score": 95,
                "review_decision": "promote to notable draft",
            },
            {
                "detection_name": "Kubernetes token exfiltration",
                "search_outcome": "zero hits",
                "evidence_summary": "required kubernetes audit sourcetype missing",
                "data_readiness": "low",
                "confidence_score": 35,
                "review_decision": "do not close; fix telemetry",
            },
            {
                "detection_name": "Cloud credential abuse",
                "search_outcome": "zero hits",
                "evidence_summary": "required cloud control-plane sourcetype missing",
                "data_readiness": "low",
                "confidence_score": 30,
                "review_decision": "do not close; fix telemetry",
            },
        ],
    )
    with (OUT / "splunk_events.jsonl").open("w") as f:
        for item in events:
            f.write(json.dumps(item) + "\n")
    flattened = []
    for item in events:
        row = {
            "time": item["time"],
            "index": item["index"],
            "sourcetype": item["sourcetype"],
            "source": item["source"],
        }
        row.update(item["event"])
        flattened.append(row)
    event_fields = sorted({key for row in flattened for key in row})
    write_csv(OUT / "demo_events.csv", flattened, event_fields)
    kv_payload = [
        {
            "_key": row["_key"],
            "source": row["source"],
            "actor": row["actor"],
            "focus": row["focus"],
            "type": row["type"],
            "value": row["value"],
            "confidence": row["confidence"],
            "first_seen": row["first_seen"],
        }
        for row in ioc_rows
    ]
    write_json(OUT / "kv_store_payload.json", kv_payload)
    spl_dir = OUT / "spl"
    spl_dir.mkdir(exist_ok=True)
    for name, spl in make_spl(advisories).items():
        (spl_dir / name).write_text(spl.strip() + "\n")
    proof_spl = {
        "proof_01_ioc_starter.spl": """| inputlookup demo_events.csv
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type confidence
| where isnotnull(intel_source)
| stats count values(sourcetype) as sourcetypes values(type) as ioc_types values(confidence) as confidence by demo_case actor intel_source ioc
| sort -count""",
        "proof_02_cyberav3ngers_plc_behavior.spl": """| inputlookup demo_events.csv
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type as ioc_type confidence
| lookup ot_assets.csv dest_ip OUTPUT asset_type as ot_asset_type owner zone as ot_zone
| eval resolved_asset_type=coalesce(ot_asset_type, asset_type)
| eval plc_port=if(dest_port IN (44818,2222,502,22),1,0)
| where demo_case="CyberAv3ngers" OR plc_port=1 OR resolved_asset_type="PLC"
| fillnull value="-" src_ip dest_ip host resolved_asset_type owner ot_zone intel_source actor
| stats count max(plc_port) as plc_port values(dest_port) as dest_ports values(ioc_type) as ioc_types values(process_name) as processes by src_ip dest_ip host resolved_asset_type owner ot_zone intel_source actor
| eval risk_score=case(intel_source!="-",90, resolved_asset_type="PLC" AND plc_port=1,70, resolved_asset_type="PLC",40, true(),30)
| sort -risk_score""",
        "proof_03_teampcp_cicd_behavior.spl": """| inputlookup demo_events.csv
| lookup threat_iocs.csv value as ioc OUTPUT source as intel_source actor type as ioc_type confidence
| lookup cicd_assets.csv host OUTPUT team asset_role
| eval secret_touch=if(isnotnull(secret_accessed) OR like(_raw,"%AWS_ACCESS_KEY_ID%"),1,0)
| eval package_activity=if(isnotnull(package) OR like(url,"%checkmarx-util%"),1,0)
| where demo_case="TeamPCP" OR secret_touch=1 OR package_activity=1
| fillnull value="-" host team asset_role intel_source actor
| stats count max(secret_touch) as secret_touch max(package_activity) as package_activity values(ioc_type) as ioc_types values(query) as dns values(url) as urls values(package) as packages values(secret_accessed) as secrets values(repo_created) as repo_created by host team asset_role intel_source actor
| eval risk_score=case(intel_source!="-" AND secret_touch=1,95, intel_source!="-" AND package_activity=1,85, true(),50)
| sort -risk_score""",
    }
    for name, spl in proof_spl.items():
        (spl_dir / name).write_text(spl.strip() + "\n")


def write_summary(advisories: list[dict], ioc_rows: list[dict], events: list[dict]) -> None:
    by_source = defaultdict(Counter)
    for row in ioc_rows:
        by_source[row["source"]][row["type"]] += 1
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "advisories": [
            {
                "source": advisory["source"],
                "actor": advisory["actor"],
                "focus": advisory["focus"],
                "ioc_counts": advisory["ioc_counts"],
                "telemetry": advisory["telemetry"],
                "detection_objective": advisory["detection_objective"],
            }
            for advisory in advisories
        ],
        "total_iocs": len(ioc_rows),
        "total_seed_events": len(events),
        "spl_files": sorted(p.name for p in (OUT / "spl").glob("*.spl")),
    }
    write_json(OUT / "run_summary.json", summary)
    lines = ["# End-to-End Demo Run", ""]
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append(f"Total IOCs extracted: {summary['total_iocs']}")
    lines.append(f"Seed events generated: {summary['total_seed_events']}")
    lines.append("")
    for source, counts in by_source.items():
        rendered = ", ".join(f"{kind}={count}" for kind, count in sorted(counts.items()))
        lines.append(f"- {source}: {rendered}")
    lines.append("")
    lines.append("Generated SPL:")
    for name in summary["spl_files"]:
        lines.append(f"- outputs/spl/{name}")
    (OUT / "run_summary.md").write_text("\n".join(lines) + "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    advisories, ioc_rows = build_intel()
    events = make_seed_events(advisories, ioc_rows)
    write_json(OUT / "normalized_intel.json", {"advisories": advisories})
    write_splunk_artifacts(advisories, ioc_rows, events)
    write_summary(advisories, ioc_rows, events)
    print(f"Wrote demo artifacts to {OUT}")
    print((OUT / "run_summary.md").read_text())


if __name__ == "__main__":
    main()
