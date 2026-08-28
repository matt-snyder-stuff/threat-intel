#!/usr/bin/env python3
"""Pipeline output validator.

Loads a processed pickle and the built JSON dataset, then asserts the full
schema contract is satisfied — including the new fields added in the CTI
parsing improvements (iocs, attack_technique_ids, mitre_tactics).

Usage:
  python3 tests/validate.py                          # uses /tmp defaults
  PKL_IN=/data/tw-30d-processed.pkl JSON_IN=/data/threat-watch-data.json python3 tests/validate.py

Exit 0 on success, 1 on any failure.  Designed to run inside the Docker image.
"""
import json, os, pickle, re, sys

PKL_IN  = os.environ.get("PKL_IN",  "/tmp/tw-30d-processed.pkl")
JSON_IN = os.environ.get("JSON_IN", "/tmp/threat-watch-data.json")

REQUIRED_ITEM_FIELDS = [
    "id", "name", "created", "confidence",
    "all_labels", "labels",
    "publisher", "url",
    "tas", "t1_vendors", "t2_vendors",
    "description",
    "attack_technique_ids",
    "mitre_tactics",
    "iocs",
]

REQUIRED_JSON_KEYS = [
    "generated_at", "schema_version", "window_days", "summary",
    "cloud_clusters", "last_24h",
]

IOC_TYPES = {"cve", "ipv4", "url", "md5", "sha1", "sha256", "domain"}

_CVE_RE   = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)
_IPV4_RE  = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def check(condition, msg):
    if not condition:
        print(f"  FAIL: {msg}")
        return False
    return True


def validate_pickle(path):
    errors = 0
    print(f"Pickle: {path}")

    if not os.path.exists(path):
        print(f"  FAIL: file not found: {path}")
        return 1

    with open(path, "rb") as f:
        state = pickle.load(f)

    if not check("items" in state, "pickle missing 'items' key"):
        return 1
    if not check("cutoff" in state, "pickle missing 'cutoff' key"):
        return 1

    items = state["items"]
    print(f"  Items: {len(items)}")

    # --- Field completeness ---
    missing_fields = set()
    for item in items:
        for field in REQUIRED_ITEM_FIELDS:
            if field not in item:
                missing_fields.add(field)
    if missing_fields:
        print(f"  FAIL: items missing required fields: {sorted(missing_fields)}")
        errors += 1
    else:
        print(f"  PASS: all {len(REQUIRED_ITEM_FIELDS)} required fields present")

    # --- Field types ---
    type_errors = 0
    for i, item in enumerate(items):
        if not isinstance(item.get("attack_technique_ids"), list):
            type_errors += 1
        if not isinstance(item.get("mitre_tactics"), list):
            type_errors += 1
        if not isinstance(item.get("iocs"), dict):
            type_errors += 1
        conf = item.get("confidence", -1)
        if not (0 <= conf <= 100):
            type_errors += 1
    if type_errors:
        print(f"  FAIL: {type_errors} type violations across items")
        errors += 1
    else:
        print(f"  PASS: field types correct")

    # --- IOC dict structure ---
    ioc_key_errors = 0
    for item in items:
        iocs = item.get("iocs", {})
        for k, v in iocs.items():
            if k not in IOC_TYPES:
                ioc_key_errors += 1
            if not isinstance(v, list):
                ioc_key_errors += 1
    if ioc_key_errors:
        print(f"  FAIL: {ioc_key_errors} unexpected IOC dict keys/types")
        errors += 1
    else:
        print(f"  PASS: iocs dict structure valid")

    # --- CVE format check ---
    cve_format_errors = 0
    for item in items:
        for cve in item.get("iocs", {}).get("cve", []):
            if not _CVE_RE.match(cve):
                cve_format_errors += 1
    if cve_format_errors:
        print(f"  FAIL: {cve_format_errors} malformed CVE IDs (should be CVE-YYYY-NNNNN)")
        errors += 1
    else:
        print(f"  PASS: all extracted CVE IDs correctly formatted")

    # --- IPv4 sanity (no defanged values should survive) ---
    bad_ips = 0
    for item in items:
        for ip in item.get("iocs", {}).get("ipv4", []):
            if not _IPV4_RE.match(ip):
                bad_ips += 1
            else:
                parts = ip.split(".")
                if not all(0 <= int(p) <= 255 for p in parts):
                    bad_ips += 1
    if bad_ips:
        print(f"  FAIL: {bad_ips} IPv4 values failed sanity check (defanged or out of range)")
        errors += 1
    else:
        print(f"  PASS: all IPv4 values are valid plain dotted-decimal")

    # --- ATT&CK T-ID format and no embedded IDs in name ---
    tid_format_errors = 0
    name_pollution = 0
    _TID_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
    for item in items:
        for tid in item.get("attack_technique_ids", []):
            if not _TID_RE.match(tid):
                tid_format_errors += 1
        if re.search(r'\[T\d{4}', item.get("name", "")):
            name_pollution += 1
    if tid_format_errors:
        print(f"  FAIL: {tid_format_errors} malformed attack_technique_ids")
        errors += 1
    else:
        print(f"  PASS: all attack_technique_ids match T####(.###) format")
    if name_pollution:
        print(f"  FAIL: {name_pollution} items have ATT&CK IDs embedded in name field")
        errors += 1
    else:
        print(f"  PASS: no ATT&CK IDs embedded in name strings")

    # --- Summary stats ---
    ioc_count   = sum(1 for i in items if any(i.get("iocs", {}).values()))
    atk_count   = sum(1 for i in items if i.get("attack_technique_ids"))
    tactic_count = sum(1 for i in items if i.get("mitre_tactics"))
    cve_total   = sum(len(i.get("iocs", {}).get("cve", [])) for i in items)
    print(f"  INFO: {ioc_count}/{len(items)} items have extracted IOCs | {cve_total} CVEs total")
    print(f"  INFO: {atk_count} items with ATT&CK technique IDs | {tactic_count} items with tactic labels")

    return errors


def validate_json(path):
    errors = 0
    print(f"\nJSON dataset: {path}")

    if not os.path.exists(path):
        print(f"  FAIL: file not found: {path}")
        return 1

    with open(path) as f:
        d = json.load(f)

    for key in REQUIRED_JSON_KEYS:
        if not check(key in d, f"missing key '{key}'"):
            errors += 1

    clusters = d.get("cloud_clusters", [])
    for cluster in clusters:
        for field in ("reach_score", "size", "cloud_tags", "lead", "reports"):
            if field not in cluster:
                print(f"  FAIL: cluster missing field '{field}'")
                errors += 1
                break

    # Verify late-IOC fields are present on cluster reports
    report_ioc_errors = 0
    for cluster in clusters:
        for report in cluster.get("reports", []):
            for field in ("intel_published", "iocs", "attack_technique_ids", "description"):
                if field not in report:
                    report_ioc_errors += 1
    if report_ioc_errors:
        print(f"  FAIL: {report_ioc_errors} cluster reports missing late-IOC fields (intel_published/iocs/attack_technique_ids/description)")
        errors += 1
    else:
        total_reports = sum(len(c.get("reports", [])) for c in clusters)
        if total_reports:
            print(f"  PASS: late-IOC fields present on all {total_reports} cluster reports")

    # Same check for last_24h reports
    last24_ioc_errors = 0
    for report in d.get("last_24h", {}).get("reports", []):
        for field in ("intel_published", "iocs", "attack_technique_ids"):
            if field not in report:
                last24_ioc_errors += 1
    if last24_ioc_errors:
        print(f"  FAIL: {last24_ioc_errors} last_24h reports missing late-IOC fields")
        errors += 1
    else:
        n24 = len(d.get("last_24h", {}).get("reports", []))
        if n24:
            print(f"  PASS: late-IOC fields present on all {n24} last_24h reports")

    if not errors:
        print(f"  PASS: JSON schema valid")
    print(f"  INFO: {len(clusters)} clusters | {d.get('last_24h',{}).get('count',0)} last-24h reports")

    return errors


def main():
    print("=" * 60)
    print("Threat Intel Pipeline — Output Validator")
    print("=" * 60)

    errors = 0
    errors += validate_pickle(PKL_IN)
    errors += validate_json(JSON_IN)

    print("\n" + "=" * 60)
    if errors:
        print(f"FAILED — {errors} check(s) failed")
        sys.exit(1)
    else:
        print("ALL CHECKS PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
