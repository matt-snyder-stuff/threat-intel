#!/usr/bin/env python3
"""Pipeline health check — read-only, no data modified.

Usage:
  python3 check_pipeline.py
  make status
"""
import base64, glob, json, os, re, sys
from datetime import datetime, timezone

PASS = "PASS"; WARN = "WARN"; FAIL = "FAIL"; SKIP = "SKIP"
results = []


def row(status, check, detail):
    results.append((status, check, detail))
    color = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m", "SKIP": "\033[90m"}
    reset = "\033[0m"
    print(f"  {color.get(status,'')}{status}{reset}  {check:<12}  {detail}")


def _ssl_ctx():
    if os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "false":
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


# ── 1. Dataset freshness ──────────────────────────────────────────────────────
candidates = [
    os.environ.get("JSON_OUT", ""),
    "/tmp/threat-watch-data.json",
    "data/threat-watch-data.json",
]
found = next((p for p in candidates if p and os.path.exists(p)), None)

if not found:
    row(FAIL, "dataset", "No threat-watch-data.json found — run /rebuild or make run-<source>")
else:
    try:
        d = json.load(open(found))
        gen = d.get("generated_at", "")
        ts = datetime.fromisoformat(gen.replace("Z", "+00:00"))
        age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
        reports = d.get("summary", {}).get("total_reports", "?")
        label = f"{found} — {age_h:.0f}h old, {reports} reports"
        if age_h < 25:
            row(PASS, "dataset", label)
        elif age_h < 72:
            row(WARN, "dataset", f"{label} (stale — run /rebuild)")
        else:
            row(FAIL, "dataset", f"{label} (very stale — {age_h/24:.0f}d old)")
    except Exception as e:
        row(WARN, "dataset", f"{found} — could not parse: {e}")


# ── 2. OpenCTI ────────────────────────────────────────────────────────────────
opencti_url = os.environ.get("OPENCTI_URL", "")
opencti_tok = os.environ.get("OPENCTI_TOKEN", "")
if not opencti_url:
    row(SKIP, "opencti", "OPENCTI_URL not set")
else:
    try:
        import urllib.request as _ur
        req = _ur.Request(opencti_url,
            data=b'{"query":"{ about { version } }"}',
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {opencti_tok}"})
        body = json.loads(_ur.urlopen(req, timeout=8).read())
        ver = body.get("data", {}).get("about", {}).get("version", "?")
        row(PASS, "opencti", f"{opencti_url} — version {ver}")
    except Exception as e:
        row(FAIL, "opencti", f"{opencti_url} — {e}")


# ── 3. Splunk ─────────────────────────────────────────────────────────────────
splunk_url = os.environ.get("SPLUNK_URL", "").rstrip("/")
splunk_tok = os.environ.get("SPLUNK_TOKEN", "")
splunk_usr = os.environ.get("SPLUNK_USERNAME", "")
splunk_pw  = os.environ.get("SPLUNK_PASSWORD", "")
if not splunk_url:
    row(SKIP, "splunk", "SPLUNK_URL not set")
elif not (splunk_tok or splunk_usr):
    row(FAIL, "splunk", "SPLUNK_URL set but no SPLUNK_TOKEN or SPLUNK_USERNAME")
else:
    try:
        import urllib.request as _ur
        hdrs = ({"Authorization": f"Bearer {splunk_tok}"} if splunk_tok
                else {"Authorization": "Basic " + base64.b64encode(
                    f"{splunk_usr}:{splunk_pw}".encode()).decode()})
        req = _ur.Request(f"{splunk_url}/services/server/info?output_mode=json", headers=hdrs)
        body = json.loads(_ur.urlopen(req, context=_ssl_ctx(), timeout=8).read())
        ver = body["entry"][0]["content"].get("version", "?")
        row(PASS, "splunk", f"{splunk_url} — Splunk {ver}")
    except Exception as e:
        row(FAIL, "splunk", f"{splunk_url} — {e}")


# ── 4. Slack ──────────────────────────────────────────────────────────────────
slack_tok = os.environ.get("SLACK_TOKEN", "")
if not slack_tok:
    row(SKIP, "slack", "SLACK_TOKEN not set")
else:
    try:
        import urllib.request as _ur
        req = _ur.Request("https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {slack_tok}"})
        body = json.loads(_ur.urlopen(req, timeout=8).read())
        if body.get("ok"):
            row(PASS, "slack", f"authenticated as {body.get('user')} in {body.get('team')}")
        else:
            row(FAIL, "slack", f"auth.test error: {body.get('error')}")
    except Exception as e:
        row(FAIL, "slack", str(e))


# ── 5. environment.md completeness ───────────────────────────────────────────
env_path = "environment.md"
if not os.path.exists(env_path):
    row(WARN, "environ", "environment.md not found — peak-hunt agent will treat all indexes as unknown")
else:
    text = open(env_path).read()
    unknown = len(re.findall(r'\bUnknown\b', text))
    total   = len(re.findall(r'\|\s*(?:Active|Inactive|Unknown)\s*\|', text))
    if total == 0:
        row(WARN, "environ", "environment.md exists but contains no index status rows")
    elif unknown == 0:
        row(PASS, "environ", f"all {total} indexes have known status")
    elif unknown == total:
        row(WARN, "environ", f"all {total} indexes still Unknown — fill in after first Splunk run")
    else:
        row(WARN, "environ", f"{unknown}/{total} indexes still Unknown")


# ── 6. Prior hunts ────────────────────────────────────────────────────────────
hunt_files = sorted(glob.glob("prior-hunts/HUNT-*.json"))
if not hunt_files:
    row(WARN, "prior-hunts", "No hunt records — institutional memory empty (run /peak-hunt to start)")
else:
    try:
        latest = json.load(open(hunt_files[-1]))
        row(PASS, "prior-hunts",
            f"{len(hunt_files)} records — latest: {latest.get('hunt_id')} ({latest.get('date')})")
    except Exception as e:
        row(WARN, "prior-hunts", f"{len(hunt_files)} files found but could not parse latest: {e}")


# ── Summary ───────────────────────────────────────────────────────────────────
counts = {s: sum(1 for r in results if r[0] == s) for s in (PASS, WARN, FAIL, SKIP)}
print()
print("─" * 60)
print(f"Pipeline Health — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
for s, label in ((PASS, "passed"), (WARN, "need attention"), (FAIL, "failed"), (SKIP, "skipped")):
    if counts[s]:
        print(f"  {s}  {counts[s]} {label}")
print("─" * 60)

if counts[FAIL]:
    print("Run /rebuild to refresh the dataset or check failing source credentials.")
    sys.exit(1)
elif counts[WARN]:
    print("Pipeline functional — address warnings before next hunt.")
else:
    print("All checks passed. Pipeline is healthy.")
