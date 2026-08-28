# /check-pipeline

Health check for the Threat Watch pipeline. Verifies dataset freshness, source
connectivity, Splunk reachability, and environment completeness. Prints a
pass/warn/fail summary — no data is modified.

## Steps

### 1 — Dataset freshness

Check whether `threat-watch-data.json` exists and how old it is:

```python
import json, os
from datetime import datetime, timezone

paths = [
    os.environ.get("JSON_OUT", "/tmp/threat-watch-data.json"),
    "data/threat-watch-data.json",
]
found = None
for p in paths:
    if os.path.exists(p):
        found = p
        break

if not found:
    print("FAIL  dataset    No threat-watch-data.json found (run /rebuild first)")
else:
    with open(found) as f:
        d = json.load(f)
    gen = d.get("generated_at", "")
    try:
        ts = datetime.fromisoformat(gen.replace("Z", "+00:00"))
        age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
        status = "PASS" if age_h < 25 else ("WARN" if age_h < 72 else "FAIL")
        print(f"{status}  dataset    {found} — {age_h:.0f}h old ({d.get('summary',{}).get('total_reports',0)} reports)")
    except Exception:
        print(f"WARN  dataset    {found} — could not parse generated_at: {gen!r}")
```

### 2 — Source connectivity checks

For each configured source, verify the required env vars are present and attempt
a lightweight connectivity probe:

**OpenCTI** (if `OPENCTI_URL` is set):
```python
import os, urllib.request, json as _json
url = os.environ.get("OPENCTI_URL", "")
token = os.environ.get("OPENCTI_TOKEN", "")
if url:
    try:
        req = urllib.request.Request(url,
            data=b'{"query":"{ about { version } }"}',
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        body = _json.loads(urllib.request.urlopen(req, timeout=8).read())
        ver = body.get("data", {}).get("about", {}).get("version", "?")
        print(f"PASS  opencti    {url} — version {ver}")
    except Exception as e:
        print(f"FAIL  opencti    {url} — {e}")
else:
    print("SKIP  opencti    OPENCTI_URL not set")
```

**Splunk** (if `SPLUNK_URL` is set):
```python
import os, base64, urllib.request, json as _json
url = os.environ.get("SPLUNK_URL", "").rstrip("/")
token = os.environ.get("SPLUNK_TOKEN", "")
user = os.environ.get("SPLUNK_USERNAME", "")
pw   = os.environ.get("SPLUNK_PASSWORD", "")
verify = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() != "false"
if url:
    try:
        if token:
            hdrs = {"Authorization": f"Bearer {token}"}
        elif user:
            creds = base64.b64encode(f"{user}:{pw}".encode()).decode()
            hdrs = {"Authorization": f"Basic {creds}"}
        else:
            print("FAIL  splunk     SPLUNK_URL set but no SPLUNK_TOKEN or SPLUNK_USERNAME")
            raise SystemExit
        ctx = None
        if not verify:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(f"{url}/services/server/info?output_mode=json", headers=hdrs)
        body = _json.loads(urllib.request.urlopen(req, context=ctx, timeout=8).read())
        ver = body["entry"][0]["content"].get("version", "?")
        print(f"PASS  splunk     {url} — Splunk {ver}")
    except SystemExit:
        pass
    except Exception as e:
        print(f"FAIL  splunk     {url} — {e}")
else:
    print("SKIP  splunk     SPLUNK_URL not set")
```

**Slack** (if `SLACK_TOKEN` is set):
```python
import os, urllib.request, json as _json
token = os.environ.get("SLACK_TOKEN", "")
if token:
    try:
        req = urllib.request.Request("https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"})
        body = _json.loads(urllib.request.urlopen(req, timeout=8).read())
        if body.get("ok"):
            print(f"PASS  slack      authenticated as {body.get('user')} in {body.get('team')}")
        else:
            print(f"FAIL  slack      auth.test returned ok=false: {body.get('error')}")
    except Exception as e:
        print(f"FAIL  slack      {e}")
else:
    print("SKIP  slack      SLACK_TOKEN not set")
```

### 3 — environment.md completeness

Count how many indexes in `environment.md` are still marked `Unknown`:

```python
import re, os
path = "environment.md"
if not os.path.exists(path):
    print("WARN  environ    environment.md not found — peak-hunt agent will treat all indexes as unknown")
else:
    with open(path) as f:
        text = f.read()
    unknown = len(re.findall(r'\bUnknown\b', text))
    total   = len(re.findall(r'\|\s*(Active|Inactive|Unknown)\s*\|', text))
    if unknown == 0:
        print(f"PASS  environ    environment.md — all {total} indexes have known status")
    elif unknown == total:
        print(f"WARN  environ    environment.md — all {total} indexes still Unknown (fill in after first Splunk run)")
    else:
        print(f"WARN  environ    environment.md — {unknown}/{total} indexes still Unknown")
```

### 4 — Prior hunts index

```python
import os, glob, json as _json
files = sorted(glob.glob("prior-hunts/HUNT-*.json"))
if not files:
    print("WARN  prior-hunts  No hunt records found — institutional memory is empty")
else:
    latest = _json.load(open(files[-1]))
    print(f"PASS  prior-hunts  {len(files)} hunt records — latest: {latest.get('hunt_id')} ({latest.get('date')})")
```

### 5 — Print summary

After running all checks, print:

```
─────────────────────────────────────────
Pipeline Health — <timestamp UTC>
PASS  N checks passed
WARN  N checks need attention
FAIL  N checks failed
SKIP  N checks skipped (source not configured)
─────────────────────────────────────────
```

If any FAIL, print: `Run /rebuild to refresh the dataset or check the failing source credentials.`

If all PASS or SKIP (no FAIL or WARN), print: `All checks passed. Pipeline is healthy.`

## Notes

- This command is read-only. It never modifies files, runs searches, or sends messages.
- If `.env` is present in the repo root, remind the user to `source .env` or use `direnv` before running checks that need credentials.
- Keep runtime under 15 seconds. If any connectivity check exceeds 8 seconds, it counts as FAIL.
