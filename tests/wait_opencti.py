#!/usr/bin/env python3
"""Wait until OpenCTI is ready to accept API requests.

Exits 0 when the GraphQL /about endpoint responds with a version string.
Exits 1 after TIMEOUT seconds (default: 300).

Usage:
  python3 tests/wait_opencti.py [url] [token] [timeout_seconds]
"""
import json, sys, time, urllib.request

url     = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/graphql"
token   = sys.argv[2] if len(sys.argv) > 2 else "8ac2c1f9-0b3d-4f24-a621-4c9b1f2e5a37"
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 300

deadline = time.time() + timeout
while time.time() < deadline:
    try:
        req = urllib.request.Request(
            url,
            data=b'{"query":"{ about { version } }"}',
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        body = json.loads(urllib.request.urlopen(req, timeout=5).read())
        version = body.get("data", {}).get("about", {}).get("version")
        if version:
            print(f"  OpenCTI ready: {version}")
            sys.exit(0)
    except Exception:
        pass
    sys.stdout.write(".")
    sys.stdout.flush()
    time.sleep(5)

print("\nTimed out waiting for OpenCTI")
sys.exit(1)
