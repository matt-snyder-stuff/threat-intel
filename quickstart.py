#!/usr/bin/env python3
"""Build and optionally serve the bundled conference demo."""

import argparse
import json
import os
import subprocess
import sys
import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def build_demo(output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "PKL_OUT": str(output_dir / "tw-30d-processed.pkl"),
        "PUB_SIDECAR": str(output_dir / "tw-30d-published.json"),
        "HTML_OUT": str(output_dir / "threat-watch.html"),
        "JSON_OUT": str(output_dir / "threat-watch-data.json"),
        "REVIEW_STATE_IN": str(output_dir / "review-state.json"),
        "ENVIRONMENT_PROFILE": "",
        "PUBLISH_MAX_TLP": "TLP:AMBER",
        "PYTHONUNBUFFERED": "1",
    })
    subprocess.run(
        [sys.executable, "run.py", "--source", "sample", "--build"],
        cwd=ROOT,
        env=env,
        check=True,
    )
    with (output_dir / "threat-watch-data.json").open() as handle:
        dataset = json.load(handle)
    print(
        f"Ready: {dataset['summary']['total_reports']} synthetic reports, "
        f"{len(dataset['cloud_clusters'])} clusters, "
        f"{len(dataset['threat_actors'])} actors"
    )
    print(f"Dashboard: {(output_dir / 'threat-watch.html').resolve().as_uri()}")


def serve_demo(output_dir, port, open_browser):
    url = f"http://127.0.0.1:{port}/threat-watch.html"
    handler = partial(SimpleHTTPRequestHandler, directory=str(output_dir))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"Dashboard: {url}")
    print("Press Ctrl-C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="data", help="Artifact directory (default: data)")
    parser.add_argument("--serve", action="store_true", help="Serve the dashboard after building")
    parser.add_argument("--port", type=int, default=8080, help="Local server port (default: 8080)")
    parser.add_argument("--no-open", action="store_true", help="Do not open a browser when serving")
    args = parser.parse_args()
    output_dir = (ROOT / args.output_dir).resolve() if not os.path.isabs(args.output_dir) else Path(args.output_dir)
    build_demo(output_dir)
    if args.serve:
        serve_demo(output_dir, args.port, not args.no_open)


if __name__ == "__main__":
    main()
