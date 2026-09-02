#!/usr/bin/env python3
"""Top-level CLI for the threat-intel pipeline.

Usage:
  python3 run.py --source opencti          # fetch from OpenCTI
  python3 run.py --source slack            # fetch from Slack channel
  python3 run.py --source rss              # fetch from RSS feeds
  python3 run.py --source opencti --build  # fetch + build dashboard

Each source reads its configuration from environment variables.
Run with -h / --help for per-source env var details.
"""
import argparse, os, subprocess, sys

# ── Per-source metadata (for help text + env-var validation) ─────────────────
SOURCES = {
    "opencti": {
        "required": ["OPENCTI_URL", "OPENCTI_TOKEN"],
        "optional": ["RAW_OUT", "PKL_OUT", "PUB_SIDECAR", "CUTOFF_DAYS"],
        "description": "Fetch 30-day cloud/AI reports from an OpenCTI GraphQL instance.",
    },
    "slack": {
        "required": ["SLACK_TOKEN", "SLACK_CHANNEL_ID"],
        "optional": ["SLACK_LOOKBACK_DAYS", "PKL_OUT", "PUB_SIDECAR"],
        "description": "Read threat intel messages from a Slack channel.",
    },
    "rss": {
        "required": [],
        "optional": ["RSS_FEEDS", "CUTOFF_DAYS", "PKL_OUT", "PUB_SIDECAR"],
        "description": "Parse RSS/Atom feeds directly (no OpenCTI required).",
    },
    "splunk": {
        "required": ["SPLUNK_URL"],
        "optional": [
            "SPLUNK_TOKEN", "SPLUNK_USERNAME", "SPLUNK_PASSWORD",
            "SPLUNK_SEARCH", "SPLUNK_EARLIEST",
            "SPLUNK_FIELD_NAME", "SPLUNK_FIELD_DESC", "SPLUNK_FIELD_URL",
            "SPLUNK_FIELD_PUBLISHER", "SPLUNK_FIELD_TIME",
            "SPLUNK_VERIFY_SSL", "CUTOFF_DAYS", "PKL_OUT", "PUB_SIDECAR",
            "SPLUNK_ALLOWED_INDEXES", "SPLUNK_MAX_LOOKBACK_DAYS", "SPLUNK_MAX_RESULTS",
        ],
        "description": "Run a Splunk search via the REST API and use results as threat intel items.",
    },
    "stix": {
        "required": [],
        "optional": [
            "TAXII_URL", "TAXII_USERNAME", "TAXII_PASSWORD", "TAXII_TOKEN",
            "TAXII_COLLECTION", "TAXII_API_ROOT",
            "STIX_FILE", "STIX_URL",
            "STIX_VERIFY_SSL", "STIX_LIMIT",
            "CUTOFF_DAYS", "PKL_OUT", "PUB_SIDECAR",
        ],
        "description": "Ingest STIX 2.x objects from a TAXII 2.x server, a local bundle file, or a bundle URL.",
    },
}


def _env_var_table(source_name):
    meta = SOURCES[source_name]
    lines = []
    lines.append(f"\n  {source_name}: {meta['description']}")
    lines.append("  Required env vars:")
    for v in meta["required"]:
        lines.append(f"    {v}")
    if meta["optional"]:
        lines.append("  Optional env vars:")
        for v in meta["optional"]:
            lines.append(f"    {v}")
    return "\n".join(lines)


class HelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


def build_parser():
    epilog_parts = ["\nSources and their environment variables:"]
    for name in SOURCES:
        epilog_parts.append(_env_var_table(name))
    epilog_parts.append("\nExamples:")
    epilog_parts.append("  python3 run.py --source opencti")
    epilog_parts.append("  python3 run.py --source rss --build")
    epilog_parts.append("  python3 run.py --source slack")
    epilog_parts.append("  python3 run.py --source stix   # TAXII_URL or STIX_FILE or STIX_URL")

    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Threat-intel pipeline: fetch from a source, optionally build the dashboard.",
        epilog="\n".join(epilog_parts),
        formatter_class=HelpFormatter,
    )
    parser.add_argument(
        "--source", "-s",
        required=True,
        choices=list(SOURCES.keys()),
        help="Data source to fetch from (opencti | slack | rss | splunk | stix)",
    )
    parser.add_argument(
        "--build", "-b",
        action="store_true",
        default=False,
        help="Also run generator/build.py after fetching (requires PKL_OUT + RAW_OUT in place)",
    )
    return parser


def check_env(source_name):
    """Print a clear error and exit 1 if any required env var is missing."""
    missing = [v for v in SOURCES[source_name]["required"] if not os.environ.get(v)]
    if missing:
        print(f"Error: the '{source_name}' source requires these env vars which are not set:", file=sys.stderr)
        for v in missing:
            print(f"  {v}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Set them in your shell or copy .env.example → .env and source it:", file=sys.stderr)
        print("  source .env", file=sys.stderr)
        sys.exit(1)


def main():
    parser = build_parser()
    args   = parser.parse_args()

    source_name = args.source
    meta        = SOURCES[source_name]

    print(f"[run.py] Source: {source_name}")
    print(f"[run.py] {meta['description']}")
    print(f"[run.py] Required env vars: {', '.join(meta['required'])}")
    if meta["optional"]:
        print(f"[run.py] Optional env vars: {', '.join(meta['optional'])}")

    # Validate required env vars before importing (gives a nicer error)
    check_env(source_name)

    # Dispatch to the appropriate source module
    if source_name == "opencti":
        from sources.opencti import run
    elif source_name == "slack":
        from sources.slack import run
    elif source_name == "rss":
        from sources.rss import run
    elif source_name == "splunk":
        from sources.splunk import run
    elif source_name == "stix":
        from sources.stix import run
    else:
        print(f"Error: unknown source '{source_name}'", file=sys.stderr)
        sys.exit(1)

    run()

    if args.build:
        repository_root = os.path.dirname(os.path.abspath(__file__))
        print("\n[run.py] Running generator.build...", file=sys.stderr)
        result = subprocess.run([sys.executable, "-m", "generator.build"], cwd=repository_root)
        if result.returncode != 0:
            print(f"[run.py] build.py exited with code {result.returncode}", file=sys.stderr)
            sys.exit(result.returncode)
        print("[run.py] build.py completed successfully.", file=sys.stderr)


if __name__ == "__main__":
    main()
