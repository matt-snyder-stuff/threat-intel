#!/usr/bin/env python3
"""Persistent local review state for threat-intelligence reports."""

import argparse
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from sources.base import atomic_write_text


DISPOSITIONS = {"unreviewed", "actioned", "confirmed", "false_positive", "expired", "revoked"}


def load_review_state(path):
    if not os.path.exists(path):
        return {"schema_version": "1", "reports": {}}
    with open(path) as handle:
        state = json.load(handle)
    if state.get("schema_version") != "1" or not isinstance(state.get("reports"), dict):
        raise ValueError("review state must use schema_version 1 and contain a reports object")
    return state


def save_review_state(path, state):
    atomic_write_text(path, json.dumps(state, indent=2, sort_keys=True) + "\n")


def set_review(state, report_id, disposition, owner="", case_url="", note=""):
    if not report_id.strip():
        raise ValueError("report ID cannot be empty")
    if disposition not in DISPOSITIONS:
        raise ValueError(f"invalid disposition: {disposition}")
    if case_url:
        parsed = urlparse(case_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("case URL must be an absolute http or https URL")
    existing = state["reports"].get(report_id, {})
    state["reports"][report_id] = {
        "disposition": disposition,
        "owner": owner or existing.get("owner", ""),
        "case_url": case_url or existing.get("case_url", ""),
        "note": note or existing.get("note", ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    return state["reports"][report_id]


def build_parser():
    parser = argparse.ArgumentParser(description="Manage persistent report review state.")
    parser.add_argument("--file", default=os.environ.get("REVIEW_STATE", "data/review-state.json"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    set_parser = subparsers.add_parser("set", help="Create or update a report review")
    set_parser.add_argument("report_id")
    set_parser.add_argument("--disposition", required=True, choices=sorted(DISPOSITIONS))
    set_parser.add_argument("--owner", default="")
    set_parser.add_argument("--case-url", default="")
    set_parser.add_argument("--note", default="")
    subparsers.add_parser("list", help="Print all report reviews")
    return parser


def main():
    args = build_parser().parse_args()
    state = load_review_state(args.file)
    if args.command == "set":
        record = set_review(state, args.report_id, args.disposition, args.owner, args.case_url, args.note)
        save_review_state(args.file, state)
        print(json.dumps({"report_id": args.report_id, **record}, indent=2))
    else:
        print(json.dumps(state, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
