#!/usr/bin/env python3
"""Validate version-controlled Sigma and Splunk detection artifacts."""

import argparse
import pathlib
import re
import sys
import uuid

import yaml


SIGMA_REQUIRED = {"title", "id", "status", "description", "logsource", "detection", "level"}
SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
BLOCKED_SPL = re.compile(r"\|\s*(?:collect|delete|outputlookup|sendalert|script)\b", re.I)


def validate_sigma(path):
    with open(path) as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        raise ValueError("Sigma document must be an object")
    missing = SIGMA_REQUIRED - set(document)
    if missing:
        raise ValueError(f"missing Sigma fields: {', '.join(sorted(missing))}")
    uuid.UUID(str(document["id"]))
    if document["level"] not in SIGMA_LEVELS:
        raise ValueError(f"invalid Sigma level: {document['level']}")
    detection = document["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError("Sigma detection must contain a condition")


def validate_spl(path):
    text = path.read_text().strip()
    if not text:
        raise ValueError("SPL detection cannot be empty")
    if not re.search(r"\bindex\s*=", text, re.I):
        raise ValueError("SPL detection must explicitly scope an index")
    if not re.search(r"\bearliest\s*=\s*-\d+[smhdw]", text, re.I):
        raise ValueError("SPL detection must include a bounded earliest time")
    if BLOCKED_SPL.search(text):
        raise ValueError("SPL detection contains a write or destructive command")


def validate_directory(root):
    root = pathlib.Path(root)
    paths = sorted(root.rglob("*.yml")) + sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.spl"))
    if not paths:
        raise ValueError(f"no detection artifacts found under {root}")
    errors = []
    for path in paths:
        try:
            if path.suffix == ".spl":
                validate_spl(path)
            else:
                validate_sigma(path)
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return paths, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="detections")
    args = parser.parse_args()
    try:
        paths, errors = validate_directory(args.path)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    if errors:
        for problem in errors:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"PASS: validated {len(paths)} detection artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
