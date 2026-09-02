#!/usr/bin/env python3
"""Validate a generated dataset against the published JSON Schema."""
import json
import os
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_IN = Path(os.environ.get("SCHEMA_IN", ROOT / "schema" / "threat-watch-data.schema.json"))
JSON_IN = Path(os.environ.get("JSON_IN", "/tmp/threat-watch-data.json"))


def main():
    schema = json.loads(SCHEMA_IN.read_text())
    dataset = json.loads(JSON_IN.read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(dataset), key=lambda error: list(error.path))
    if errors:
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            print(f"FAIL {location}: {error.message}")
        return 1
    print(f"PASS: {JSON_IN} conforms to schema {dataset.get('schema_version')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
