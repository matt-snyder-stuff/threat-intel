#!/usr/bin/env python3
"""Deterministic, credential-free sample source for the conference quickstart."""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sources.base import extract_iocs, lifecycle_fields, save_pickle, save_published


DEFAULT_FIXTURE = Path(__file__).resolve().parents[1] / "sample-data" / "reports.json"


def run():
    fixture_path = Path(os.environ.get("SAMPLE_DATA_FILE", DEFAULT_FIXTURE))
    cutoff_days = int(os.environ.get("CUTOFF_DAYS", "30"))
    pkl_out = os.environ.get("PKL_OUT", "/tmp/tw-30d-processed.pkl")
    pub_sidecar = os.environ.get("PUB_SIDECAR", "/tmp/tw-30d-published.json")
    now = datetime.now(timezone.utc)
    cutoff_dt = now - timedelta(days=cutoff_days)

    with fixture_path.open() as handle:
        fixture = json.load(handle)

    items = []
    published = {}
    for report in fixture.get("reports", []):
        created = now - timedelta(hours=int(report["age_hours"]))
        if created < cutoff_dt:
            continue
        publisher = report["publisher"]
        description = report["description"]
        item = {
            "id": report["id"],
            "name": report["name"],
            "created": created,
            "confidence": report["confidence"],
            "all_labels": report["labels"],
            "labels": report["labels"],
            "publisher": publisher,
            "url": f"https://example.com/threat-intel/{report['id']}",
            "tas": report["tas"],
            "t1_vendors": report.get("t1_vendors", []),
            "t2_vendors": report.get("t2_vendors", []),
            "description": description,
            "attack_technique_ids": report.get("attack_technique_ids", []),
            "mitre_tactics": report.get("mitre_tactics", []),
            "iocs": extract_iocs(description),
            **lifecycle_fields(publisher, "sample", tlp="TLP:CLEAR"),
        }
        items.append(item)
        published[item["id"]] = created.isoformat()

    if not items:
        raise ValueError(f"sample fixture contains no reports inside the {cutoff_days}-day window")
    save_pickle(items, cutoff_dt, pkl_out)
    save_published(published, pub_sidecar)
    print(f"Loaded {len(items)} synthetic reports from {fixture_path}")
    print(f"Wrote {pkl_out} and {pub_sidecar}")


if __name__ == "__main__":
    run()
