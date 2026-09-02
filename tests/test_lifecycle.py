#!/usr/bin/env python3
"""Tests for CTI handling and lifecycle normalization."""
from datetime import datetime, timedelta, timezone
import os
import tempfile
import unittest
from unittest import mock

from sources.base import (
    PUBLISHER_CONFIDENCE,
    PUBLISHER_RELIABILITY,
    atomic_write_text,
    confidence_for_publisher,
    lifecycle_fields,
    source_reliability_for_publisher,
    validate_item,
)
from sources.stix import _object_to_item


class LifecycleTests(unittest.TestCase):
    def test_public_rss_is_clear_but_internal_sources_fail_closed(self):
        self.assertEqual(lifecycle_fields("CISA", "rss")["tlp"], "TLP:CLEAR")
        self.assertEqual(lifecycle_fields("Unknown", "stix")["tlp"], "TLP:AMBER")
        self.assertEqual(lifecycle_fields("Unknown", "slack")["tlp"], "TLP:AMBER")

    def test_stix_object_marking_is_preserved(self):
        now = datetime.now(timezone.utc)
        marking_id = "marking-definition--test-red"
        markings = {
            marking_id: {
                "type": "marking-definition",
                "id": marking_id,
                "definition_type": "tlp",
                "definition": {"tlp": "red"},
            }
        }
        obj = {
            "type": "report",
            "id": "report--lifecycle-test",
            "name": "Handling test",
            "published": now.isoformat(),
            "object_marking_refs": [marking_id],
        }
        item = _object_to_item(obj, "test", now - timedelta(days=1), markings)
        self.assertEqual(item["tlp"], "TLP:RED")
        self.assertEqual(item["analyst_disposition"], "unreviewed")

    def test_source_reliability_is_independent_of_item_confidence(self):
        with mock.patch.dict(PUBLISHER_CONFIDENCE, {"Independent Source": 99}), \
                mock.patch.dict(PUBLISHER_RELIABILITY, {"Independent Source": "D"}):
            self.assertEqual(confidence_for_publisher("Independent Source"), 99)
            self.assertEqual(source_reliability_for_publisher("Independent Source"), "D")

    def test_atomic_write_preserves_previous_output_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "dataset.json")
            atomic_write_text(output, "old")
            with mock.patch("sources.base.os.replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    atomic_write_text(output, "new")
            with open(output) as handle:
                self.assertEqual(handle.read(), "old")

    def test_runtime_contract_rejects_incomplete_items(self):
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            validate_item({"id": "incomplete"})


if __name__ == "__main__":
    unittest.main()
