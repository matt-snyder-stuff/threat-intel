#!/usr/bin/env python3
"""Tests for CTI handling and lifecycle normalization."""
from datetime import datetime, timedelta, timezone
import unittest

from sources.base import lifecycle_fields
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


if __name__ == "__main__":
    unittest.main()
