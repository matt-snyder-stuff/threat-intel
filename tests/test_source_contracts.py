#!/usr/bin/env python3
"""Deterministic contract tests for non-OpenCTI source adapters."""

import os
import pickle
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from sources import rss, sample, slack, splunk, stix


REQUIRED_FIELDS = {
    "id", "name", "created", "confidence", "all_labels", "labels",
    "publisher", "url", "tas", "t1_vendors", "t2_vendors", "description",
    "attack_technique_ids", "mitre_tactics", "iocs", "source_type",
    "source_reliability", "tlp", "valid_until", "revoked",
    "analyst_disposition",
}
IOC_TYPES = {"cve", "ipv4", "url", "md5", "sha1", "sha256", "domain"}


class SourceContractTests(unittest.TestCase):
    def assert_contract(self, item, source_type):
        self.assertFalse(REQUIRED_FIELDS - set(item))
        self.assertEqual(item["source_type"], source_type)
        self.assertIsInstance(item["created"], datetime)
        self.assertIsInstance(item["confidence"], int)
        self.assertTrue(0 <= item["confidence"] <= 100)
        self.assertEqual(set(item["iocs"]), IOC_TYPES)
        self.assertIn(item["source_reliability"], "ABCDEF")
        self.assertTrue(item["tlp"].startswith("TLP:"))

    @staticmethod
    def load_single(path):
        with open(path, "rb") as handle:
            state = pickle.load(handle)
        if len(state["items"]) != 1:
            raise AssertionError(f"expected one item, got {len(state['items'])}")
        return state["items"][0]

    def test_rss_contract(self):
        now = datetime.now(timezone.utc)
        feed_item = {
            "id": "rss-1",
            "title": "CISA cloud advisory",
            "link": "https://www.cisa.gov/news-events/alerts/test",
            "pub_str": now.isoformat(),
            "desc": "CVE-2026-12345 observed at 203.0.113.8",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "RSS_FEEDS": "https://example.test/feed",
            "PKL_OUT": os.path.join(directory, "rss.pkl"),
            "PUB_SIDECAR": os.path.join(directory, "rss.json"),
        }, clear=False), mock.patch("sources.rss._fetch_feed", return_value=[feed_item]):
            rss.run()
            item = self.load_single(os.environ["PKL_OUT"])
        self.assert_contract(item, "rss")

    def test_sample_source_is_deterministic_and_offline(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "PKL_OUT": os.path.join(directory, "sample.pkl"),
            "PUB_SIDECAR": os.path.join(directory, "sample.json"),
        }, clear=False):
            sample.run()
            with open(os.environ["PKL_OUT"], "rb") as handle:
                items = pickle.load(handle)["items"]
        self.assertGreaterEqual(len(items), 8)
        self.assertTrue(all(item["source_type"] == "sample" for item in items))
        self.assertTrue(any(item["tas"] for item in items))
        for item in items:
            self.assert_contract(item, "sample")

    def test_slack_contract(self):
        message = {
            "ts": str(datetime.now(timezone.utc).timestamp()),
            "text": "Cloud IOC <https://www.cisa.gov/alert> CVE-2026-12345",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "SLACK_TOKEN": "test-token",
            "SLACK_CHANNEL_ID": "C123",
            "PKL_OUT": os.path.join(directory, "slack.pkl"),
            "PUB_SIDECAR": os.path.join(directory, "slack.json"),
        }, clear=False), mock.patch("sources.slack._fetch_messages", return_value=[message]):
            slack.run()
            item = self.load_single(os.environ["PKL_OUT"])
        self.assert_contract(item, "slack")

    def test_splunk_contract(self):
        row = {
            "id": "splunk-1",
            "title": "Endpoint IOC match",
            "description": "CVE-2026-12345 on 203.0.113.8",
            "url": "https://www.cisa.gov/alert",
            "source": "CISA",
            "_time": datetime.now(timezone.utc).isoformat(),
            "confidence": "90",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {
            "SPLUNK_URL": "https://splunk.example.test:8089",
            "PKL_OUT": os.path.join(directory, "splunk.pkl"),
            "PUB_SIDECAR": os.path.join(directory, "splunk.json"),
        }, clear=False), mock.patch("sources.splunk._run_search", return_value=[row]):
            splunk.run()
            item = self.load_single(os.environ["PKL_OUT"])
        self.assert_contract(item, "splunk")

    def test_stix_contract(self):
        now = datetime.now(timezone.utc)
        objects = [{
            "type": "report",
            "id": "report--contract-test",
            "name": "STIX cloud report",
            "description": "CVE-2026-12345",
            "published": now.isoformat(),
            "confidence": 80,
        }]
        items, _ = stix._objects_to_items(objects, "CISA", now - timedelta(days=1))
        self.assertEqual(len(items), 1)
        self.assert_contract(items[0], "stix")


if __name__ == "__main__":
    unittest.main()
