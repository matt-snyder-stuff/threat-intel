#!/usr/bin/env python3
"""Tests for live Splunk query policy and count-first execution."""

import json
import os
import tempfile
import unittest
from unittest import mock

from guardrails.splunk import QueryPolicyError, SearchResult, count_then_search, validate_query


class FakeClient:
    def __init__(self, count=12):
        self.count = count
        self.calls = []

    def search(self, spl, earliest, max_results):
        self.calls.append((spl, earliest, max_results))
        if "stats count" in spl and max_results == 1:
            return SearchResult("count-sid", [{"count": str(self.count)}])
        return SearchResult("detail-sid", [{"host": "host-1"}])


class SplunkPolicyTests(unittest.TestCase):
    def test_accepts_scoped_read_only_query(self):
        validate_query("index=security action=blocked | stats count", "-24h", 50)

    def test_rejects_dangerous_commands(self):
        for command in ("collect", "delete", "outputlookup", "sendalert", "map"):
            with self.subTest(command=command), self.assertRaises(QueryPolicyError):
                validate_query(f"index=security | {command} destination", "-1d", 10)

    def test_rejects_unscoped_wildcard_and_unknown_indexes(self):
        for spl in ("sourcetype=syslog | stats count", "index=* | stats count", "index=finance | stats count"):
            with self.subTest(spl=spl), self.assertRaises(QueryPolicyError):
                validate_query(spl, "-1d", 10)

    def test_rejects_unbounded_or_oversized_execution(self):
        for earliest, limit in (("all", 10), ("-91d", 10), ("-1d", 501)):
            with self.subTest(earliest=earliest, limit=limit), self.assertRaises(QueryPolicyError):
                validate_query("index=security | stats count", earliest, limit)

    def test_rejects_macro_and_inline_time_bypasses(self):
        for spl in ("index=security `hidden_macro` | stats count", "index=security earliest=-365d | stats count"):
            with self.subTest(spl=spl), self.assertRaises(QueryPolicyError):
                validate_query(spl, "-1d", 10)

    def test_count_then_search_audits_both_jobs(self):
        client = FakeClient()
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {"AGENT_AUDIT_LOG": os.path.join(directory, "audit.jsonl")}
        ):
            rows = count_then_search(
                "index=security action=blocked | stats count",
                "index=security action=blocked | stats count by host",
                "-7d",
                threshold=100,
                agent="test-agent",
                operator="analyst@example.com",
                model="test-model",
                client=client,
            )
            self.assertEqual(rows, [{"host": "host-1"}])
            with open(os.environ["AGENT_AUDIT_LOG"]) as handle:
                events = [json.loads(line) for line in handle]
            self.assertEqual([event["action"] for event in events], ["count", "detail"])
            self.assertTrue(all("query_sha256" in event for event in events))
            self.assertTrue(all("query" not in event for event in events))

    def test_count_threshold_blocks_detail_query(self):
        client = FakeClient(count=1001)
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {"AGENT_AUDIT_LOG": os.path.join(directory, "audit.jsonl")}
        ):
            with self.assertRaises(QueryPolicyError):
                count_then_search(
                    "index=security | stats count",
                    "index=security | stats count by host",
                    "-7d",
                    threshold=1000,
                    client=client,
                )
        self.assertEqual(len(client.calls), 1)


if __name__ == "__main__":
    unittest.main()
