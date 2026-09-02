#!/usr/bin/env python3
"""Tests for environment relevance and persistent analyst review state."""

import json
import os
import tempfile
import unittest

from operations.context import filter_by_tlp, load_environment_profile, relevance_for_item
from operations.review_state import load_review_state, save_review_state, set_review


class OperatorWorkflowTests(unittest.TestCase):
    def test_environment_profile_scores_exact_context_matches(self):
        profile = {
            "name": "Production",
            "priorities": {
                "labels": {"cloud-aws": 20},
                "vendors": {"Okta": 30},
                "keywords": {"identity provider": 15},
            },
        }
        item = {
            "all_labels": ["cloud", "cloud-aws"],
            "t1_vendors": ["Okta"],
            "t2_vendors": [],
            "tas": [],
            "name": "Identity provider compromise",
            "description": "AWS tenant affected",
        }
        score, matches = relevance_for_item(item, profile)
        self.assertEqual(score, 65)
        self.assertEqual(len(matches), 3)

    def test_invalid_profile_weight_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "profile.json")
            with open(path, "w") as handle:
                json.dump({"name": "Bad", "priorities": {"labels": {"cloud": 101}}}, handle)
            with self.assertRaises(ValueError):
                load_environment_profile(path)

    def test_review_state_persists_assignment_and_case(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "review-state.json")
            state = load_review_state(path)
            set_review(
                state,
                "report--1",
                "actioned",
                owner="soc@example.com",
                case_url="https://cases.example/IR-42",
                note="Detection owner assigned",
            )
            save_review_state(path, state)
            restored = load_review_state(path)["reports"]["report--1"]
            self.assertEqual(restored["disposition"], "actioned")
            self.assertEqual(restored["owner"], "soc@example.com")
            self.assertIn("updated_at", restored)

    def test_review_state_rejects_unsafe_case_url(self):
        state = {"schema_version": "1", "reports": {}}
        with self.assertRaises(ValueError):
            set_review(state, "report--1", "actioned", case_url="javascript:alert(1)")

    def test_publication_boundary_excludes_more_restrictive_tlp(self):
        items = [
            {"id": "clear", "tlp": "TLP:CLEAR"},
            {"id": "amber", "tlp": "TLP:AMBER"},
            {"id": "red", "tlp": "TLP:RED"},
        ]
        included, excluded = filter_by_tlp(items, "TLP:AMBER")
        self.assertEqual([item["id"] for item in included], ["clear", "amber"])
        self.assertEqual(excluded, 1)


if __name__ == "__main__":
    unittest.main()
