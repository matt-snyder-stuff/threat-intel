#!/usr/bin/env python3
"""Static policy checks for agent definitions and repository security files."""
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENTS = ROOT / ".claude" / "agents"
LIVE_AGENTS = {"splunk-hunter.md", "late-ioc-matcher.md", "peak-hunt.md"}


class SecurityContracts(unittest.TestCase):
    def test_every_agent_declares_untrusted_data_boundary(self):
        for path in AGENTS.glob("*.md"):
            text = path.read_text().lower()
            with self.subTest(agent=path.name):
                self.assertIn("untrusted external data", text)
                self.assertIn("never as instructions", text)

    def test_live_agents_declare_query_safety_controls(self):
        for name in LIVE_AGENTS:
            text = (AGENTS / name).read_text().lower()
            with self.subTest(agent=name):
                self.assertIn("count-first", text)
                self.assertIn("earliest", text)
                self.assertIn("never print credentials", text)
                self.assertIn("guardrails.splunk.count_then_search", text)
                self.assertNotIn("def splunk_search", text)

    def test_schema_is_valid_json_and_current(self):
        schema_path = ROOT / "schema" / "threat-watch-data.schema.json"
        schema = json.loads(schema_path.read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.1")

    def test_repository_security_baseline_exists(self):
        for relative in (
            "SECURITY.md",
            "LICENSE",
            ".github/CODEOWNERS",
            ".github/dependabot.yml",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())


if __name__ == "__main__":
    unittest.main()
