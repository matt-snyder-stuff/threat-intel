#!/usr/bin/env python3
"""Tests for deployable detection artifact validation."""

import pathlib
import tempfile
import unittest

from tools.validate_detections import validate_directory, validate_sigma, validate_spl


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DetectionArtifactTests(unittest.TestCase):
    def test_repository_examples_are_valid(self):
        paths, errors = validate_directory(ROOT / "detections")
        self.assertGreaterEqual(len(paths), 2)
        self.assertEqual(errors, [])

    def test_invalid_sigma_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.yml"
            path.write_text("title: incomplete\n")
            with self.assertRaises(ValueError):
                validate_sigma(path)

    def test_unbounded_or_writing_spl_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "bad.spl"
            path.write_text("index=cloud | outputlookup unsafe.csv\n")
            with self.assertRaises(ValueError):
                validate_spl(path)


if __name__ == "__main__":
    unittest.main()
