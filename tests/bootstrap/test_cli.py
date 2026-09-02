from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CliTests(unittest.TestCase):
    def run_cli(self, path: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run([sys.executable, "cmd/harness-bundlectl/verify.py", path], cwd=ROOT, env=environment, shell=False, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_valid_report_is_canonical_and_content_free(self) -> None:
        result = self.run_cli("fixtures/oci-layout")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "VALID")
        self.assertNotIn("/Users/", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_invalid_and_unavailable_exit_codes_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            invalid = self.run_cli(directory)
        unavailable = self.run_cli("fixtures/does-not-exist")
        self.assertEqual((invalid.returncode, invalid.stderr), (2, "REQUIRED_FILE_MISSING\n"))
        self.assertEqual((unavailable.returncode, unavailable.stderr), (3, "LAYOUT_UNAVAILABLE\n"))


if __name__ == "__main__":
    unittest.main()
