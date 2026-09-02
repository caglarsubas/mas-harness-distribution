from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ci.validate_porting import EXPECTED, validate
from ci.zero_bill_scan import scan

ROOT = Path(__file__).resolve().parents[2]


class BoundaryTests(unittest.TestCase):
    def test_porting_is_exact_inert_sentinel(self) -> None:
        validate(ROOT / "PORTING.yaml")
        self.assertEqual(json.loads((ROOT / "PORTING.yaml").read_text(encoding="utf-8")), EXPECTED)
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "PORTING.yaml"
            candidate.write_text(json.dumps({**EXPECTED, "source": "forbidden"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "PORTING_AUTHORIZATION_PRESENT"):
                validate(candidate)

    def test_zero_bill_scanner_accepts_repo_and_rejects_hosted_runner(self) -> None:
        self.assertEqual(scan(ROOT), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows"
            workflow.mkdir(parents=True)
            (workflow / "verify.yml").write_text("runs-on: ubuntu-latest\n", encoding="utf-8")
            failures = scan(root)
            self.assertTrue(any(value.startswith("HOSTED_RUNNER:") for value in failures))

    def test_toolchain_lock_is_closed_and_dependency_free(self) -> None:
        lock = json.loads((ROOT / "toolchain.lock").read_text(encoding="utf-8"))
        self.assertEqual(set(lock), {"authorities", "planningBase", "schemaVersion", "tools"})
        self.assertEqual(set(lock["tools"]), {"python", "uv"})
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", project)


if __name__ == "__main__":
    unittest.main()
