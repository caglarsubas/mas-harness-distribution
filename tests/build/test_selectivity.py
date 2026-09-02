from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.builder import build_bundle
from planeon_distribution.resolver import resolve_profile

ROOT = Path(__file__).resolve().parents[2]


class SelectivityProof(unittest.TestCase):
    def test_unselected_harness_is_absent_from_components_and_lock(self) -> None:
        source = ROOT / "fixtures/oci-layout"
        resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "bundle"
            build_bundle(resolution, source, destination)
            lock_text = (destination / "bundle.lock.json").read_text(encoding="utf-8")
            lock = json.loads(lock_text)
            self.assertEqual({component["kind"] for component in lock["components"]}, {"image", "chart"})
            self.assertEqual({component["platform"] for component in lock["components"]}, {"linux/arm64"})
            self.assertEqual(lock["selectedModules"], ["runtime.infrastructure"])
            self.assertNotIn("runtime.ai-gateway", lock_text)


if __name__ == "__main__":
    unittest.main()
