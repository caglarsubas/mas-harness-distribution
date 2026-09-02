from __future__ import annotations

import unittest
from pathlib import Path

from planeon_distribution.helm import validate_vendored_charts
from planeon_distribution.oci import LayoutError
from planeon_distribution.resolver import resolve_profile

ROOT = Path(__file__).resolve().parents[2]


class HelmBoundaryTests(unittest.TestCase):
    def test_only_declared_local_layer_can_back_chart(self) -> None:
        source = ROOT / "fixtures/oci-layout"
        resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
        layers = {item["digest"] for item in resolution["blobs"] if ".layer." in item["mediaType"]}
        validate_vendored_charts(source, resolution["components"], layers)
        chart = next(dict(item) for item in resolution["components"] if item["kind"] == "chart")
        chart["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(LayoutError, "UNDECLARED_CHART_BLOB"):
            validate_vendored_charts(source, [chart], layers)


if __name__ == "__main__":
    unittest.main()
