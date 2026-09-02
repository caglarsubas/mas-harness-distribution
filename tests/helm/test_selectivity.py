from __future__ import annotations

import re
import unittest

from tests.helm.helpers import EXPECTED, render, sources

ALL_MODULES = {"runtime-infrastructure", "model-inference", "ai-gateway", "data-integration", "control-overview"}


class SelectivityTests(unittest.TestCase):
    def test_disabled_subcharts_emit_no_resource_or_image_bytes(self) -> None:
        for profile, expected in EXPECTED.items():
            with self.subTest(profile=profile):
                output = render(profile).decode("utf-8")
                selected = set(expected["selectedModules"])
                self.assertEqual(sources(output.encode()), selected)
                for module in ALL_MODULES - selected:
                    self.assertNotIn(f"planeon-{module}", output)
                    self.assertNotIn(f"/{module}@sha256:", output)
                rendered_images = re.findall(r"image: \"([^\"]+)\"", output)
                self.assertEqual(len(rendered_images), len(selected))
                self.assertTrue(all(re.fullmatch(r"planeon\.local/[a-z0-9-]+@sha256:[0-9a-f]{64}", image) for image in rendered_images))

    def test_minimal_profiles_are_three_modules_only(self) -> None:
        exact = {"control-overview", "model-inference", "runtime-infrastructure"}
        self.assertEqual(set(EXPECTED["minimal-arm64"]["selectedModules"]), exact)
        self.assertEqual(set(EXPECTED["minimal-amd64"]["selectedModules"]), exact)
        self.assertEqual(set(EXPECTED["air-gap"]["selectedModules"]), exact)


if __name__ == "__main__":
    unittest.main()
