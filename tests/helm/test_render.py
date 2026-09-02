from __future__ import annotations

import subprocess
import unittest

from tests.helm.helpers import CHART, EXPECTED, HELM, PROFILES, documents, render, sources, verify_helm


class RenderMatrixTests(unittest.TestCase):
    def test_all_six_profiles_render_deterministically_with_exact_inventory(self) -> None:
        self.assertEqual(sorted(EXPECTED), ["air-gap", "bridge", "minimal-amd64", "minimal-arm64", "regulated-openshift", "silo"])
        for profile, expected in EXPECTED.items():
            with self.subTest(profile=profile):
                first = render(profile)
                second = render(profile)
                self.assertEqual(first, second)
                self.assertEqual(sources(first), set(expected["selectedModules"]))
                self.assertEqual(len(documents(first)), 1 + 4 * len(expected["selectedModules"]))
                self.assertIn(b"kind: NetworkPolicy", first)
                self.assertIn(f'kubernetes.io/arch: "{expected["architecture"]}"'.encode(), first)

    def test_chart_lints_locally_without_dependency_update(self) -> None:
        verify_helm()
        for profile in EXPECTED:
            completed = subprocess.run([str(HELM), "lint", str(CHART), "--values", str(PROFILES / f"{profile}.yaml")], shell=False, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"HOME": "/tmp", "PATH": "/opt/planeon/bin:/usr/bin:/bin"})
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
