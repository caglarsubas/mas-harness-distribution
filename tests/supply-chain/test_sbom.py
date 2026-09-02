from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from planeon_distribution.builder import build_bundle
from planeon_distribution.canonical import encode
from planeon_distribution.licenses import LicenseError, classify_expression, evaluate_license, load_policy
from planeon_distribution.resolver import resolve_profile
from planeon_distribution.sbom import SbomError, generate_spdx_bytes, load_inventory

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "fixtures/supply-chain"


class SbomAndLicenseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, _ = load_policy(ROOT / "policies/license-policy.json")

    def test_spdx_is_deterministic_and_describes_exact_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ROOT / "fixtures/oci-layout"
            destination = root / "bundle"
            build_bundle(resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source), source, destination)
            inventory, _, _ = load_inventory(destination / "bundle.lock.json", SUPPLY / "component-inventory.json")
            first = generate_spdx_bytes(inventory["components"][0])
            second = generate_spdx_bytes(inventory["components"][0])
            self.assertEqual(first, second)
            self.assertIn(b'"spdxVersion":"SPDX-2.3"', first)
            self.assertIn(inventory["components"][0]["artifactDigest"].removeprefix("sha256:").encode(), first)

    def test_license_denial_unknown_unresolved_and_review_fail_closed(self) -> None:
        for expression, code in [
            ("SSPL-1.0", "LICENSE_DENIED"),
            ("MadeUp-1.0", "LICENSE_UNKNOWN"),
            ("NOASSERTION", "LICENSE_UNRESOLVED"),
            ("AGPL-3.0-only", "LICENSE_REVIEW_REQUIRED"),
            ("", "LICENSE_MISSING_OR_MALFORMED"),
        ]:
            with self.subTest(expression=expression), self.assertRaisesRegex(LicenseError, code):
                classify_expression(expression, self.policy)

    def test_custody_requires_exact_evidence_and_generated_sbom(self) -> None:
        valid = {"notice": "sha256:" + "1" * 64, "sourceCommit": "sha256:" + "2" * 64}
        result = evaluate_license("Apache-2.0", "REPOSITORY_BUILT", valid, "sha256:" + "3" * 64, self.policy)
        self.assertEqual(result["classification"], "DEFAULT_ALLOWED")
        with self.assertRaisesRegex(LicenseError, "CUSTODY_EVIDENCE_INCOMPLETE"):
            evaluate_license("Apache-2.0", "REPOSITORY_BUILT", {}, "sha256:" + "3" * 64, self.policy)

    def test_inventory_extra_component_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ROOT / "fixtures/oci-layout"
            destination = root / "bundle"
            build_bundle(resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source), source, destination)
            import json
            inventory = json.loads((SUPPLY / "component-inventory.json").read_text())
            extra = dict(inventory["components"][0])
            extra["artifactDigest"] = "sha256:" + "9" * 64
            extra["purl"] = "pkg:generic/extra@0.1.0"
            extra["source"] = "urn:planeon:source:extra:" + extra["artifactDigest"]
            inventory["components"].append(extra)
            path = root / "inventory.json"
            path.write_bytes(encode(inventory))
            with self.assertRaisesRegex(SbomError, "COMPONENT_INVENTORY_INCOMPLETE_OR_EXTRA"):
                load_inventory(destination / "bundle.lock.json", path)


if __name__ == "__main__":
    unittest.main()
