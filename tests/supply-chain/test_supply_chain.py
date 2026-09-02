from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.builder import build_bundle
from planeon_distribution.resolver import resolve_profile
from planeon_distribution.sbom import SbomError, build_evidence, publish_evidence

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "fixtures/supply-chain"


def build_fixture(root: Path) -> Path:
    destination = root / "bundle"
    source = ROOT / "fixtures/oci-layout"
    resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
    build_bundle(resolution, source, destination)
    return destination


def evidence(bundle: Path) -> dict[str, object]:
    return build_evidence(
        bundle / "bundle.lock.json",
        SUPPLY / "component-inventory.json",
        ROOT / "policies/license-policy.json",
        ROOT / "policies/vulnerability-policy.json",
        SUPPLY / "vulnerability-db.json",
        SUPPLY / "dispositions.json",
        SUPPLY / "model-custody.json",
    )


class SupplyChainTests(unittest.TestCase):
    def test_evidence_is_reproducible_complete_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = build_fixture(Path(directory))
            first = evidence(bundle)
            second = evidence(bundle)
            self.assertEqual(first, second)
            self.assertEqual(first["state"], "SCANNED")
            self.assertEqual(len(first["components"]), 2)
            self.assertEqual(first["models"], [])
            self.assertNotIn("signature", first)
            self.assertNotIn("released", first)
            payload = {key: value for key, value in first.items() if key != "evidenceDigest"}
            from planeon_distribution.canonical import encode
            self.assertEqual(first["evidenceDigest"], "sha256:" + hashlib.sha256(encode(payload)).hexdigest())

    def test_high_finding_remains_visible_with_exact_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = evidence(build_fixture(Path(directory)))
            chart = next(item for item in record["components"] if item["kind"] == "chart")
            self.assertEqual(chart["vulnerabilities"], [{
                "descriptionDigest": "sha256:" + "2" * 64,
                "disposition": "ACCEPTED_RISK",
                "id": "CVE-2099-0002",
                "severity": "HIGH",
            }])

    def test_publish_is_create_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = evidence(build_fixture(root))
            target = root / "supply-chain.evidence.json"
            first = publish_evidence(record, target)
            self.assertTrue(target.is_file())
            self.assertEqual(first, "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest())
            with self.assertRaisesRegex(SbomError, "EVIDENCE_DESTINATION_EXISTS"):
                publish_evidence(record, target)


if __name__ == "__main__":
    unittest.main()
