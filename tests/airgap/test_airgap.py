from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from planeon_distribution.airgap import AirgapError, export_archive, import_archive
from tests.airgap.helpers import evidence_map, released_fixture
from tests.signing.helpers import NOW


class AirgapRoundTripTests(unittest.TestCase):
    def test_two_zone_export_import_is_complete_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released = released_fixture(root)
            evidence = evidence_map(root, released)
            first = root / "export-zone-one.tar"
            second = root / "export-zone-two.tar"
            first_result = export_archive(released, evidence, first, NOW)
            second_result = export_archive(released, evidence, second, NOW)
            self.assertEqual(first_result, second_result)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            imported = root / "import-zone"
            receipt = import_archive(first, first_result["archiveDigest"], imported, NOW)
            self.assertEqual(receipt["state"], "VERIFIED_IMPORT")
            self.assertTrue((imported / "payload/bundle/oci/index.json").is_file())
            self.assertTrue((imported / "evidence/license-policy.json").is_file())
            self.assertEqual(len(list((imported / "evidence/sbom").glob("*.spdx.json"))), 2)

    def test_wrong_out_of_band_archive_digest_blocks_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released = released_fixture(root)
            archive = root / "transfer.tar"
            export_archive(released, evidence_map(root, released), archive, NOW)
            destination = root / "imported"
            with self.assertRaisesRegex(AirgapError, "ARCHIVE_DIGEST_MISMATCH"):
                import_archive(archive, "sha256:" + "0" * 64, destination, NOW)
            self.assertFalse(destination.exists())

    def test_missing_evidence_is_rejected_without_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released = released_fixture(root)
            evidence = evidence_map(root, released)
            evidence.pop("model-custody.json")
            destination = root / "transfer.tar"
            with self.assertRaisesRegex(AirgapError, "EVIDENCE_SET_INVALID"):
                export_archive(released, evidence, destination, NOW)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
