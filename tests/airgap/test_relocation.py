from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from planeon_distribution.airgap import export_archive, import_archive
from planeon_distribution.relocation import RelocationError, relocate
from tests.airgap.helpers import evidence_map, released_fixture
from tests.signing.helpers import NOW


def imported_fixture(root: Path) -> Path:
    released = released_fixture(root)
    archive = root / "transfer.tar"
    exported = export_archive(released, evidence_map(root, released), archive, NOW)
    imported = root / "imported"
    import_archive(archive, exported["archiveDigest"], imported, NOW)
    return imported


class RelocationTests(unittest.TestCase):
    def test_relocation_preserves_exact_oci_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            imported = imported_fixture(root)
            destination = root / "local-registry"
            receipt = relocate(imported, destination, "airgap-registry-one")
            self.assertEqual(receipt["sourceOciDigest"], receipt["targetOciDigest"])
            self.assertTrue((destination / "relocation.receipt.json").is_file())
            with self.assertRaisesRegex(RelocationError, "RELOCATION_DESTINATION_EXISTS"):
                relocate(imported, destination, "airgap-registry-one")

    def test_invalid_target_and_injected_failure_leave_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            imported = imported_fixture(root)
            with self.assertRaisesRegex(RelocationError, "RELOCATION_TARGET_INVALID"):
                relocate(imported, root / "bad", "https://registry.example")
            destination = root / "local-registry"
            with self.assertRaisesRegex(RelocationError, "INJECTED_RELOCATION_FAILURE"):
                relocate(imported, destination, "airgap-registry-one", fail_before_publish=True)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob(".planeon-relocation-*")), [])


if __name__ == "__main__":
    unittest.main()
