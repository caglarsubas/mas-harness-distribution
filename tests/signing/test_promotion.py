from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from planeon_distribution.promotion import PromotionError, promote
from planeon_distribution.signing import sign_candidate
from tests.signing.helpers import NOW, prepare


def signed_fixture(root: Path) -> tuple[dict[str, object], Path]:
    fixture = prepare(root)
    destination = root / "signed"
    sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], destination, NOW)
    return fixture, destination


class PromotionTests(unittest.TestCase):
    def test_signed_candidate_promotes_once_under_release_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, signed = signed_fixture(root)
            releases = root / "releases"
            releases.mkdir()
            record = promote(fixture["bundle"], signed, releases, NOW)
            destination = releases / record["releaseDigest"].removeprefix("sha256:")
            self.assertTrue((destination / "release.record.json").is_file())
            self.assertEqual(record["state"], "RELEASED")
            with self.assertRaisesRegex(PromotionError, "RELEASE_DESTINATION_EXISTS"):
                promote(fixture["bundle"], signed, releases, NOW)

    def test_mutated_bundle_is_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, signed = signed_fixture(root)
            (fixture["bundle"] / "bundle.lock.json").write_bytes(b"{}\n")
            releases = root / "releases"
            releases.mkdir()
            with self.assertRaisesRegex(PromotionError, "PROMOTION_BUNDLE_MUTATED"):
                promote(fixture["bundle"], signed, releases, NOW)
            self.assertEqual(list(releases.iterdir()), [])

    def test_injected_failure_cleans_private_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture, signed = signed_fixture(root)
            releases = root / "releases"
            releases.mkdir()
            with self.assertRaisesRegex(PromotionError, "INJECTED_PROMOTION_FAILURE"):
                promote(fixture["bundle"], signed, releases, NOW, fail_before_publish=True)
            self.assertEqual(list(releases.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
