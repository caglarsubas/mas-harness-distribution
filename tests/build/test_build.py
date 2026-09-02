from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.builder import BuildError, build_bundle
from planeon_distribution.oci import verify_layout
from planeon_distribution.resolver import resolve_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "fixtures/profiles/minimal-arm64.json"
SOURCE = ROOT / "fixtures/oci-layout"


def directory_digest(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        digest.update(item.relative_to(path).as_posix().encode())
        digest.update(b"\0")
        digest.update(item.read_bytes())
    return digest.hexdigest()


class BuildTests(unittest.TestCase):
    def test_two_clean_builds_are_byte_identical_and_unsigned(self) -> None:
        resolution = resolve_profile(PROFILE, SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one"
            second = root / "two"
            first_result = build_bundle(resolution, SOURCE, first)
            second_result = build_bundle(resolution, SOURCE, second)
            self.assertEqual(first_result, second_result)
            self.assertEqual(directory_digest(first), directory_digest(second))
            self.assertEqual(verify_layout(first / "oci")["blobCount"], 3)
            lock = json.loads((first / "bundle.lock.json").read_text(encoding="utf-8"))
            self.assertEqual(lock["state"], "BUILT_UNSIGNED")
            self.assertEqual(lock["selectedModules"], ["runtime.infrastructure"])
            self.assertNotIn("signature", lock)
            self.assertNotIn("released", lock)

    def test_existing_destination_and_source_overlap_are_denied(self) -> None:
        resolution = resolve_profile(PROFILE, SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(BuildError, "DESTINATION_EXISTS"):
                build_bundle(resolution, SOURCE, existing)
        with self.assertRaisesRegex(BuildError, "SOURCE_DESTINATION_OVERLAP"):
            build_bundle(resolution, SOURCE, SOURCE / "candidate")

    def test_injected_failure_leaves_no_destination_or_candidate(self) -> None:
        resolution = resolve_profile(PROFILE, SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "bundle"
            with self.assertRaisesRegex(BuildError, "INJECTED_PREPUBLISH_FAILURE"):
                build_bundle(resolution, SOURCE, destination, fail_before_publish=True)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
