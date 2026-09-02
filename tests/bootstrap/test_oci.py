from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.oci import LayoutError, verify_layout

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/oci-layout"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class OciLayoutTests(unittest.TestCase):
    def test_valid_fixture_is_stable_and_immutable(self) -> None:
        before = tree_digest(FIXTURE)
        first = verify_layout(FIXTURE)
        second = verify_layout(FIXTURE)
        self.assertEqual(first, second)
        self.assertEqual(before, tree_digest(FIXTURE))
        self.assertEqual(first["status"], "VALID")
        self.assertEqual(first["blobCount"], 3)
        self.assertEqual(first["descriptorCount"], 3)
        self.assertEqual(first["indexDigest"], "sha256:cf42fa1a8b59cbd3cf3123b0d558fc04c5b1d8a00eba95acbff5161daa5cfdb4")

    def mutate(self, callback) -> str:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "layout"
            shutil.copytree(FIXTURE, target)
            callback(target)
            with self.assertRaises(LayoutError) as caught:
                verify_layout(target)
            return str(caught.exception)

    def test_missing_extra_and_tampered_blobs_are_denied(self) -> None:
        self.assertEqual(self.mutate(lambda root: next((root / "blobs/sha256").iterdir()).unlink()), "MISSING_BLOB")
        self.assertEqual(self.mutate(lambda root: (root / "blobs/sha256" / ("0" * 64)).write_bytes(b"extra")), "UNREACHABLE_OR_EXTRA_BLOB")
        manifest = "10047593289a87b166eb103ddfabb826131f86b8b70d6f48903b80e74e81ee7d"
        self.assertEqual(self.mutate(lambda root: (root / "blobs/sha256" / manifest).write_bytes(b"{}\n")), "BLOB_SIZE_MISMATCH")

    def test_noncanonical_duplicate_and_mutable_json_are_denied(self) -> None:
        self.assertEqual(self.mutate(lambda root: (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0", "x":1}\n', encoding="utf-8")), "NONCANONICAL_JSON")
        self.assertEqual(self.mutate(lambda root: (root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0","imageLayoutVersion":"1.0.0"}\n', encoding="utf-8")), "DUPLICATE_JSON_MEMBER")
        self.assertEqual(self.mutate(lambda root: (root / "index.json").write_bytes(encode({"manifests": [], "mediaType": "https://example.invalid:latest", "schemaVersion": 2}))), "INVALID_INDEX")

    def test_symlink_unexpected_and_remote_paths_are_denied(self) -> None:
        def link(root: Path) -> None:
            (root / "linked").symlink_to(root / "index.json")
        self.assertEqual(self.mutate(link), "SYMLINK_FORBIDDEN")
        self.assertEqual(self.mutate(lambda root: (root / "unexpected.txt").write_text("x", encoding="utf-8")), "UNEXPECTED_PATH")
        with self.assertRaisesRegex(LayoutError, "REMOTE_PATH_FORBIDDEN"):
            verify_layout("https://example.invalid/layout")

    def test_wrong_version_media_digest_size_and_duplicate_descriptor_are_denied(self) -> None:
        def change_index(root: Path, change) -> None:
            path = root / "index.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            change(value)
            path.write_bytes(encode(value))
        self.assertEqual(self.mutate(lambda root: change_index(root, lambda value: value.update(schemaVersion=3))), "INVALID_INDEX")
        self.assertEqual(self.mutate(lambda root: change_index(root, lambda value: value["manifests"][0].update(mediaType="application/unknown"))), "UNSUPPORTED_MEDIA_TYPE")
        self.assertEqual(self.mutate(lambda root: change_index(root, lambda value: value["manifests"][0].update(digest="sha256:ABC"))), "INVALID_DIGEST")
        self.assertEqual(self.mutate(lambda root: change_index(root, lambda value: value["manifests"][0].update(size=-1))), "INVALID_DESCRIPTOR_SIZE")
        self.assertEqual(self.mutate(lambda root: change_index(root, lambda value: value["manifests"].append(dict(value["manifests"][0])))), "DUPLICATE_DESCRIPTOR")


if __name__ == "__main__":
    unittest.main()
