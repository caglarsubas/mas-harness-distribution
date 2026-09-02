from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.resolver import ResolutionError, resolve_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "fixtures/profiles/minimal-arm64.json"
SOURCE = ROOT / "fixtures/oci-layout"


def with_digest(value: dict) -> dict:
    payload = {key: item for key, item in value.items() if key != "profileDigest"}
    value["profileDigest"] = f"sha256:{hashlib.sha256(encode(payload)).hexdigest()}"
    return value


class ResolverTests(unittest.TestCase):
    def candidate(self, change) -> str:
        value = json.loads(PROFILE.read_text(encoding="utf-8"))
        change(value)
        with_digest(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_bytes(encode(value))
            with self.assertRaises(ResolutionError) as caught:
                resolve_profile(path, SOURCE)
        return str(caught.exception)

    def test_minimal_profile_resolves_exact_selected_components(self) -> None:
        resolution = resolve_profile(PROFILE, SOURCE)
        self.assertEqual(resolution["selectedModules"], ["runtime.infrastructure"])
        self.assertEqual(resolution["platforms"], ["linux/arm64"])
        self.assertEqual([(item["moduleId"], item["kind"]) for item in resolution["components"]], [("runtime.infrastructure", "chart"), ("runtime.infrastructure", "image")])
        self.assertEqual(len(resolution["blobs"]), 3)
        self.assertNotIn("runtime.ai-gateway", json.dumps(resolution["components"]))

    def test_unselected_artifacts_and_empty_selection_are_denied(self) -> None:
        self.assertEqual(self.candidate(lambda value: value["modules"][1]["artifacts"].append(dict(value["modules"][0]["artifacts"][0]))), "UNSELECTED_MODULE_HAS_ARTIFACTS")
        self.assertEqual(self.candidate(lambda value: [module.update(selected=False, artifacts=[]) for module in value["modules"]]), "EMPTY_SELECTION")

    def test_platform_media_digest_size_and_duplicates_are_denied(self) -> None:
        self.assertEqual(self.candidate(lambda value: value["modules"][0]["artifacts"].pop(0)), "MISSING_PLATFORM_COVERAGE")
        self.assertEqual(self.candidate(lambda value: value["modules"][0]["artifacts"][0].update(mediaType="application/unknown")), "UNSUPPORTED_MEDIA_TYPE")
        self.assertEqual(self.candidate(lambda value: value["modules"][0]["artifacts"][0].update(digest="https://example.invalid:latest")), "INVALID_DIGEST")
        self.assertEqual(self.candidate(lambda value: value["modules"][0]["artifacts"][1].update(size=1)), "COMPONENT_DIGEST_OR_SIZE_MISMATCH")
        self.assertEqual(self.candidate(lambda value: value["modules"][0]["artifacts"].append(dict(value["modules"][0]["artifacts"][0]))), "DUPLICATE_ARTIFACT")

    def test_unknown_fields_noncanonical_and_changed_profile_digest_are_denied(self) -> None:
        self.assertEqual(self.candidate(lambda value: value.update(unknown=True)), "INVALID_PROFILE")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(PROFILE.read_text(encoding="utf-8").replace("\":", "\" :", 1), encoding="utf-8")
            with self.assertRaisesRegex(ResolutionError, "NONCANONICAL_JSON"):
                resolve_profile(path, SOURCE)
            path.write_bytes(PROFILE.read_bytes().replace(b"c6eb", b"a6eb", 1))
            with self.assertRaisesRegex(ResolutionError, "PROFILE_DIGEST_MISMATCH"):
                resolve_profile(path, SOURCE)

    def test_extra_source_blob_fails_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "oci"
            shutil.copytree(SOURCE, source)
            (source / "blobs/sha256" / ("0" * 64)).write_bytes(b"extra")
            with self.assertRaisesRegex(ResolutionError, "UNREACHABLE_OR_EXTRA_BLOB"):
                resolve_profile(PROFILE, source)


if __name__ == "__main__":
    unittest.main()
