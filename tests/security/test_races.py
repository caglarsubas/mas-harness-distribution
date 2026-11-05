"""Publication races: a writer that appears between the existence check and publication is never overwritten."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from planeon_distribution import airgap, builder, oci, promotion, relocation, signing
from planeon_distribution.oci import verify_layout
from planeon_distribution.resolver import resolve_profile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("run_supply_chain_campaign", ROOT / "scripts/run_supply_chain_campaign.py")
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)
MARKER = b"concurrent writer\n"


def racing(original: Callable[..., Any], race: Callable[[], None]) -> Callable[..., Any]:
    """Wrap ``original`` so the racer runs once, after the operation's own existence check."""
    state = {"done": False}

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not state["done"]:
            state["done"] = True
            race()
        return original(*args, **kwargs)

    return wrapper


def no_staging_left(test: unittest.TestCase, parent: Path) -> None:
    test.assertEqual([path.name for path in parent.iterdir() if path.name.startswith(".planeon-")], [])


class PublicationRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.base = campaign.prepare_base(Path(cls.directory.name) / "base")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def work(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def test_build_never_replaces_a_directory_created_during_the_build(self) -> None:
        root = self.work()
        destination = root / "bundle"
        source = ROOT / "fixtures/oci-layout"
        resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
        with mock.patch.object(builder, "layout_tree_digest", racing(oci.layout_tree_digest, lambda: destination.mkdir())):
            with self.assertRaisesRegex(builder.BuildError, "DESTINATION_EXISTS"):
                builder.build_bundle(resolution, source, destination)
        self.assertEqual(list(destination.iterdir()), [])
        no_staging_left(self, root)

    def test_concurrent_builds_publish_exactly_once(self) -> None:
        root = self.work()
        destination = root / "bundle"
        source = ROOT / "fixtures/oci-layout"
        resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
        barrier = threading.Barrier(2, timeout=30)
        outcomes: list[str] = []

        def synchronized(layout: Path) -> str:
            barrier.wait()
            return oci.layout_tree_digest(layout)

        def build() -> None:
            try:
                builder.build_bundle(resolution, source, destination)
                outcomes.append("PUBLISHED")
            except builder.BuildError as exc:
                outcomes.append(str(exc))

        with mock.patch.object(builder, "layout_tree_digest", synchronized):
            threads = [threading.Thread(target=build) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
        self.assertEqual(sorted(outcomes), ["DESTINATION_EXISTS", "PUBLISHED"])
        self.assertEqual(verify_layout(destination / "oci")["blobCount"], 3)
        no_staging_left(self, root)

    def test_signing_never_replaces_a_destination_created_during_signing(self) -> None:
        root = self.work()
        destination = root / "signed"
        base = self.base
        with mock.patch.object(signing, "verify_signed_release", racing(signing.verify_signed_release, lambda: destination.mkdir())):
            with self.assertRaisesRegex(signing.SigningError, "SIGNED_DESTINATION_EXISTS"):
                signing.sign_candidate(base["bundle"], base["approvalPath"], base["approvalBundle"], base["trustPath"], base["publicKeys"], base["releaseId"], base["releasePrivate"], destination, base["now"])
        self.assertEqual(list(destination.iterdir()), [])
        no_staging_left(self, root)

    def test_promotion_never_replaces_a_release_created_during_promotion(self) -> None:
        root = self.work()
        releases = root / "releases"
        releases.mkdir()
        digest = json.loads((self.base["signed"] / "signed-release.json").read_text(encoding="utf-8"))["releaseDigest"]
        target = releases / digest.removeprefix("sha256:")
        with mock.patch.object(promotion, "layout_tree_digest", racing(oci.layout_tree_digest, lambda: target.mkdir())):
            with self.assertRaisesRegex(promotion.PromotionError, "RELEASE_DESTINATION_EXISTS"):
                promotion.promote(self.base["bundle"], self.base["signed"], releases, self.base["now"])
        self.assertEqual([path.name for path in releases.iterdir()], [target.name])
        self.assertEqual(list(target.iterdir()), [])

    def test_export_never_overwrites_a_file_created_during_export(self) -> None:
        root = self.work()
        destination = root / "transfer.tar"
        with mock.patch.object(airgap, "_validate_evidence_map", racing(airgap._validate_evidence_map, lambda: destination.write_bytes(MARKER))):
            with self.assertRaisesRegex(airgap.AirgapError, "ARCHIVE_DESTINATION_EXISTS"):
                airgap.export_archive(self.base["released"], self.base["evidence"], destination, self.base["now"])
        self.assertEqual(destination.read_bytes(), MARKER)
        no_staging_left(self, root)

    def test_import_never_replaces_a_populated_destination_created_during_import(self) -> None:
        root = self.work()
        destination = root / "imported"

        def populate() -> None:
            destination.mkdir()
            (destination / "owner.txt").write_bytes(MARKER)

        with mock.patch.object(airgap, "_verify_import", racing(airgap._verify_import, populate)):
            with self.assertRaisesRegex(airgap.AirgapError, "IMPORT_DESTINATION_EXISTS"):
                airgap.import_archive(self.base["archive"], self.base["archiveDigest"], destination, self.base["now"])
        self.assertEqual((destination / "owner.txt").read_bytes(), MARKER)
        self.assertEqual([path.name for path in destination.iterdir()], ["owner.txt"])
        no_staging_left(self, root)

    def test_relocation_never_replaces_a_destination_created_during_relocation(self) -> None:
        root = self.work()
        imported = root / "imported"
        airgap.import_archive(self.base["archive"], self.base["archiveDigest"], imported, self.base["now"])
        destination = root / "relocated"
        with mock.patch.object(relocation, "layout_tree_digest", racing(oci.layout_tree_digest, lambda: destination.mkdir())):
            with self.assertRaisesRegex(relocation.RelocationError, "RELOCATION_DESTINATION_EXISTS"):
                relocation.relocate(imported, destination, "registry.local")
        self.assertEqual(list(destination.iterdir()), [])
        no_staging_left(self, root)


if __name__ == "__main__":
    unittest.main()
