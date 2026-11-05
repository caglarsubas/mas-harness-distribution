from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.builder import BuildError, build_bundle
from planeon_distribution.canonical import encode
from planeon_distribution.resolver import resolve_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "fixtures/profiles/minimal-arm64.json"
SOURCE = ROOT / "fixtures/oci-layout"

# One clean build in a fresh interpreter: it prints the bundle id, the lock bytes' digest, and every file's
# path, mode and content digest, so the parent compares whole trees, not only the reported identifier.
CHILD = r"""
import hashlib, json, os, sys
from pathlib import Path
os.umask(int(sys.argv[4], 8))
from planeon_distribution.builder import build_bundle
from planeon_distribution.resolver import resolve_profile
profile, source, destination = (Path(item) for item in sys.argv[1:4])
result = build_bundle(resolve_profile(profile, source), source, destination)
files = {}
for path in sorted(item for item in destination.rglob("*") if item.is_file()):
    data = path.read_bytes()
    files[path.relative_to(destination).as_posix()] = {"mode": oct(path.stat().st_mode & 0o777), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
lock = (destination / "bundle.lock.json").read_bytes()
print(json.dumps({"bundleId": result["bundleId"], "files": files, "lockSha256": hashlib.sha256(lock).hexdigest(), "state": result["state"]}, sort_keys=True))
"""


def clean_inputs(root: Path, mode: int, mtime: int) -> tuple[Path, Path]:
    """Copy the profile and source layout byte for byte with different metadata."""
    source = root / "source-layout"
    for path in sorted(SOURCE.rglob("*")):
        target = source / path.relative_to(SOURCE)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(mode)
        os.utime(target, (mtime, mtime))
    profile = root / "profile.json"
    shutil.copyfile(PROFILE, profile)
    profile.chmod(mode)
    os.utime(profile, (mtime, mtime))
    return profile, source


def fresh_build(root: Path, *, mode: int, mtime: int, umask: str, seed: str, zone: str) -> dict[str, object]:
    profile, source = clean_inputs(root, mode, mtime)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": seed,
        "PYTHONPATH": str(ROOT / "src"),
        "TMPDIR": str(root),
        "TZ": zone,
    }
    completed = subprocess.run(
        [sys.executable, "-B", "-c", CHILD, str(profile), str(source), str(root / "bundle"), umask],
        cwd=root,
        env=environment,
        shell=False,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode:
        raise AssertionError("CLEAN_BUILD_FAILED:" + completed.stderr)
    return json.loads(completed.stdout)


class CleanRebuildTests(unittest.TestCase):
    def test_two_clean_builds_have_identical_root_digests_and_trees(self) -> None:
        with tempfile.TemporaryDirectory() as first_directory, tempfile.TemporaryDirectory() as second_directory:
            first = fresh_build(Path(first_directory), mode=0o644, mtime=0, umask="022", seed="1", zone="UTC")
            second = fresh_build(Path(second_directory), mode=0o600, mtime=1_790_000_000, umask="077", seed="4242", zone="Asia/Tokyo")
        self.assertEqual(first, second)
        self.assertEqual(first["state"], "BUILT_UNSIGNED")
        self.assertEqual(first["bundleId"], "sha256:" + first["lockSha256"])
        self.assertEqual(set(first["files"]), {"bundle.lock.json", "oci/index.json", "oci/oci-layout"} | {f"oci/blobs/sha256/{name}" for name in ("10047593289a87b166eb103ddfabb826131f86b8b70d6f48903b80e74e81ee7d", "ce46f075a74ac873c1fb23c8efa90d3f61de82726996b7dfa724a86c21c8b072", "f10a6334b74663490bf704d5b0fed54d6e17c1d48219acb16bcb6b13c6792915")})
        self.assertEqual({item["mode"] for item in first["files"].values()}, {"0o644"})

    def test_rebuild_identity_tracks_every_input_change(self) -> None:
        """The comparison is not vacuous: a changed profile changes the bundle id."""
        baseline = resolve_profile(PROFILE, SOURCE)
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        profile["profileId"] = profile["profileId"] + "-variant"
        payload = {key: value for key, value in profile.items() if key != "profileDigest"}
        profile["profileDigest"] = "sha256:" + hashlib.sha256(encode(payload)).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            variant_profile = root / "variant.json"
            variant_profile.write_bytes(encode(profile))
            first = build_bundle(baseline, SOURCE, root / "baseline")
            second = build_bundle(resolve_profile(variant_profile, SOURCE), SOURCE, root / "variant")
        self.assertNotEqual(first["bundleId"], second["bundleId"])

    def test_mutated_source_input_is_never_treated_as_reproducible(self) -> None:
        resolution = resolve_profile(PROFILE, SOURCE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, source = clean_inputs(root, 0o644, 0)
            blob = source / "blobs/sha256" / resolution["blobs"][0]["digest"].removeprefix("sha256:")
            data = bytearray(blob.read_bytes())
            data[0] ^= 0x01
            blob.write_bytes(bytes(data))
            destination = root / "bundle"
            with self.assertRaisesRegex(BuildError, "SOURCE_BLOB_CHANGED"):
                build_bundle(resolution, source, destination)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
