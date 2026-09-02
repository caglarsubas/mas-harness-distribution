"""Immutable no-overwrite promotion of a fully verified signed bundle."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .canonical import encode
from .signing import SigningError, verify_signed_release

RECORD_SCHEMA = "harness.planeon.ai/released-bundle-record/v1alpha1"


class PromotionError(ValueError):
    pass


def _fail(code: str) -> None:
    raise PromotionError(code)


def _regular_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        _fail("PROMOTION_SOURCE_INVALID")
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            _fail("PROMOTION_SOURCE_INVALID")
        if path.is_file() and path.stat().st_nlink != 1:
            _fail("PROMOTION_SOURCE_AMBIGUOUS")


def promote(bundle_directory: Path, signed_directory: Path, releases_root: Path, verification_time: str, *, fail_before_publish: bool = False) -> dict[str, Any]:
    _regular_tree(bundle_directory)
    _regular_tree(signed_directory)
    try:
        signed = verify_signed_release(signed_directory, verification_time)
    except SigningError as exc:
        raise PromotionError(str(exc)) from exc
    if (bundle_directory / "bundle.lock.json").read_bytes() != (signed_directory / "bundle.lock.json").read_bytes():
        _fail("PROMOTION_BUNDLE_MUTATED")
    if (bundle_directory / "supply-chain.evidence.json").read_bytes() != (signed_directory / "supply-chain.evidence.json").read_bytes():
        _fail("PROMOTION_EVIDENCE_MUTATED")
    root = releases_root.resolve(strict=True)
    destination = root / signed["releaseDigest"].removeprefix("sha256:")
    if destination.exists() or destination.is_symlink():
        _fail("RELEASE_DESTINATION_EXISTS")
    staging = Path(tempfile.mkdtemp(prefix=".planeon-release-", dir=root))
    staging.chmod(0o700)
    try:
        shutil.copytree(bundle_directory, staging / "bundle", copy_function=shutil.copyfile)
        shutil.copytree(signed_directory, staging / "release", copy_function=shutil.copyfile)
        _regular_tree(staging / "bundle")
        _regular_tree(staging / "release")
        verified = verify_signed_release(staging / "release", verification_time)
        if verified != signed or (staging / "bundle/bundle.lock.json").read_bytes() != (staging / "release/bundle.lock.json").read_bytes():
            _fail("PROMOTION_COPY_CHANGED")
        payload = {
            "organizationId": __import__("json").loads((staging / "release/release-manifest.json").read_text(encoding="utf-8"))["organizationId"],
            "promotedAt": verification_time,
            "releaseDigest": signed["releaseDigest"],
            "schemaVersion": RECORD_SCHEMA,
            "signedReleaseFileDigest": "sha256:" + hashlib.sha256((staging / "release/signed-release.json").read_bytes()).hexdigest(),
            "state": "RELEASED",
        }
        record = {**payload, "recordDigest": "sha256:" + hashlib.sha256(encode(payload)).hexdigest()}
        target = staging / "release.record.json"
        with target.open("xb") as stream:
            stream.write(encode(record))
            stream.flush()
            os.fsync(stream.fileno())
        if fail_before_publish:
            _fail("INJECTED_PROMOTION_FAILURE")
        os.replace(staging, destination)
        return record
    finally:
        if staging.exists():
            shutil.rmtree(staging)
