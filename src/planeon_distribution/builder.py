"""Deterministic no-overwrite staging and publication for resolved bundles."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .canonical import encode
from .oci import INDEX_MEDIA, LayoutError, layout_tree_digest, verify_layout


class BuildError(ValueError):
    pass


def _fail(code: str) -> None:
    raise BuildError(code)


def _inside(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        return False


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o644)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_bundle(resolution: dict[str, Any], source_layout: Path, destination: Path, *, fail_before_publish: bool = False) -> dict[str, str]:
    source = source_layout.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        _fail("DESTINATION_EXISTS")
    destination_absolute = parent / destination.name
    if _inside(destination_absolute, source) or _inside(source, destination_absolute):
        _fail("SOURCE_DESTINATION_OVERLAP")
    staging = Path(tempfile.mkdtemp(prefix=".planeon-bundle-", dir=parent))
    staging.chmod(0o700)
    try:
        oci = staging / "oci"
        (oci / "blobs/sha256").mkdir(parents=True)
        _write(oci / "oci-layout", encode({"imageLayoutVersion": "1.0.0"}))
        index = {"manifests": resolution["indexManifests"], "mediaType": INDEX_MEDIA, "schemaVersion": 2}
        _write(oci / "index.json", encode(index))
        for blob in resolution["blobs"]:
            hexadecimal = blob["digest"].removeprefix("sha256:")
            source_blob = source / "blobs/sha256" / hexadecimal
            if source_blob.is_symlink() or not source_blob.is_file() or source_blob.stat().st_nlink != 1:
                _fail("AMBIGUOUS_SOURCE_BLOB")
            data = source_blob.read_bytes()
            if len(data) != blob["size"] or hashlib.sha256(data).hexdigest() != hexadecimal:
                _fail("SOURCE_BLOB_CHANGED")
            _write(oci / "blobs/sha256" / hexadecimal, data)
        try:
            verify_layout(oci)
        except LayoutError as exc:
            raise BuildError(str(exc)) from exc
        lock = {
            "blobs": resolution["blobs"],
            "components": resolution["components"],
            "ociLayoutDigest": layout_tree_digest(oci),
            "platforms": resolution["platforms"],
            "profileDigest": resolution["profileDigest"],
            "profileId": resolution["profileId"],
            "schemaVersion": "harness.planeon.ai/bundle-lock/v1alpha1",
            "selectedModules": resolution["selectedModules"],
            "sourceIndexDigest": resolution["sourceIndexDigest"],
            "state": "BUILT_UNSIGNED",
        }
        lock_bytes = encode(lock)
        _write(staging / "bundle.lock.json", lock_bytes)
        _fsync_directory(oci / "blobs/sha256")
        _fsync_directory(oci / "blobs")
        _fsync_directory(oci)
        _fsync_directory(staging)
        if fail_before_publish:
            _fail("INJECTED_PREPUBLISH_FAILURE")
        try:
            os.replace(staging, destination_absolute)
        except OSError as exc:
            raise BuildError("ATOMIC_PUBLISH_FAILED") from exc
        _fsync_directory(parent)
        return {"bundleId": f"sha256:{hashlib.sha256(lock_bytes).hexdigest()}", "state": "BUILT_UNSIGNED"}
    finally:
        if staging.exists():
            shutil.rmtree(staging)
