"""Bounded verification for a local OCI image-layout fixture."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import CanonicalJsonError, decode, encode

MAX_FILES = 64
MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 8_388_608
MAX_DEPTH = 4
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
BLOB_NAME = re.compile(r"^[0-9a-f]{64}$")
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip"}


class LayoutError(ValueError):
    """Bounded validation failure whose string is a stable reason code."""


@dataclass(frozen=True, slots=True)
class Descriptor:
    digest: str
    size: int
    media_type: str


def _fail(code: str) -> None:
    raise LayoutError(code)


def _regular_files(root: Path) -> dict[str, Path]:
    try:
        root_info = os.lstat(root)
    except FileNotFoundError as exc:
        raise LayoutError("LAYOUT_UNAVAILABLE") from exc
    if stat.S_ISLNK(root_info.st_mode):
        _fail("SYMLINK_FORBIDDEN")
    if not stat.S_ISDIR(root_info.st_mode):
        _fail("LAYOUT_NOT_DIRECTORY")
    result: dict[str, Path] = {}
    total = 0
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if depth > MAX_DEPTH:
            _fail("PATH_DEPTH_EXCEEDED")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise LayoutError("LAYOUT_UNREADABLE") from exc
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            pure = PurePosixPath(relative)
            if pure.is_absolute() or ".." in pure.parts or any(part in {"", "."} for part in pure.parts):
                _fail("UNSAFE_PATH")
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise LayoutError("LAYOUT_UNREADABLE") from exc
            if stat.S_ISLNK(info.st_mode):
                _fail("SYMLINK_FORBIDDEN")
            if stat.S_ISDIR(info.st_mode):
                stack.append((Path(entry.path), depth + 1))
                continue
            if not stat.S_ISREG(info.st_mode):
                _fail("SPECIAL_FILE_FORBIDDEN")
            if info.st_size > MAX_FILE_BYTES:
                _fail("FILE_SIZE_EXCEEDED")
            total += info.st_size
            if total > MAX_TOTAL_BYTES:
                _fail("LAYOUT_SIZE_EXCEEDED")
            result[relative] = Path(entry.path)
            if len(result) > MAX_FILES:
                _fail("FILE_COUNT_EXCEEDED")
    return result


def _read(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise LayoutError("LAYOUT_UNREADABLE") from exc


def _closed_object(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _descriptor(value: Any, allowed_media: set[str], *, platform: bool) -> Descriptor:
    keys = {"digest", "mediaType", "size"} | ({"platform"} if platform else set())
    item = _closed_object(value, keys, "INVALID_DESCRIPTOR")
    match = DIGEST.fullmatch(item["digest"]) if isinstance(item.get("digest"), str) else None
    if match is None:
        _fail("INVALID_DIGEST")
    if item.get("mediaType") not in allowed_media:
        _fail("UNSUPPORTED_MEDIA_TYPE")
    if not isinstance(item.get("size"), int) or isinstance(item["size"], bool) or not 0 <= item["size"] <= MAX_FILE_BYTES:
        _fail("INVALID_DESCRIPTOR_SIZE")
    if platform:
        platform_value = _closed_object(item.get("platform"), {"architecture", "os"}, "INVALID_PLATFORM")
        if platform_value["architecture"] not in {"amd64", "arm64"} or platform_value["os"] != "linux":
            _fail("UNSUPPORTED_PLATFORM")
    return Descriptor(item["digest"], item["size"], item["mediaType"])


def _reject_mutable(value: Any) -> None:
    if isinstance(value, str) and (":latest" in value.casefold() or value.startswith(("http://", "https://"))):
        _fail("MUTABLE_OR_REMOTE_REFERENCE")
    if isinstance(value, list):
        for item in value:
            _reject_mutable(item)
    elif isinstance(value, dict):
        for item in value.values():
            _reject_mutable(item)


def _blob(files: dict[str, Path], descriptor: Descriptor) -> tuple[str, bytes]:
    hexadecimal = descriptor.digest.removeprefix("sha256:")
    relative = f"blobs/sha256/{hexadecimal}"
    path = files.get(relative)
    if path is None:
        _fail("MISSING_BLOB")
    data = _read(path)
    if len(data) != descriptor.size:
        _fail("BLOB_SIZE_MISMATCH")
    if hashlib.sha256(data).hexdigest() != hexadecimal:
        _fail("BLOB_DIGEST_MISMATCH")
    return relative, data


def verify_layout(root: str | os.PathLike[str]) -> dict[str, Any]:
    root_path = Path(root)
    if "://" in os.fspath(root):
        _fail("REMOTE_PATH_FORBIDDEN")
    files = _regular_files(root_path)
    if "oci-layout" not in files or "index.json" not in files:
        _fail("REQUIRED_FILE_MISSING")
    for relative in files:
        if relative in {"oci-layout", "index.json"}:
            continue
        parts = PurePosixPath(relative).parts
        if len(parts) != 3 or parts[:2] != ("blobs", "sha256") or BLOB_NAME.fullmatch(parts[2]) is None:
            _fail("UNEXPECTED_PATH")
    try:
        layout = decode(_read(files["oci-layout"]))
        index_bytes = _read(files["index.json"])
        index = decode(index_bytes)
    except CanonicalJsonError as exc:
        raise LayoutError(str(exc)) from exc
    _closed_object(layout, {"imageLayoutVersion"}, "INVALID_LAYOUT_DOCUMENT")
    if layout["imageLayoutVersion"] != "1.0.0":
        _fail("UNSUPPORTED_LAYOUT_VERSION")
    _closed_object(index, {"manifests", "mediaType", "schemaVersion"}, "INVALID_INDEX")
    if index["schemaVersion"] != 2 or index["mediaType"] != INDEX_MEDIA:
        _fail("INVALID_INDEX")
    if not isinstance(index["manifests"], list) or not 1 <= len(index["manifests"]) <= 16:
        _fail("INVALID_INDEX")
    _reject_mutable(index)
    root_descriptors = [_descriptor(item, {MANIFEST_MEDIA}, platform=True) for item in index["manifests"]]
    if len({item.digest for item in root_descriptors}) != len(root_descriptors):
        _fail("DUPLICATE_DESCRIPTOR")
    reachable: set[str] = set()
    descriptor_count = 0
    for manifest_descriptor in root_descriptors:
        relative, manifest_bytes = _blob(files, manifest_descriptor)
        reachable.add(relative)
        descriptor_count += 1
        try:
            manifest = decode(manifest_bytes)
        except CanonicalJsonError as exc:
            raise LayoutError(str(exc)) from exc
        _closed_object(manifest, {"config", "layers", "mediaType", "schemaVersion"}, "INVALID_MANIFEST")
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != MANIFEST_MEDIA:
            _fail("INVALID_MANIFEST")
        if not isinstance(manifest["layers"], list) or not 1 <= len(manifest["layers"]) <= 32:
            _fail("INVALID_MANIFEST")
        _reject_mutable(manifest)
        children = [_descriptor(manifest["config"], {CONFIG_MEDIA}, platform=False)]
        children.extend(_descriptor(item, LAYER_MEDIA, platform=False) for item in manifest["layers"])
        if len({item.digest for item in children}) != len(children):
            _fail("DUPLICATE_DESCRIPTOR")
        for child in children:
            child_relative, child_bytes = _blob(files, child)
            reachable.add(child_relative)
            descriptor_count += 1
            if child.media_type == CONFIG_MEDIA:
                try:
                    config = decode(child_bytes)
                except CanonicalJsonError as exc:
                    raise LayoutError(str(exc)) from exc
                _reject_mutable(config)
    actual_blobs = {path for path in files if path.startswith("blobs/")}
    if actual_blobs != reachable:
        _fail("UNREACHABLE_OR_EXTRA_BLOB")
    report = {
        "blobCount": len(reachable),
        "descriptorCount": descriptor_count,
        "indexDigest": f"sha256:{hashlib.sha256(index_bytes).hexdigest()}",
        "layoutVersion": "1.0.0",
        "schemaVersion": "harness.planeon.ai/oci-layout-verification/v1alpha1",
        "status": "VALID",
        "totalBytes": sum(path.stat().st_size for path in files.values()),
    }
    if encode(report).decode("utf-8").count("\n") != 1:
        _fail("REPORT_ENCODING_FAILED")
    return report


def selected_image_closure(root: str | os.PathLike[str], image_digests: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return selected index descriptors and their exact recursive blob closure."""
    root_path = Path(root)
    verify_layout(root_path)
    files = _regular_files(root_path)
    try:
        index = decode(_read(files["index.json"]))
    except CanonicalJsonError as exc:
        raise LayoutError(str(exc)) from exc
    selected = [item for item in index["manifests"] if item["digest"] in image_digests]
    if {item["digest"] for item in selected} != image_digests:
        _fail("IMAGE_ROOT_NOT_FOUND")
    records: dict[str, dict[str, Any]] = {}
    for item in selected:
        descriptor = _descriptor(item, {MANIFEST_MEDIA}, platform=True)
        _, manifest_bytes = _blob(files, descriptor)
        records[descriptor.digest] = {"digest": descriptor.digest, "mediaType": descriptor.media_type, "size": descriptor.size}
        try:
            manifest = decode(manifest_bytes)
        except CanonicalJsonError as exc:
            raise LayoutError(str(exc)) from exc
        children = [_descriptor(manifest["config"], {CONFIG_MEDIA}, platform=False)]
        children.extend(_descriptor(layer, LAYER_MEDIA, platform=False) for layer in manifest["layers"])
        for child in children:
            _blob(files, child)
            existing = records.get(child.digest)
            record = {"digest": child.digest, "mediaType": child.media_type, "size": child.size}
            if existing is not None and existing != record:
                _fail("CONFLICTING_BLOB_DESCRIPTOR")
            records[child.digest] = record
    return sorted(selected, key=lambda item: item["digest"]), sorted(records.values(), key=lambda item: item["digest"])


def layout_tree_digest(root: str | os.PathLike[str]) -> str:
    root_path = Path(root)
    files = _regular_files(root_path)
    digest = hashlib.sha256()
    for relative, path in sorted(files.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_read(path))
    return f"sha256:{digest.hexdigest()}"
