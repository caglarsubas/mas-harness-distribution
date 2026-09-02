"""Digest-preserving local relocation of a verified imported OCI layout."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .canonical import CanonicalJsonError, decode, encode
from .oci import layout_tree_digest, verify_layout

SCHEMA = "harness.planeon.ai/oci-relocation-receipt/v1alpha1"
TARGET_ID = re.compile(r"^[a-z][a-z0-9.-]{2,63}$")


class RelocationError(ValueError):
    pass


def _fail(code: str) -> None:
    raise RelocationError(code)


def _regular_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        _fail("RELOCATION_SOURCE_INVALID")
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()) or (path.is_file() and path.stat().st_nlink != 1):
            _fail("RELOCATION_SOURCE_INVALID")


def relocate(imported: Path, destination: Path, target_id: str, *, fail_before_publish: bool = False) -> dict[str, Any]:
    if not isinstance(target_id, str) or TARGET_ID.fullmatch(target_id) is None:
        _fail("RELOCATION_TARGET_INVALID")
    if destination.exists() or destination.is_symlink():
        _fail("RELOCATION_DESTINATION_EXISTS")
    try:
        receipt_bytes = (imported / "import.receipt.json").read_bytes()
        receipt = decode(receipt_bytes)
    except (OSError, CanonicalJsonError) as exc:
        raise RelocationError("IMPORT_RECEIPT_INVALID") from exc
    payload = {key: value for key, value in receipt.items() if key != "receiptDigest"} if isinstance(receipt, dict) else {}
    expected_receipt = "sha256:" + hashlib.sha256(encode(payload)).hexdigest()
    if not isinstance(receipt, dict) or receipt.get("state") != "VERIFIED_IMPORT" or receipt.get("receiptDigest") != expected_receipt:
        _fail("IMPORT_RECEIPT_INVALID")
    source = imported / "payload/bundle/oci"
    _regular_tree(source)
    verify_layout(source)
    source_digest = layout_tree_digest(source)
    if source_digest != receipt.get("ociLayoutDigest"):
        _fail("RELOCATION_SOURCE_DIGEST_MISMATCH")
    parent = destination.parent.resolve(strict=True)
    staging = Path(tempfile.mkdtemp(prefix=".planeon-relocation-", dir=parent))
    staging.chmod(0o700)
    try:
        shutil.copytree(source, staging / "oci", copy_function=shutil.copyfile)
        _regular_tree(staging / "oci")
        verify_layout(staging / "oci")
        destination_digest = layout_tree_digest(staging / "oci")
        if destination_digest != source_digest:
            _fail("RELOCATION_DIGEST_CHANGED")
        receipt_payload = {"importReceiptDigest": "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(), "releaseDigest": receipt["releaseDigest"], "schemaVersion": SCHEMA, "sourceOciDigest": source_digest, "targetId": target_id, "targetOciDigest": destination_digest}
        result = {**receipt_payload, "receiptDigest": "sha256:" + hashlib.sha256(encode(receipt_payload)).hexdigest()}
        (staging / "relocation.receipt.json").write_bytes(encode(result))
        if fail_before_publish:
            _fail("INJECTED_RELOCATION_FAILURE")
        os.replace(staging, parent / destination.name)
        return result
    finally:
        if staging.exists():
            shutil.rmtree(staging)
