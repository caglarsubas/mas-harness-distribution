"""Deterministic physical-transfer archive export and bounded safe import."""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .canonical import CanonicalJsonError, decode, encode
from .licenses import load_policy as load_license_policy
from .model_custody import validate_manifest
from .oci import layout_tree_digest, verify_layout
from .signing import verify_signed_release
from .vulnerabilities import load_database, load_dispositions, load_policy as load_vulnerability_policy

MANIFEST_SCHEMA = "harness.planeon.ai/airgap-transfer-manifest/v1alpha1"
RECEIPT_SCHEMA = "harness.planeon.ai/airgap-import-receipt/v1alpha1"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 512
MAX_PATH_BYTES = 240
MAX_DEPTH = 12
BASE_EVIDENCE = {"license-policy.json", "vulnerability-policy.json", "vulnerability-db.json", "dispositions.json", "model-custody.json"}
SBOM_NAME = re.compile(r"^sbom/[0-9a-f]{64}\.spdx\.json$")


class AirgapError(ValueError):
    pass


def _fail(code: str) -> None:
    raise AirgapError(code)


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _safe_name(value: str) -> str:
    if not value or not value.isascii() or "\\" in value or value.startswith("/") or len(value.encode()) > MAX_PATH_BYTES:
        _fail("ARCHIVE_PATH_INVALID")
    path = PurePosixPath(value)
    if len(path.parts) > MAX_DEPTH or any(part in {"", ".", ".."} for part in path.parts):
        _fail("ARCHIVE_PATH_INVALID")
    normalized = path.as_posix()
    if normalized != value:
        _fail("ARCHIVE_PATH_INVALID")
    return normalized


def _regular(path: Path, code: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        _fail(code)
    if path.stat().st_size > MAX_FILE_BYTES:
        _fail("ARCHIVE_FILE_TOO_LARGE")
    return path.read_bytes()


def _json(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    data = _regular(path, code)
    try:
        value = decode(data)
    except CanonicalJsonError as exc:
        raise AirgapError(code) from exc
    if not isinstance(value, dict):
        _fail(code)
    return value, data


def _release_subject(released: Path, verification_time: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    record, _ = _json(released / "release.record.json", "RELEASE_RECORD_INVALID")
    if record.get("schemaVersion") != "harness.planeon.ai/released-bundle-record/v1alpha1" or record.get("state") != "RELEASED":
        _fail("RELEASE_RECORD_INVALID")
    signed = verify_signed_release(released / "release", verification_time)
    if record.get("releaseDigest") != signed["releaseDigest"]:
        _fail("RELEASE_RECORD_SUBJECT_MISMATCH")
    lock, _ = _json(released / "bundle/bundle.lock.json", "BUNDLE_LOCK_INVALID")
    if (released / "bundle/bundle.lock.json").read_bytes() != (released / "release/bundle.lock.json").read_bytes():
        _fail("RELEASE_BUNDLE_MISMATCH")
    return record, signed, lock


def _collect_tree(root: Path, prefix: str) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        _fail("EXPORT_SOURCE_INVALID")
    result: dict[str, bytes] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = _safe_name(f"{prefix}/{path.relative_to(root).as_posix()}")
        result[relative] = _regular(path, "EXPORT_SOURCE_INVALID")
    return result


def _validate_evidence_map(evidence: Mapping[str, Path], released: Path) -> dict[str, bytes]:
    names = set(evidence)
    sbom_names = {name for name in names if SBOM_NAME.fullmatch(name)}
    if names - BASE_EVIDENCE - sbom_names or not BASE_EVIDENCE.issubset(names):
        _fail("EVIDENCE_SET_INVALID")
    supply, _ = _json(released / "bundle/supply-chain.evidence.json", "SUPPLY_CHAIN_EVIDENCE_INVALID")
    expected_sboms = {item["sbomDigest"].removeprefix("sha256:") for item in supply.get("components", [])}
    if sbom_names != {f"sbom/{digest}.spdx.json" for digest in expected_sboms}:
        _fail("EVIDENCE_SBOM_SET_MISMATCH")
    expected_digests = {
        "license-policy.json": supply.get("licensePolicyDigest"),
        "vulnerability-policy.json": supply.get("vulnerabilityPolicyDigest"),
        "vulnerability-db.json": supply.get("vulnerabilityDatabaseDigest"),
        "dispositions.json": supply.get("dispositionDigest"),
        "model-custody.json": supply.get("modelManifestDigest"),
    }
    result: dict[str, bytes] = {}
    for name, path in evidence.items():
        _safe_name(name)
        data = _regular(path, "EVIDENCE_SOURCE_INVALID")
        if name in expected_digests and _sha(data) != expected_digests[name]:
            _fail("EVIDENCE_DIGEST_MISMATCH")
        if name in sbom_names and _sha(data).removeprefix("sha256:") not in expected_sboms:
            _fail("EVIDENCE_SBOM_DIGEST_MISMATCH")
        lowered = data.lower()
        if any(marker in lowered for marker in (b"private key", b"cosign_password", b"api_key", b"secret key")):
            _fail("SECRET_MATERIAL_DETECTED")
        result[f"evidence/{name}"] = data
    return result


def export_archive(released: Path, evidence: Mapping[str, Path], destination: Path, verification_time: str) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        _fail("ARCHIVE_DESTINATION_EXISTS")
    parent = destination.parent.resolve(strict=True)
    record, signed, lock = _release_subject(released, verification_time)
    files = _collect_tree(released, "payload")
    files.update(_validate_evidence_map(evidence, released))
    if not files or len(files) > MAX_ENTRIES - 1 or sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES:
        _fail("ARCHIVE_LIMIT_EXCEEDED")
    entries = [{"path": name, "role": "EVIDENCE" if name.startswith("evidence/") else "RELEASE_PAYLOAD", "sha256": _sha(data), "size": len(data)} for name, data in sorted(files.items())]
    manifest = {
        "entries": entries,
        "limits": {"maxArchiveBytes": MAX_ARCHIVE_BYTES, "maxEntries": MAX_ENTRIES, "maxFileBytes": MAX_FILE_BYTES, "maxPathBytes": MAX_PATH_BYTES, "maxPathDepth": MAX_DEPTH, "maxTotalBytes": MAX_TOTAL_BYTES},
        "ociLayoutDigest": lock["ociLayoutDigest"],
        "releaseDigest": signed["releaseDigest"],
        "releaseRecordDigest": _sha((released / "release.record.json").read_bytes()),
        "schemaVersion": MANIFEST_SCHEMA,
        "verificationTime": verification_time,
    }
    files["transfer-manifest.json"] = encode(manifest)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".planeon-airgap-", suffix=".tar", dir=parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(_safe_name(name))
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            _fail("ARCHIVE_LIMIT_EXCEEDED")
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        archive_digest = _sha(temporary.read_bytes())
        os.replace(temporary, parent / destination.name)
        return {"archiveDigest": archive_digest, "entryCount": len(entries), "releaseDigest": signed["releaseDigest"]}
    finally:
        temporary.unlink(missing_ok=True)


def _inspect_archive(archive_path: Path, expected_digest: str) -> tuple[tarfile.TarFile, list[tarfile.TarInfo]]:
    data = _regular(archive_path, "ARCHIVE_UNAVAILABLE")
    if len(data) > MAX_ARCHIVE_BYTES:
        _fail("ARCHIVE_LIMIT_EXCEEDED")
    if expected_digest != _sha(data):
        _fail("ARCHIVE_DIGEST_MISMATCH")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        members = archive.getmembers()
    except tarfile.TarError as exc:
        raise AirgapError("ARCHIVE_FORMAT_INVALID") from exc
    if not members or len(members) > MAX_ENTRIES:
        archive.close()
        _fail("ARCHIVE_LIMIT_EXCEEDED")
    seen: set[str] = set()
    total = 0
    for member in members:
        name = _safe_name(member.name)
        if name in seen:
            archive.close()
            _fail("ARCHIVE_DUPLICATE_PATH")
        seen.add(name)
        if not member.isreg() or member.pax_headers or getattr(member, "sparse", None) or member.mode != 0o644 or member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
            archive.close()
            _fail("ARCHIVE_MEMBER_INVALID")
        if member.size < 0 or member.size > MAX_FILE_BYTES:
            archive.close()
            _fail("ARCHIVE_FILE_TOO_LARGE")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            archive.close()
            _fail("ARCHIVE_LIMIT_EXCEEDED")
    return archive, members


def _verify_import(staging: Path, manifest: Mapping[str, Any], verification_time: str) -> dict[str, Any]:
    released = staging / "payload"
    record, signed, lock = _release_subject(released, verification_time)
    if manifest.get("releaseDigest") != signed["releaseDigest"] or manifest.get("releaseRecordDigest") != _sha((released / "release.record.json").read_bytes()) or manifest.get("ociLayoutDigest") != lock["ociLayoutDigest"]:
        _fail("TRANSFER_SUBJECT_MISMATCH")
    oci_report = verify_layout(released / "bundle/oci")
    if layout_tree_digest(released / "bundle/oci") != lock["ociLayoutDigest"]:
        _fail("TRANSFER_OCI_DIGEST_MISMATCH")
    evidence_root = staging / "evidence"
    supply, _ = _json(released / "bundle/supply-chain.evidence.json", "SUPPLY_CHAIN_EVIDENCE_INVALID")
    license_policy, _ = load_license_policy(evidence_root / "license-policy.json")
    vulnerability_policy, _ = load_vulnerability_policy(evidence_root / "vulnerability-policy.json")
    database, _ = load_database(evidence_root / "vulnerability-db.json", vulnerability_policy)
    load_dispositions(evidence_root / "dispositions.json", vulnerability_policy)
    expected_models = sorted(item["modelId"] for item in supply.get("models", []))
    validate_manifest(evidence_root / "model-custody.json", supply["bundleLockDigest"], expected_models, license_policy)
    expected_components = {item["sbomDigest"]: item for item in supply.get("components", [])}
    actual_sboms: dict[str, dict[str, Any]] = {}
    for path in sorted((evidence_root / "sbom").glob("*.spdx.json")):
        document, data = _json(path, "SPDX_DOCUMENT_INVALID")
        actual_sboms[_sha(data)] = document
    if set(actual_sboms) != set(expected_components):
        _fail("EVIDENCE_SBOM_SET_MISMATCH")
    for digest, component in expected_components.items():
        document = actual_sboms[digest]
        if document.get("spdxVersion") != "SPDX-2.3" or len(document.get("packages", [])) != 1:
            _fail("SPDX_DOCUMENT_INVALID")
        checksums = document["packages"][0].get("checksums", [])
        if {item.get("checksumValue") for item in checksums if isinstance(item, dict)} != {component["artifactDigest"].removeprefix("sha256:")}:
            _fail("SPDX_SUBJECT_MISMATCH")
    return {"ociBlobCount": oci_report["blobCount"], "releaseDigest": signed["releaseDigest"]}


def import_archive(archive_path: Path, expected_digest: str, destination: Path, verification_time: str) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        _fail("IMPORT_DESTINATION_EXISTS")
    parent = destination.parent.resolve(strict=True)
    archive, members = _inspect_archive(archive_path, expected_digest)
    staging = Path(tempfile.mkdtemp(prefix=".planeon-import-", dir=parent))
    staging.chmod(0o700)
    try:
        member_map = {member.name: member for member in members}
        manifest_member = member_map.get("transfer-manifest.json")
        if manifest_member is None:
            _fail("TRANSFER_MANIFEST_MISSING")
        manifest_stream = archive.extractfile(manifest_member)
        if manifest_stream is None:
            _fail("TRANSFER_MANIFEST_INVALID")
        try:
            manifest = decode(manifest_stream.read(MAX_FILE_BYTES + 1))
        except CanonicalJsonError as exc:
            raise AirgapError("TRANSFER_MANIFEST_INVALID") from exc
        if not isinstance(manifest, dict) or set(manifest) != {"entries", "limits", "ociLayoutDigest", "releaseDigest", "releaseRecordDigest", "schemaVersion", "verificationTime"} or manifest["schemaVersion"] != MANIFEST_SCHEMA or manifest["verificationTime"] != verification_time:
            _fail("TRANSFER_MANIFEST_INVALID")
        expected_limits = {"maxArchiveBytes": MAX_ARCHIVE_BYTES, "maxEntries": MAX_ENTRIES, "maxFileBytes": MAX_FILE_BYTES, "maxPathBytes": MAX_PATH_BYTES, "maxPathDepth": MAX_DEPTH, "maxTotalBytes": MAX_TOTAL_BYTES}
        if manifest["limits"] != expected_limits or not isinstance(manifest["entries"], list):
            _fail("TRANSFER_MANIFEST_INVALID")
        entries: dict[str, dict[str, Any]] = {}
        for raw in manifest["entries"]:
            if not isinstance(raw, dict) or set(raw) != {"path", "role", "sha256", "size"} or raw["role"] not in {"EVIDENCE", "RELEASE_PAYLOAD"}:
                _fail("TRANSFER_ENTRY_INVALID")
            name = _safe_name(raw["path"])
            if name in entries or not isinstance(raw["size"], int) or isinstance(raw["size"], bool) or raw["size"] < 0 or raw["size"] > MAX_FILE_BYTES:
                _fail("TRANSFER_ENTRY_INVALID")
            entries[name] = raw
        if set(member_map) - {"transfer-manifest.json"} != set(entries):
            _fail("TRANSFER_CLOSURE_MISMATCH")
        for name in sorted(entries):
            member = member_map[name]
            stream = archive.extractfile(member)
            if stream is None:
                _fail("ARCHIVE_MEMBER_INVALID")
            data = stream.read(member.size + 1)
            if len(data) != member.size or entries[name]["size"] != len(data) or entries[name]["sha256"] != _sha(data):
                _fail("TRANSFER_CHECKSUM_MISMATCH")
            target = staging.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with target.open("xb") as output:
                output.write(data)
        report = _verify_import(staging, manifest, verification_time)
        receipt_payload = {"archiveDigest": expected_digest, "ociLayoutDigest": manifest["ociLayoutDigest"], "releaseDigest": report["releaseDigest"], "schemaVersion": RECEIPT_SCHEMA, "state": "VERIFIED_IMPORT", "verificationTime": verification_time}
        receipt = {**receipt_payload, "receiptDigest": _sha(encode(receipt_payload))}
        (staging / "import.receipt.json").write_bytes(encode(receipt))
        os.replace(staging, parent / destination.name)
        return receipt
    finally:
        archive.close()
        if staging.exists():
            shutil.rmtree(staging)
