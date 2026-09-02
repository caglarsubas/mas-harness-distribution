"""Offline Cosign signing with role-scoped local trust and revocation."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import CanonicalJsonError, decode, encode

COSIGN = Path("/opt/planeon/bin/cosign")
COSIGN_SHA256 = "e1775d26440ce3f57a95599d34d2b976c6400e06d1b31b6bea927f4857e3fe18"
TRUST_SCHEMA = "harness.planeon.ai/release-trust-bundle/v1alpha1"
APPROVAL_SCHEMA = "harness.planeon.ai/release-approval/v1alpha1"
MANIFEST_SCHEMA = "harness.planeon.ai/release-signing-manifest/v1alpha1"
COMPONENT_SCHEMA = "harness.planeon.ai/component-attestation/v1alpha1"
SIGNED_SCHEMA = "harness.planeon.ai/signed-release/v1alpha1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
KEY_ID = re.compile(r"^key-[0-9a-f]{16}$")
ROLES = {"BUNDLE_RELEASE", "RELEASE_APPROVAL"}


class SigningError(ValueError):
    pass


def _fail(code: str) -> None:
    raise SigningError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _read(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        _fail(code)
    try:
        data = path.read_bytes()
        value = decode(data)
    except (OSError, CanonicalJsonError) as exc:
        raise SigningError(code) from exc
    if not isinstance(value, dict):
        _fail(code)
    return value, data


def _file_bytes(path: Path, code: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        _fail(code)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SigningError(code) from exc


def _instant(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise SigningError(code) from exc
    if parsed.tzinfo != timezone.utc or parsed.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" != value:
        _fail(code)
    return parsed


def _write(path: Path, value: Mapping[str, Any] | bytes, mode: int = 0o600) -> None:
    data = value if isinstance(value, bytes) else encode(dict(value))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def verify_cosign_binary() -> None:
    if COSIGN.is_symlink() or not COSIGN.is_file() or COSIGN.stat().st_uid != 0 or COSIGN.stat().st_mode & 0o022:
        _fail("COSIGN_BINARY_UNTRUSTED")
    if hashlib.sha256(COSIGN.read_bytes()).hexdigest() != COSIGN_SHA256:
        _fail("COSIGN_BINARY_DIGEST_MISMATCH")


def _cosign(arguments: list[str], *, password: str | None = None) -> None:
    verify_cosign_binary()
    environment = {"HOME": tempfile.gettempdir(), "PATH": "/opt/planeon/bin:/usr/bin:/bin"}
    if password is not None:
        environment["COSIGN_PASSWORD"] = password
    completed = subprocess.run([str(COSIGN), *arguments], shell=False, check=False, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.returncode:
        _fail("COSIGN_OPERATION_FAILED")


def sign_blob(payload: Path, private_key: Path, signature_bundle: Path, *, password: str = "") -> None:
    if private_key.is_symlink() or not private_key.is_file() or private_key.stat().st_mode & 0o077:
        _fail("PRIVATE_KEY_CUSTODY_INVALID")
    if signature_bundle.exists() or signature_bundle.is_symlink():
        _fail("SIGNATURE_DESTINATION_EXISTS")
    _cosign(["sign-blob", "--yes", "--tlog-upload=false", "--use-signing-config=false", "--key", str(private_key), "--bundle", str(signature_bundle), str(payload)], password=password)
    if signature_bundle.is_symlink() or not signature_bundle.is_file():
        _fail("SIGNATURE_NOT_CREATED")
    signature_bundle.chmod(0o644)


def verify_blob(payload: Path, public_key: Path, signature_bundle: Path) -> None:
    if any(path.is_symlink() or not path.is_file() for path in (payload, public_key, signature_bundle)):
        _fail("SIGNATURE_INPUT_INVALID")
    _cosign(["verify-blob", "--offline", "--insecure-ignore-tlog", "--key", str(public_key), "--bundle", str(signature_bundle), str(payload)])


def load_trust(path: Path, public_keys: Mapping[str, Path], role: str, key_id: str, verification_time: str, *, minimum_sequence: int = 1) -> tuple[dict[str, Any], str, Path]:
    trust, data = _read(path, "TRUST_BUNDLE_INVALID")
    trust = _closed(trust, {"keys", "revocations", "schemaVersion", "sequence", "trustBundleDigest"}, "TRUST_BUNDLE_INVALID")
    payload = {name: value for name, value in trust.items() if name != "trustBundleDigest"}
    if trust["schemaVersion"] != TRUST_SCHEMA or trust["trustBundleDigest"] != _sha(encode(payload)):
        _fail("TRUST_BUNDLE_DIGEST_MISMATCH")
    if not isinstance(minimum_sequence, int) or isinstance(minimum_sequence, bool) or minimum_sequence < 1 or not isinstance(trust["sequence"], int) or isinstance(trust["sequence"], bool) or trust["sequence"] < minimum_sequence:
        _fail("TRUST_SEQUENCE_INVALID")
    if role not in ROLES or not isinstance(trust["keys"], list) or not trust["keys"]:
        _fail("TRUST_BUNDLE_INVALID")
    key_records: dict[str, dict[str, Any]] = {}
    expected_files: set[str] = set()
    for raw in trust["keys"]:
        record = _closed(raw, {"keyId", "notAfter", "notBefore", "publicKeyDigest", "publicKeyFile", "roles", "state"}, "TRUST_KEY_INVALID")
        if not isinstance(record["keyId"], str) or KEY_ID.fullmatch(record["keyId"]) is None or record["keyId"] in key_records:
            _fail("TRUST_KEY_DUPLICATE_OR_INVALID")
        roles = record["roles"]
        if not isinstance(roles, list) or roles != sorted(set(roles)) or not roles or set(roles) - ROLES:
            _fail("TRUST_ROLE_INVALID")
        if record["state"] not in {"ACTIVE", "RETIRING"} or _instant(record["notBefore"], "TRUST_TIME_INVALID") >= _instant(record["notAfter"], "TRUST_TIME_INVALID"):
            _fail("TRUST_KEY_INVALID")
        expected_file = f"public-keys/{record['keyId']}.pub"
        if record["publicKeyFile"] != expected_file or not isinstance(record["publicKeyDigest"], str) or DIGEST.fullmatch(record["publicKeyDigest"]) is None:
            _fail("TRUST_KEY_INVALID")
        key_records[record["keyId"]] = record
        expected_files.add(record["keyId"])
    if set(public_keys) != expected_files:
        _fail("TRUST_PUBLIC_KEY_SET_MISMATCH")
    for candidate_id, candidate_path in public_keys.items():
        if candidate_path.is_symlink() or not candidate_path.is_file() or _sha(candidate_path.read_bytes()) != key_records[candidate_id]["publicKeyDigest"]:
            _fail("TRUST_PUBLIC_KEY_DIGEST_MISMATCH")
    if not isinstance(trust["revocations"], list):
        _fail("TRUST_BUNDLE_INVALID")
    revocations: dict[str, datetime] = {}
    for raw in trust["revocations"]:
        revocation = _closed(raw, {"effectiveAt", "keyId", "reasonDigest"}, "TRUST_REVOCATION_INVALID")
        if revocation["keyId"] not in key_records or revocation["keyId"] in revocations or not isinstance(revocation["reasonDigest"], str) or DIGEST.fullmatch(revocation["reasonDigest"]) is None:
            _fail("TRUST_REVOCATION_INVALID")
        revocations[revocation["keyId"]] = _instant(revocation["effectiveAt"], "TRUST_REVOCATION_INVALID")
    selected = key_records.get(key_id)
    if selected is None or role not in selected["roles"]:
        _fail("TRUST_KEY_OR_ROLE_NOT_ADMITTED")
    instant = _instant(verification_time, "TRUST_VERIFICATION_TIME_INVALID")
    if not (_instant(selected["notBefore"], "TRUST_TIME_INVALID") <= instant < _instant(selected["notAfter"], "TRUST_TIME_INVALID")):
        _fail("TRUST_KEY_OUTSIDE_VALIDITY")
    if key_id in revocations and revocations[key_id] <= instant:
        _fail("TRUST_KEY_REVOKED")
    return trust, _sha(data), public_keys[key_id]


def validate_approval(
    approval_path: Path,
    approval_bundle: Path,
    trust_path: Path,
    public_keys: Mapping[str, Path],
    bundle_lock_digest: str,
    evidence_digest: str,
    verification_time: str,
) -> tuple[dict[str, Any], str]:
    approval, data = _read(approval_path, "RELEASE_APPROVAL_INVALID")
    approval = _closed(approval, {"approvalDigest", "approvalKeyId", "authority", "authorizedReleaseKeyIds", "bundleLockDigest", "evidenceDigest", "notAfter", "notBefore", "organizationId", "profileId", "schemaVersion", "trustBundleDigest"}, "RELEASE_APPROVAL_INVALID")
    payload = {name: value for name, value in approval.items() if name != "approvalDigest"}
    if approval["schemaVersion"] != APPROVAL_SCHEMA or approval["approvalDigest"] != _sha(encode(payload)):
        _fail("RELEASE_APPROVAL_DIGEST_MISMATCH")
    if approval["bundleLockDigest"] != bundle_lock_digest or approval["evidenceDigest"] != evidence_digest:
        _fail("RELEASE_APPROVAL_SUBJECT_MISMATCH")
    authorized = approval["authorizedReleaseKeyIds"]
    if not isinstance(authorized, list) or authorized != sorted(set(authorized)) or not authorized:
        _fail("RELEASE_APPROVAL_KEY_SET_INVALID")
    instant = _instant(verification_time, "RELEASE_APPROVAL_TIME_INVALID")
    if not (_instant(approval["notBefore"], "RELEASE_APPROVAL_TIME_INVALID") <= instant < _instant(approval["notAfter"], "RELEASE_APPROVAL_TIME_INVALID")):
        _fail("RELEASE_APPROVAL_EXPIRED")
    trust, trust_digest, approval_public = load_trust(trust_path, public_keys, "RELEASE_APPROVAL", approval["approvalKeyId"], verification_time)
    if approval["trustBundleDigest"] != trust["trustBundleDigest"]:
        _fail("RELEASE_APPROVAL_TRUST_MISMATCH")
    verify_blob(approval_path, approval_public, approval_bundle)
    return approval, _sha(data)


def _public_key_map(trust_path: Path) -> dict[str, Path]:
    trust, _ = _read(trust_path, "TRUST_BUNDLE_INVALID")
    if not isinstance(trust.get("keys"), list):
        _fail("TRUST_BUNDLE_INVALID")
    return {record["keyId"]: trust_path.parent / record["publicKeyFile"] for record in trust["keys"] if isinstance(record, dict) and isinstance(record.get("keyId"), str) and isinstance(record.get("publicKeyFile"), str)}


def sign_candidate(
    bundle_directory: Path,
    approval_path: Path,
    approval_bundle: Path,
    trust_path: Path,
    public_keys: Mapping[str, Path],
    release_key_id: str,
    private_key: Path,
    destination: Path,
    verification_time: str,
    *,
    password: str = "",
) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink():
        _fail("SIGNED_DESTINATION_EXISTS")
    parent = destination.parent.resolve(strict=True)
    lock, lock_bytes = _read(bundle_directory / "bundle.lock.json", "BUNDLE_LOCK_INVALID")
    evidence, evidence_bytes = _read(bundle_directory / "supply-chain.evidence.json", "SUPPLY_CHAIN_EVIDENCE_INVALID")
    lock_digest, evidence_digest = _sha(lock_bytes), _sha(evidence_bytes)
    if lock.get("state") != "BUILT_UNSIGNED" or evidence.get("state") != "SCANNED" or evidence.get("bundleLockDigest") != lock_digest:
        _fail("SIGNING_STATE_INVALID")
    approval, approval_file_digest = validate_approval(approval_path, approval_bundle, trust_path, public_keys, lock_digest, evidence_digest, verification_time)
    if approval["profileId"] != lock.get("profileId") or release_key_id not in approval["authorizedReleaseKeyIds"]:
        _fail("RELEASE_APPROVAL_SCOPE_MISMATCH")
    trust, trust_file_digest, release_public = load_trust(trust_path, public_keys, "BUNDLE_RELEASE", release_key_id, verification_time)
    staging = Path(tempfile.mkdtemp(prefix=".planeon-signed-", dir=parent))
    staging.chmod(0o700)
    try:
        _write(staging / "bundle.lock.json", lock_bytes, 0o644)
        _write(staging / "supply-chain.evidence.json", evidence_bytes, 0o644)
        _write(staging / "approval.json", approval_path.read_bytes(), 0o644)
        _write(staging / "approval.sigstore.json", approval_bundle.read_bytes(), 0o644)
        _write(staging / "trust-bundle.json", trust_path.read_bytes(), 0o644)
        for key_id, source in public_keys.items():
            _write(staging / f"public-keys/{key_id}.pub", source.read_bytes(), 0o644)
        components: list[dict[str, Any]] = []
        for component in evidence.get("components", []):
            payload = {
                "artifactDigest": component["artifactDigest"],
                "bundleLockDigest": lock_digest,
                "kind": component["kind"],
                "license": component["license"],
                "moduleId": component["moduleId"],
                "platform": component["platform"],
                "schemaVersion": COMPONENT_SCHEMA,
                "sbomDigest": component["sbomDigest"],
                "vulnerabilities": component["vulnerabilities"],
            }
            name = component["artifactDigest"].removeprefix("sha256:")
            payload_path = staging / f"components/{name}.json"
            signature_path = staging / f"components/{name}.sigstore.json"
            _write(payload_path, payload, 0o644)
            sign_blob(payload_path, private_key, signature_path, password=password)
            verify_blob(payload_path, release_public, signature_path)
            components.append({"artifactDigest": component["artifactDigest"], "payloadDigest": _sha(payload_path.read_bytes()), "signatureBundleDigest": _sha(signature_path.read_bytes())})
        manifest = {
            "approvalDigest": approval_file_digest,
            "bundleLockDigest": lock_digest,
            "components": sorted(components, key=lambda item: item["artifactDigest"]),
            "evidenceDigest": evidence_digest,
            "organizationId": approval["organizationId"],
            "profileId": approval["profileId"],
            "schemaVersion": MANIFEST_SCHEMA,
            "signingKeyId": release_key_id,
            "state": "AWAITING_SIGNATURE",
            "trustBundleDigest": trust["trustBundleDigest"],
            "verificationTime": verification_time,
        }
        manifest_path = staging / "release-manifest.json"
        root_signature = staging / "release-manifest.sigstore.json"
        _write(manifest_path, manifest, 0o644)
        sign_blob(manifest_path, private_key, root_signature, password=password)
        verify_blob(manifest_path, release_public, root_signature)
        signed_payload = {
            "approvalDigest": approval_file_digest,
            "bundleLockDigest": lock_digest,
            "evidenceDigest": evidence_digest,
            "rootManifestDigest": _sha(manifest_path.read_bytes()),
            "rootSignatureBundleDigest": _sha(root_signature.read_bytes()),
            "schemaVersion": SIGNED_SCHEMA,
            "signingKeyId": release_key_id,
            "state": "SIGNED",
            "trustBundleFileDigest": trust_file_digest,
        }
        signed = {**signed_payload, "releaseDigest": _sha(encode(signed_payload))}
        _write(staging / "signed-release.json", signed, 0o644)
        verify_signed_release(staging, verification_time)
        os.replace(staging, parent / destination.name)
        return signed
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def verify_signed_release(directory: Path, verification_time: str) -> dict[str, Any]:
    trust_path = directory / "trust-bundle.json"
    public_keys = _public_key_map(trust_path)
    signed, _ = _read(directory / "signed-release.json", "SIGNED_RELEASE_INVALID")
    signed = _closed(signed, {"approvalDigest", "bundleLockDigest", "evidenceDigest", "releaseDigest", "rootManifestDigest", "rootSignatureBundleDigest", "schemaVersion", "signingKeyId", "state", "trustBundleFileDigest"}, "SIGNED_RELEASE_INVALID")
    payload = {name: value for name, value in signed.items() if name != "releaseDigest"}
    if signed["schemaVersion"] != SIGNED_SCHEMA or signed["state"] != "SIGNED" or signed["releaseDigest"] != _sha(encode(payload)):
        _fail("SIGNED_RELEASE_DIGEST_MISMATCH")
    lock, lock_bytes = _read(directory / "bundle.lock.json", "BUNDLE_LOCK_INVALID")
    evidence, evidence_bytes = _read(directory / "supply-chain.evidence.json", "SUPPLY_CHAIN_EVIDENCE_INVALID")
    if signed["bundleLockDigest"] != _sha(lock_bytes) or signed["evidenceDigest"] != _sha(evidence_bytes) or evidence.get("bundleLockDigest") != signed["bundleLockDigest"]:
        _fail("SIGNED_RELEASE_SUBJECT_MISMATCH")
    manifest, manifest_bytes = _read(directory / "release-manifest.json", "RELEASE_MANIFEST_INVALID")
    manifest = _closed(manifest, {"approvalDigest", "bundleLockDigest", "components", "evidenceDigest", "organizationId", "profileId", "schemaVersion", "signingKeyId", "state", "trustBundleDigest", "verificationTime"}, "RELEASE_MANIFEST_INVALID")
    if manifest["schemaVersion"] != MANIFEST_SCHEMA or manifest["state"] != "AWAITING_SIGNATURE" or manifest["signingKeyId"] != signed["signingKeyId"] or manifest["bundleLockDigest"] != signed["bundleLockDigest"] or manifest["evidenceDigest"] != signed["evidenceDigest"] or manifest["verificationTime"] != verification_time:
        _fail("SIGNED_RELEASE_ROOT_MISMATCH")
    if signed["rootManifestDigest"] != _sha(manifest_bytes) or signed["rootSignatureBundleDigest"] != _sha(_file_bytes(directory / "release-manifest.sigstore.json", "RELEASE_SIGNATURE_INVALID")):
        _fail("SIGNED_RELEASE_ROOT_MISMATCH")
    trust, trust_file_digest, release_public = load_trust(trust_path, public_keys, "BUNDLE_RELEASE", signed["signingKeyId"], verification_time)
    if signed["trustBundleFileDigest"] != trust_file_digest or manifest.get("trustBundleDigest") != trust["trustBundleDigest"]:
        _fail("SIGNED_RELEASE_TRUST_MISMATCH")
    approval, approval_file_digest = validate_approval(directory / "approval.json", directory / "approval.sigstore.json", trust_path, public_keys, signed["bundleLockDigest"], signed["evidenceDigest"], verification_time)
    if signed["approvalDigest"] != approval_file_digest or manifest.get("approvalDigest") != approval_file_digest or manifest.get("profileId") != lock.get("profileId") or manifest.get("organizationId") != approval.get("organizationId"):
        _fail("SIGNED_RELEASE_APPROVAL_MISMATCH")
    verify_blob(directory / "release-manifest.json", release_public, directory / "release-manifest.sigstore.json")
    expected_components = {item["artifactDigest"]: item for item in evidence.get("components", [])}
    manifest_components = manifest.get("components")
    if not isinstance(manifest_components, list) or len(manifest_components) != len(expected_components) or {item.get("artifactDigest") for item in manifest_components if isinstance(item, dict)} != set(expected_components):
        _fail("SIGNED_COMPONENT_SET_MISMATCH")
    for record in manifest_components:
        record = _closed(record, {"artifactDigest", "payloadDigest", "signatureBundleDigest"}, "SIGNED_COMPONENT_INVALID")
        name = record["artifactDigest"].removeprefix("sha256:")
        payload_path = directory / f"components/{name}.json"
        signature_path = directory / f"components/{name}.sigstore.json"
        component_payload, payload_bytes = _read(payload_path, "SIGNED_COMPONENT_INVALID")
        component_payload = _closed(component_payload, {"artifactDigest", "bundleLockDigest", "kind", "license", "moduleId", "platform", "schemaVersion", "sbomDigest", "vulnerabilities"}, "SIGNED_COMPONENT_INVALID")
        if component_payload["schemaVersion"] != COMPONENT_SCHEMA or component_payload["artifactDigest"] != record["artifactDigest"]:
            _fail("SIGNED_COMPONENT_SUBJECT_MISMATCH")
        if record["payloadDigest"] != _sha(payload_bytes) or record["signatureBundleDigest"] != _sha(_file_bytes(signature_path, "SIGNED_COMPONENT_INVALID")):
            _fail("SIGNED_COMPONENT_DIGEST_MISMATCH")
        source = expected_components[record["artifactDigest"]]
        if component_payload.get("bundleLockDigest") != signed["bundleLockDigest"] or any(component_payload.get(field) != source[field] for field in ("artifactDigest", "kind", "license", "moduleId", "platform", "sbomDigest", "vulnerabilities")):
            _fail("SIGNED_COMPONENT_SUBJECT_MISMATCH")
        verify_blob(payload_path, release_public, signature_path)
    return signed
