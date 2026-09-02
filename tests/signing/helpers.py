from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from planeon_distribution.builder import build_bundle
from planeon_distribution.canonical import encode
from planeon_distribution.resolver import resolve_profile
from planeon_distribution.sbom import build_evidence, publish_evidence
from planeon_distribution.signing import COSIGN, sign_blob

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "fixtures/supply-chain"
NOW = "2026-09-02T12:00:00Z"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(value))


def keypair(root: Path, name: str) -> tuple[str, Path, Path]:
    prefix = root / name
    completed = subprocess.run(
        [str(COSIGN), "generate-key-pair", "--output-key-prefix", str(prefix)],
        shell=False,
        check=False,
        env={"COSIGN_PASSWORD": "", "HOME": str(root), "PATH": "/opt/planeon/bin:/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode:
        raise RuntimeError("fixture key generation failed")
    private_key = prefix.with_suffix(".key")
    public_key = prefix.with_suffix(".pub")
    private_key.chmod(0o600)
    key_id = "key-" + hashlib.sha256(public_key.read_bytes()).hexdigest()[:16]
    return key_id, private_key, public_key


def trust_document(keys: list[dict[str, object]], revocations: list[dict[str, object]] | None = None, sequence: int = 1) -> dict[str, object]:
    payload = {
        "keys": sorted(keys, key=lambda item: str(item["keyId"])),
        "revocations": [] if revocations is None else sorted(revocations, key=lambda item: str(item["keyId"])),
        "schemaVersion": "harness.planeon.ai/release-trust-bundle/v1alpha1",
        "sequence": sequence,
    }
    return {**payload, "trustBundleDigest": sha(encode(payload))}


def trust_key(key_id: str, public_key: Path, roles: list[str], state: str = "ACTIVE", not_before: str = "2026-08-01T00:00:00Z", not_after: str = "2027-01-01T00:00:00Z") -> dict[str, object]:
    return {
        "keyId": key_id,
        "notAfter": not_after,
        "notBefore": not_before,
        "publicKeyDigest": sha(public_key.read_bytes()),
        "publicKeyFile": f"public-keys/{key_id}.pub",
        "roles": sorted(roles),
        "state": state,
    }


def fixture_bundle(root: Path) -> Path:
    bundle = root / "bundle"
    source = ROOT / "fixtures/oci-layout"
    build_bundle(resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source), source, bundle)
    evidence = build_evidence(
        bundle / "bundle.lock.json",
        SUPPLY / "component-inventory.json",
        ROOT / "policies/license-policy.json",
        ROOT / "policies/vulnerability-policy.json",
        SUPPLY / "vulnerability-db.json",
        SUPPLY / "dispositions.json",
        SUPPLY / "model-custody.json",
    )
    publish_evidence(evidence, bundle / "supply-chain.evidence.json")
    return bundle


def prepare(root: Path) -> dict[str, object]:
    bundle = fixture_bundle(root)
    approval_id, approval_private, approval_public = keypair(root, "approval")
    release_id, release_private, release_public = keypair(root, "release")
    keys = [
        trust_key(approval_id, approval_public, ["RELEASE_APPROVAL"]),
        trust_key(release_id, release_public, ["BUNDLE_RELEASE"]),
    ]
    trust = trust_document(keys)
    trust_path = root / "trust.json"
    write(trust_path, trust)
    lock_digest = sha((bundle / "bundle.lock.json").read_bytes())
    evidence_digest = sha((bundle / "supply-chain.evidence.json").read_bytes())
    approval_payload = {
        "approvalKeyId": approval_id,
        "authority": "release-board",
        "authorizedReleaseKeyIds": [release_id],
        "bundleLockDigest": lock_digest,
        "evidenceDigest": evidence_digest,
        "notAfter": "2026-10-01T00:00:00Z",
        "notBefore": "2026-09-01T00:00:00Z",
        "organizationId": "org-white-goods",
        "profileId": "white-goods-minimal-arm64",
        "schemaVersion": "harness.planeon.ai/release-approval/v1alpha1",
        "trustBundleDigest": trust["trustBundleDigest"],
    }
    approval = {**approval_payload, "approvalDigest": sha(encode(approval_payload))}
    approval_path = root / "approval.json"
    approval_bundle = root / "approval.sigstore.json"
    write(approval_path, approval)
    sign_blob(approval_path, approval_private, approval_bundle)
    return {
        "approvalBundle": approval_bundle,
        "approvalId": approval_id,
        "approvalPath": approval_path,
        "approvalPrivate": approval_private,
        "approvalPublic": approval_public,
        "bundle": bundle,
        "publicKeys": {approval_id: approval_public, release_id: release_public},
        "releaseId": release_id,
        "releasePrivate": release_private,
        "releasePublic": release_public,
        "trust": trust,
        "trustPath": trust_path,
    }
