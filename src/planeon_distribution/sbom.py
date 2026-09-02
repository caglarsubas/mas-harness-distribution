"""Deterministic SPDX generation and supply-chain evidence admission."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Mapping

from .canonical import CanonicalJsonError, decode, encode
from .licenses import evaluate_license, load_policy as load_license_policy
from .model_custody import validate_manifest
from .vulnerabilities import load_database, load_dispositions, load_policy as load_vulnerability_policy, scan_inventory

INVENTORY_SCHEMA = "harness.planeon.ai/component-inventory/v1alpha1"
EVIDENCE_SCHEMA = "harness.planeon.ai/supply-chain-evidence/v1alpha1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9._+-]{0,63}$")
PURL = re.compile(r"^pkg:[a-z0-9.+-]+/[A-Za-z0-9._~%+-]+@[A-Za-z0-9._~%+-]+(?:\?[A-Za-z0-9._~%=&+-]+)?$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class SbomError(ValueError):
    pass


def _fail(code: str) -> None:
    raise SbomError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _read(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        _fail(code)
    try:
        data = path.read_bytes()
        value = decode(data)
    except (OSError, CanonicalJsonError) as exc:
        raise SbomError(code) from exc
    if not isinstance(value, dict):
        _fail(code)
    return value, data


def load_inventory(bundle_lock_path: Path, inventory_path: Path) -> tuple[dict[str, Any], str, str]:
    lock, lock_bytes = _read(bundle_lock_path, "BUNDLE_LOCK_INVALID")
    if lock.get("schemaVersion") != "harness.planeon.ai/bundle-lock/v1alpha1" or lock.get("state") != "BUILT_UNSIGNED":
        _fail("BUNDLE_LOCK_STATE_INVALID")
    lock_digest = _sha(lock_bytes)
    inventory, inventory_bytes = _read(inventory_path, "COMPONENT_INVENTORY_INVALID")
    inventory = _closed(inventory, {"bundleLockDigest", "components", "models", "schemaVersion"}, "COMPONENT_INVENTORY_INVALID")
    if inventory["schemaVersion"] != INVENTORY_SCHEMA or inventory["bundleLockDigest"] != lock_digest:
        _fail("COMPONENT_INVENTORY_BINDING_MISMATCH")
    if not isinstance(inventory["components"], list) or not isinstance(inventory["models"], list):
        _fail("COMPONENT_INVENTORY_INVALID")
    if inventory["models"] != sorted(set(inventory["models"])) or not all(isinstance(item, str) and item for item in inventory["models"]):
        _fail("MODEL_EXPECTATION_INVALID")
    expected = {
        (item["digest"], item["kind"], item["moduleId"], item["platform"])
        for item in lock.get("components", [])
        if isinstance(item, dict) and set(item) == {"digest", "kind", "mediaType", "moduleId", "platform", "size"}
    }
    if len(expected) != len(lock.get("components", [])):
        _fail("BUNDLE_COMPONENTS_INVALID")
    actual: set[tuple[str, str, str, str]] = set()
    identities: set[tuple[str, str]] = set()
    for raw in inventory["components"]:
        component = _closed(raw, {"artifactDigest", "custodyClass", "custodyEvidence", "kind", "licenseExpression", "moduleId", "name", "platform", "purl", "source", "sourceEpoch", "supplier", "version"}, "COMPONENT_INVALID")
        if not all(isinstance(component[name], str) for name in component if name != "custodyEvidence"):
            _fail("COMPONENT_INVALID")
        if DIGEST.fullmatch(component["artifactDigest"]) is None or component["kind"] not in {"chart", "image"}:
            _fail("COMPONENT_INVALID")
        if PACKAGE_NAME.fullmatch(component["name"]) is None or VERSION.fullmatch(component["version"]) is None or PURL.fullmatch(component["purl"]) is None:
            _fail("COMPONENT_IDENTITY_INVALID")
        if not TIMESTAMP.fullmatch(component["sourceEpoch"]):
            _fail("COMPONENT_SOURCE_EPOCH_INVALID")
        if not component["source"].startswith("urn:planeon:source:") or component["artifactDigest"] not in component["source"] or "@latest" in component["source"]:
            _fail("COMPONENT_SOURCE_MUTABLE")
        if not component["supplier"].startswith(("Organization: ", "Person: ")):
            _fail("COMPONENT_SUPPLIER_INVALID")
        evidence = component["custodyEvidence"]
        if not isinstance(evidence, dict) or not evidence:
            _fail("COMPONENT_CUSTODY_INVALID")
        key = (component["artifactDigest"], component["kind"], component["moduleId"], component["platform"])
        identity = (component["purl"], component["version"])
        if key in actual or identity in identities:
            _fail("COMPONENT_DUPLICATE")
        actual.add(key)
        identities.add(identity)
    if actual != expected:
        _fail("COMPONENT_INVENTORY_INCOMPLETE_OR_EXTRA")
    inventory["components"] = sorted(inventory["components"], key=lambda item: (item["moduleId"], item["platform"], item["kind"], item["artifactDigest"]))
    return inventory, lock_digest, _sha(inventory_bytes)


def generate_spdx(component: Mapping[str, Any]) -> dict[str, Any]:
    hexadecimal = component["artifactDigest"].removeprefix("sha256:")
    suffix = hashlib.sha256((component["purl"] + component["artifactDigest"]).encode("utf-8")).hexdigest()[:20]
    package_id = f"SPDXRef-Package-{suffix}"
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"created": component["sourceEpoch"], "creators": ["Tool: planeon-distribution-reference-sbom-1"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"urn:planeon:spdx:{hexadecimal}",
        "name": f"{component['name']}-{component['version']}",
        "packages": [{
            "SPDXID": package_id,
            "checksums": [{"algorithm": "SHA256", "checksumValue": hexadecimal}],
            "downloadLocation": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceLocator": component["purl"], "referenceType": "purl"}],
            "filesAnalyzed": False,
            "licenseConcluded": component["licenseExpression"],
            "licenseDeclared": component["licenseExpression"],
            "name": component["name"],
            "supplier": component["supplier"],
            "versionInfo": component["version"],
        }],
        "relationships": [{"relatedSpdxElement": package_id, "relationshipType": "DESCRIBES", "spdxElementId": "SPDXRef-DOCUMENT"}],
        "spdxVersion": "SPDX-2.3",
    }


def generate_spdx_bytes(component: Mapping[str, Any]) -> bytes:
    return encode(generate_spdx(component))


def build_evidence(
    bundle_lock_path: Path,
    inventory_path: Path,
    license_policy_path: Path,
    vulnerability_policy_path: Path,
    vulnerability_database_path: Path,
    dispositions_path: Path,
    model_manifest_path: Path,
) -> dict[str, Any]:
    inventory, lock_digest, inventory_digest = load_inventory(bundle_lock_path, inventory_path)
    license_policy, license_policy_digest = load_license_policy(license_policy_path)
    vulnerability_policy, vulnerability_policy_digest = load_vulnerability_policy(vulnerability_policy_path)
    database, database_file_digest = load_database(vulnerability_database_path, vulnerability_policy)
    dispositions, disposition_digest = load_dispositions(dispositions_path, vulnerability_policy)
    findings = scan_inventory(inventory["components"], database, vulnerability_policy, dispositions)
    models, model_manifest_digest = validate_manifest(model_manifest_path, lock_digest, inventory["models"], license_policy)
    component_records: list[dict[str, Any]] = []
    for component in inventory["components"]:
        sbom_bytes = generate_spdx_bytes(component)
        sbom_digest = _sha(sbom_bytes)
        license_result = evaluate_license(component["licenseExpression"], component["custodyClass"], component["custodyEvidence"], sbom_digest, license_policy)
        component_records.append({
            "artifactDigest": component["artifactDigest"],
            "kind": component["kind"],
            "license": license_result,
            "moduleId": component["moduleId"],
            "platform": component["platform"],
            "sbomDigest": sbom_digest,
            "vulnerabilities": findings[component["artifactDigest"]],
        })
    payload = {
        "bundleLockDigest": lock_digest,
        "componentInventoryDigest": inventory_digest,
        "components": component_records,
        "dispositionDigest": disposition_digest,
        "licensePolicyDigest": license_policy_digest,
        "modelManifestDigest": model_manifest_digest,
        "models": models,
        "schemaVersion": EVIDENCE_SCHEMA,
        "state": "SCANNED",
        "vulnerabilityDatabaseDigest": database_file_digest,
        "vulnerabilityPolicyDigest": vulnerability_policy_digest,
    }
    return {**payload, "evidenceDigest": _sha(encode(payload))}


def publish_evidence(evidence: Mapping[str, Any], destination: Path) -> str:
    if destination.exists() or destination.is_symlink():
        _fail("EVIDENCE_DESTINATION_EXISTS")
    parent = destination.parent.resolve(strict=True)
    target = parent / destination.name
    data = encode(dict(evidence))
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return _sha(data)
