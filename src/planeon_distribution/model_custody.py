"""Strict model-license and artifact-custody admission."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import CanonicalJsonError, decode, encode
from .licenses import classify_expression

SCHEMA = "harness.planeon.ai/model-custody-manifest/v1alpha1"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MODEL_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
QUANTIZATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


class ModelCustodyError(ValueError):
    pass


def _fail(code: str) -> None:
    raise ModelCustodyError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def validate_manifest(
    path: Path,
    bundle_lock_digest: str,
    expected_model_ids: Iterable[str],
    license_policy: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    if path.is_symlink() or not path.is_file():
        _fail("MODEL_CUSTODY_UNAVAILABLE")
    try:
        data = path.read_bytes()
        document = decode(data)
    except (OSError, CanonicalJsonError) as exc:
        raise ModelCustodyError("MODEL_CUSTODY_INVALID") from exc
    document = _closed(document, {"bundleLockDigest", "models", "schemaVersion"}, "MODEL_CUSTODY_INVALID")
    if document["schemaVersion"] != SCHEMA or document["bundleLockDigest"] != bundle_lock_digest or not isinstance(document["models"], list):
        _fail("MODEL_CUSTODY_BINDING_MISMATCH")
    expected = list(expected_model_ids)
    if expected != sorted(set(expected)):
        _fail("MODEL_EXPECTATION_INVALID")
    results: list[dict[str, Any]] = []
    seen_artifacts: set[str] = set()
    for raw in document["models"]:
        model = _closed(raw, {"approvalDigest", "approvingAuthority", "architecture", "artifactDigest", "licenseExpression", "modelId", "quantization", "redistributable", "source", "tokenizerDigest"}, "MODEL_CUSTODY_INVALID")
        if not isinstance(model["modelId"], str) or MODEL_ID.fullmatch(model["modelId"]) is None:
            _fail("MODEL_ID_INVALID")
        if not isinstance(model["artifactDigest"], str) or DIGEST.fullmatch(model["artifactDigest"]) is None or model["artifactDigest"] in seen_artifacts:
            _fail("MODEL_ARTIFACT_INVALID_OR_DUPLICATE")
        if not isinstance(model["tokenizerDigest"], str) or DIGEST.fullmatch(model["tokenizerDigest"]) is None:
            _fail("MODEL_TOKENIZER_INVALID")
        if model["architecture"] not in {"amd64", "arm64", "multi"} or not isinstance(model["quantization"], str) or QUANTIZATION.fullmatch(model["quantization"]) is None:
            _fail("MODEL_PLATFORM_INVALID")
        if model["redistributable"] is not True:
            _fail("MODEL_REDISTRIBUTION_DENIED")
        if not isinstance(model["source"], str) or not model["source"].startswith("urn:planeon:model-source:") or model["artifactDigest"] not in model["source"]:
            _fail("MODEL_SOURCE_MUTABLE")
        if not isinstance(model["approvingAuthority"], str) or not model["approvingAuthority"]:
            _fail("MODEL_APPROVAL_INVALID")
        payload = {key: value for key, value in model.items() if key != "approvalDigest"}
        expected_approval = f"sha256:{hashlib.sha256(encode(payload)).hexdigest()}"
        if model["approvalDigest"] != expected_approval:
            _fail("MODEL_APPROVAL_INVALID")
        classification = classify_expression(model["licenseExpression"], license_policy)
        seen_artifacts.add(model["artifactDigest"])
        results.append({
            "approvalDigest": model["approvalDigest"],
            "artifactDigest": model["artifactDigest"],
            "licenseClassification": classification,
            "modelId": model["modelId"],
            "tokenizerDigest": model["tokenizerDigest"],
        })
    results.sort(key=lambda item: item["modelId"])
    if [item["modelId"] for item in results] != expected:
        _fail("MODEL_CUSTODY_INCOMPLETE_OR_UNREFERENCED")
    return results, f"sha256:{hashlib.sha256(data).hexdigest()}"
