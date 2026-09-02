"""Closed minimal-profile resolver over an already verified local OCI layout."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .canonical import CanonicalJsonError, decode, encode
from .helm import validate_vendored_charts
from .oci import DIGEST, INDEX_MEDIA, LayoutError, selected_image_closure, verify_layout

PROFILE_SCHEMA = "harness.planeon.ai/distribution-profile/v1alpha1"
MODULE_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
PLATFORMS = {"linux/amd64", "linux/arm64"}
IMAGE_MEDIA = "application/vnd.oci.image.manifest.v1+json"
CHART_MEDIA = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"


class ResolutionError(ValueError):
    pass


def _fail(code: str) -> None:
    raise ResolutionError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _profile(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        _fail("PROFILE_UNAVAILABLE")
    try:
        profile = decode(path.read_bytes())
    except CanonicalJsonError as exc:
        raise ResolutionError(str(exc)) from exc
    profile = _closed(profile, {"schemaVersion", "profileId", "profileDigest", "platforms", "modules"}, "INVALID_PROFILE")
    if profile["schemaVersion"] != PROFILE_SCHEMA or not isinstance(profile["profileId"], str) or PROFILE_ID.fullmatch(profile["profileId"]) is None:
        _fail("INVALID_PROFILE")
    digest = profile["profileDigest"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        _fail("INVALID_PROFILE_DIGEST")
    payload = {key: value for key, value in profile.items() if key != "profileDigest"}
    if digest != f"sha256:{hashlib.sha256(encode(payload)).hexdigest()}":
        _fail("PROFILE_DIGEST_MISMATCH")
    platforms = profile["platforms"]
    if not isinstance(platforms, list) or not platforms or len(platforms) != len(set(platforms)) or set(platforms) - PLATFORMS:
        _fail("INVALID_PLATFORMS")
    if not isinstance(profile["modules"], list) or not 1 <= len(profile["modules"]) <= 16:
        _fail("INVALID_MODULES")
    return profile


def resolve_profile(profile_path: Path, source_layout: Path) -> dict[str, Any]:
    profile = _profile(profile_path)
    try:
        source_report = verify_layout(source_layout)
    except LayoutError as exc:
        raise ResolutionError(str(exc)) from exc
    modules: list[dict[str, Any]] = []
    seen_modules: set[str] = set()
    component_keys: set[tuple[str, str, str]] = set()
    digest_meanings: dict[str, tuple[int, str]] = {}
    for raw_module in profile["modules"]:
        module = _closed(raw_module, {"id", "selected", "artifacts"}, "INVALID_MODULE")
        module_id = module["id"]
        if not isinstance(module_id, str) or MODULE_ID.fullmatch(module_id) is None or module_id in seen_modules:
            _fail("INVALID_OR_DUPLICATE_MODULE")
        seen_modules.add(module_id)
        if not isinstance(module["selected"], bool) or not isinstance(module["artifacts"], list):
            _fail("INVALID_MODULE")
        if not module["selected"]:
            if module["artifacts"]:
                _fail("UNSELECTED_MODULE_HAS_ARTIFACTS")
            continue
        components: list[dict[str, Any]] = []
        coverage: dict[str, set[str]] = {platform: set() for platform in profile["platforms"]}
        for raw_artifact in module["artifacts"]:
            artifact = _closed(raw_artifact, {"kind", "digest", "size", "mediaType", "platform"}, "INVALID_ARTIFACT")
            if artifact["kind"] not in {"image", "chart"} or artifact["platform"] not in profile["platforms"]:
                _fail("INVALID_ARTIFACT")
            if not isinstance(artifact["digest"], str) or DIGEST.fullmatch(artifact["digest"]) is None:
                _fail("INVALID_DIGEST")
            expected_media = IMAGE_MEDIA if artifact["kind"] == "image" else CHART_MEDIA
            if artifact["mediaType"] != expected_media:
                _fail("UNSUPPORTED_MEDIA_TYPE")
            if not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool) or not 0 <= artifact["size"] <= 1_048_576:
                _fail("INVALID_ARTIFACT_SIZE")
            key = (artifact["kind"], artifact["digest"], artifact["platform"])
            if key in component_keys:
                _fail("DUPLICATE_ARTIFACT")
            component_keys.add(key)
            meaning = (artifact["size"], artifact["mediaType"])
            if artifact["digest"] in digest_meanings and digest_meanings[artifact["digest"]] != meaning:
                _fail("CONFLICTING_DIGEST_MEANING")
            digest_meanings[artifact["digest"]] = meaning
            coverage[artifact["platform"]].add(artifact["kind"])
            components.append({"digest": artifact["digest"], "kind": artifact["kind"], "mediaType": artifact["mediaType"], "moduleId": module_id, "platform": artifact["platform"], "size": artifact["size"]})
        if any(kinds != {"image", "chart"} for kinds in coverage.values()):
            _fail("MISSING_PLATFORM_COVERAGE")
        modules.append({"components": components, "id": module_id})
    if not modules:
        _fail("EMPTY_SELECTION")
    components = sorted((component for module in modules for component in module["components"]), key=lambda value: (value["moduleId"], value["platform"], value["kind"], value["digest"]))
    images = {component["digest"] for component in components if component["kind"] == "image"}
    try:
        index_manifests, blobs = selected_image_closure(source_layout, images)
        layer_digests = {blob["digest"] for blob in blobs if blob["mediaType"].startswith("application/vnd.oci.image.layer")}
        validate_vendored_charts(source_layout, components, layer_digests)
    except LayoutError as exc:
        raise ResolutionError(str(exc)) from exc
    blob_by_digest = {blob["digest"]: blob for blob in blobs}
    for component in components:
        source_blob = blob_by_digest.get(component["digest"])
        if source_blob is None or source_blob["size"] != component["size"]:
            _fail("COMPONENT_DIGEST_OR_SIZE_MISMATCH")
    return {
        "blobs": blobs,
        "components": components,
        "indexManifests": index_manifests,
        "platforms": sorted(profile["platforms"]),
        "profileDigest": profile["profileDigest"],
        "profileId": profile["profileId"],
        "selectedModules": sorted(module["id"] for module in modules),
        "sourceIndexDigest": source_report["indexDigest"],
    }
