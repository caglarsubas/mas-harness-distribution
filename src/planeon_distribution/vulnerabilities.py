"""Deterministic evaluation over a digest-pinned local vulnerability snapshot."""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import CanonicalJsonError, decode, encode

DB_SCHEMA = "harness.planeon.ai/vulnerability-database/v1alpha1"
POLICY_SCHEMA = "harness.planeon.ai/vulnerability-policy/v1alpha1"
DISPOSITION_SCHEMA = "harness.planeon.ai/vulnerability-dispositions/v1alpha1"
SEVERITIES = {"UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
DIGEST = "sha256:"


class VulnerabilityError(ValueError):
    pass


def _fail(code: str) -> None:
    raise VulnerabilityError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _sha(value: bytes) -> str:
    return f"{DIGEST}{hashlib.sha256(value).hexdigest()}"


def _read(path: Path, code: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        _fail(code)
    try:
        data = path.read_bytes()
        value = decode(data)
    except (OSError, CanonicalJsonError) as exc:
        raise VulnerabilityError(code) from exc
    if not isinstance(value, dict):
        _fail(code)
    return value, data


def _date(value: Any, code: str) -> date:
    if not isinstance(value, str):
        _fail(code)
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise VulnerabilityError(code) from exc
    if parsed.isoformat() != value:
        _fail(code)
    return parsed


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    policy, data = _read(path, "VULNERABILITY_POLICY_INVALID")
    policy = _closed(policy, {"allowedDispositions", "assessmentDate", "blockedSeverities", "databaseDigest", "databaseId", "schemaVersion"}, "VULNERABILITY_POLICY_INVALID")
    if policy["schemaVersion"] != POLICY_SCHEMA or not isinstance(policy["databaseId"], str) or not policy["databaseId"]:
        _fail("VULNERABILITY_POLICY_INVALID")
    if not isinstance(policy["databaseDigest"], str) or len(policy["databaseDigest"]) != 71 or not policy["databaseDigest"].startswith(DIGEST):
        _fail("VULNERABILITY_POLICY_INVALID")
    blocked = policy["blockedSeverities"]
    allowed = policy["allowedDispositions"]
    if blocked != ["CRITICAL", "HIGH"] or allowed != ["ACCEPTED_RISK", "FALSE_POSITIVE"]:
        _fail("VULNERABILITY_POLICY_INVALID")
    _date(policy["assessmentDate"], "VULNERABILITY_POLICY_INVALID")
    return policy, _sha(data)


def load_database(path: Path, policy: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    database, data = _read(path, "VULNERABILITY_DATABASE_INVALID")
    database = _closed(database, {"advisories", "databaseDigest", "databaseId", "generated", "schemaVersion", "source", "validThrough"}, "VULNERABILITY_DATABASE_INVALID")
    if database["schemaVersion"] != DB_SCHEMA or database["databaseId"] != policy["databaseId"] or database["source"] != "LOCAL_FIXTURE":
        _fail("VULNERABILITY_DATABASE_ID_MISMATCH")
    payload = {key: value for key, value in database.items() if key != "databaseDigest"}
    if database["databaseDigest"] != _sha(encode(payload)) or database["databaseDigest"] != policy["databaseDigest"]:
        _fail("VULNERABILITY_DATABASE_DIGEST_MISMATCH")
    generated = _date(database["generated"], "VULNERABILITY_DATABASE_INVALID")
    valid_through = _date(database["validThrough"], "VULNERABILITY_DATABASE_INVALID")
    assessment = _date(policy["assessmentDate"], "VULNERABILITY_POLICY_INVALID")
    if generated > assessment or valid_through < assessment or generated > valid_through:
        _fail("VULNERABILITY_DATABASE_STALE")
    advisories = database["advisories"]
    if not isinstance(advisories, list):
        _fail("VULNERABILITY_DATABASE_INVALID")
    seen: set[str] = set()
    keys: set[tuple[str, str, str]] = set()
    for raw in advisories:
        advisory = _closed(raw, {"descriptionDigest", "id", "purl", "severity", "version"}, "VULNERABILITY_ADVISORY_INVALID")
        if not all(isinstance(advisory[name], str) and advisory[name] for name in advisory):
            _fail("VULNERABILITY_ADVISORY_INVALID")
        key = (advisory["id"], advisory["purl"], advisory["version"])
        if advisory["id"] in seen or key in keys:
            _fail("VULNERABILITY_ADVISORY_AMBIGUOUS")
        if advisory["severity"] not in SEVERITIES or len(advisory["descriptionDigest"]) != 71 or not advisory["descriptionDigest"].startswith(DIGEST):
            _fail("VULNERABILITY_ADVISORY_INVALID")
        seen.add(advisory["id"])
        keys.add(key)
    return database, _sha(data)


def load_dispositions(path: Path, policy: Mapping[str, Any]) -> tuple[dict[tuple[str, str, str], dict[str, Any]], str]:
    document, data = _read(path, "VULNERABILITY_DISPOSITIONS_INVALID")
    document = _closed(document, {"dispositions", "schemaVersion"}, "VULNERABILITY_DISPOSITIONS_INVALID")
    if document["schemaVersion"] != DISPOSITION_SCHEMA or not isinstance(document["dispositions"], list):
        _fail("VULNERABILITY_DISPOSITIONS_INVALID")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in document["dispositions"]:
        disposition = _closed(raw, {"authority", "componentDigest", "decision", "decisionDigest", "expires", "purl", "vulnerabilityId"}, "VULNERABILITY_DISPOSITION_INVALID")
        payload = {key: value for key, value in disposition.items() if key != "decisionDigest"}
        if disposition["decision"] not in policy["allowedDispositions"] or disposition["decisionDigest"] != _sha(encode(payload)):
            _fail("VULNERABILITY_DISPOSITION_INVALID")
        if not isinstance(disposition["authority"], str) or not disposition["authority"] or _date(disposition["expires"], "VULNERABILITY_DISPOSITION_INVALID") < _date(policy["assessmentDate"], "VULNERABILITY_POLICY_INVALID"):
            _fail("VULNERABILITY_DISPOSITION_EXPIRED")
        key = (disposition["vulnerabilityId"], disposition["purl"], disposition["componentDigest"])
        if key in result:
            _fail("VULNERABILITY_DISPOSITION_DUPLICATE")
        result[key] = disposition
    return result, _sha(data)


def scan_inventory(
    components: Iterable[Mapping[str, Any]],
    database: Mapping[str, Any],
    policy: Mapping[str, Any],
    dispositions: Mapping[tuple[str, str, str], Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    used: set[tuple[str, str, str]] = set()
    blocked = set(policy["blockedSeverities"])
    for component in components:
        component_digest = component["artifactDigest"]
        findings: list[dict[str, Any]] = []
        for advisory in database["advisories"]:
            if advisory["purl"] != component["purl"] or advisory["version"] != component["version"]:
                continue
            key = (advisory["id"], component["purl"], component_digest)
            disposition = dispositions.get(key)
            if advisory["severity"] in blocked and disposition is None:
                _fail("VULNERABILITY_BLOCKING_UNDISPOSED")
            if disposition is not None:
                used.add(key)
            findings.append({
                "descriptionDigest": advisory["descriptionDigest"],
                "disposition": None if disposition is None else disposition["decision"],
                "id": advisory["id"],
                "severity": advisory["severity"],
            })
        results[component_digest] = sorted(findings, key=lambda item: item["id"])
    if used != set(dispositions):
        _fail("VULNERABILITY_DISPOSITION_UNREFERENCED")
    return results
