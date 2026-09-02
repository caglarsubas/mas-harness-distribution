"""Closed license admission derived from the repository policy authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import CanonicalJsonError, decode, encode

SCHEMA = "harness.planeon.ai/license-policy/v1alpha1"
DIGEST_PREFIX = "sha256:"
POLICY_KEYS = {
    "allowedExceptionExpressions",
    "allowedSpdx",
    "custodyRequirements",
    "deniedSpdx",
    "explicitReviewSpdx",
    "openContentSpdx",
    "plannedUnresolvedSpdx",
    "schemaVersion",
    "sourcePolicySha256",
}
CLASSES = {
    "DEFAULT_ALLOWED",
    "ALLOWED_EXCEPTION_EXPRESSION",
    "OPEN_CONTENT",
    "OPTIONAL_EXPLICIT_REVIEW_APPROVED",
}


class LicenseError(ValueError):
    pass


def _fail(code: str) -> None:
    raise LicenseError(code)


def _closed(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        _fail(code)
    return value


def _digest(data: bytes) -> str:
    return f"{DIGEST_PREFIX}{hashlib.sha256(data).hexdigest()}"


def _string_set(value: Any, code: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() == item and item for item in value):
        _fail(code)
    if len(value) != len(set(value)):
        _fail(code)
    return tuple(value)


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        _fail("LICENSE_POLICY_UNAVAILABLE")
    try:
        data = path.read_bytes()
        policy = decode(data)
    except (OSError, CanonicalJsonError) as exc:
        raise LicenseError("LICENSE_POLICY_INVALID") from exc
    policy = _closed(policy, POLICY_KEYS, "LICENSE_POLICY_INVALID")
    if policy["schemaVersion"] != SCHEMA:
        _fail("LICENSE_POLICY_INVALID")
    source_digest = policy["sourcePolicySha256"]
    if not isinstance(source_digest, str) or len(source_digest) != 64 or any(character not in "0123456789abcdef" for character in source_digest):
        _fail("LICENSE_POLICY_SOURCE_DIGEST_INVALID")
    groups = {
        "DEFAULT_ALLOWED": _string_set(policy["allowedSpdx"], "LICENSE_POLICY_INVALID"),
        "ALLOWED_EXCEPTION_EXPRESSION": _string_set(policy["allowedExceptionExpressions"], "LICENSE_POLICY_INVALID"),
        "OPEN_CONTENT": _string_set(policy["openContentSpdx"], "LICENSE_POLICY_INVALID"),
        "OPTIONAL_EXPLICIT_REVIEW": _string_set(policy["explicitReviewSpdx"], "LICENSE_POLICY_INVALID"),
        "PLANNED_UNRESOLVED": _string_set(policy["plannedUnresolvedSpdx"], "LICENSE_POLICY_INVALID"),
        "DENIED": _string_set(policy["deniedSpdx"], "LICENSE_POLICY_INVALID"),
    }
    seen: set[str] = set()
    for expressions in groups.values():
        if seen.intersection(expressions):
            _fail("LICENSE_POLICY_AMBIGUOUS")
        seen.update(expressions)
    custody = policy["custodyRequirements"]
    if not isinstance(custody, dict) or not custody:
        _fail("LICENSE_POLICY_INVALID")
    for name, requirements in custody.items():
        if not isinstance(name, str) or not name or not isinstance(requirements, list) or not requirements:
            _fail("LICENSE_POLICY_INVALID")
        if not all(isinstance(item, str) and item for item in requirements) or len(requirements) != len(set(requirements)):
            _fail("LICENSE_POLICY_INVALID")
    return policy, _digest(data)


def classify_expression(expression: Any, policy: Mapping[str, Any], reviews: Iterable[Mapping[str, Any]] = ()) -> str:
    if not isinstance(expression, str) or not expression or expression.strip() != expression:
        _fail("LICENSE_MISSING_OR_MALFORMED")
    if expression in policy["deniedSpdx"]:
        _fail("LICENSE_DENIED")
    if expression in policy["plannedUnresolvedSpdx"]:
        _fail("LICENSE_UNRESOLVED")
    if expression in policy["explicitReviewSpdx"]:
        matching = [review for review in reviews if review.get("expression") == expression]
        if len(matching) != 1:
            _fail("LICENSE_REVIEW_REQUIRED")
        review = _closed(dict(matching[0]), {"approved", "authority", "decisionDigest", "expression"}, "LICENSE_REVIEW_INVALID")
        payload = {key: value for key, value in review.items() if key != "decisionDigest"}
        if review["approved"] is not True or not isinstance(review["authority"], str) or not review["authority"]:
            _fail("LICENSE_REVIEW_INVALID")
        if review["decisionDigest"] != _digest(encode(payload)):
            _fail("LICENSE_REVIEW_INVALID")
        return "OPTIONAL_EXPLICIT_REVIEW_APPROVED"
    if expression in policy["allowedExceptionExpressions"]:
        return "ALLOWED_EXCEPTION_EXPRESSION"
    if expression in policy["openContentSpdx"]:
        return "OPEN_CONTENT"
    if expression in policy["allowedSpdx"]:
        return "DEFAULT_ALLOWED"
    _fail("LICENSE_UNKNOWN")


def evaluate_license(
    expression: Any,
    custody_class: Any,
    evidence: Any,
    sbom_digest: str,
    policy: Mapping[str, Any],
    reviews: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    classification = classify_expression(expression, policy, reviews)
    if not isinstance(custody_class, str) or custody_class not in policy["custodyRequirements"]:
        _fail("CUSTODY_CLASS_UNKNOWN")
    if not isinstance(evidence, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in evidence.items()):
        _fail("CUSTODY_EVIDENCE_INVALID")
    supplied = dict(evidence)
    supplied["sbom"] = sbom_digest
    required = policy["custodyRequirements"][custody_class]
    if set(supplied) != set(required):
        _fail("CUSTODY_EVIDENCE_INCOMPLETE")
    if any(not value.startswith(DIGEST_PREFIX) or len(value) != 71 for value in supplied.values()):
        _fail("CUSTODY_EVIDENCE_INVALID")
    obligations = sorted(required)
    if classification == "ALLOWED_EXCEPTION_EXPRESSION":
        obligations.append("exceptionText")
    elif classification == "OPEN_CONTENT":
        obligations.append("contentInventory")
    elif classification == "OPTIONAL_EXPLICIT_REVIEW_APPROVED":
        obligations.append("approvedReview")
    return {"classification": classification, "expression": expression, "obligations": sorted(obligations)}


def admitted_classification(value: str) -> bool:
    return value in CLASSES
