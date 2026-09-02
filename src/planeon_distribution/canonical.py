"""Strict canonical JSON helpers with duplicate-member rejection."""

from __future__ import annotations

import json
from typing import Any


class CanonicalJsonError(ValueError):
    """Raised when bytes are not the repository's canonical JSON form."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("DUPLICATE_JSON_MEMBER")
        result[key] = value
    return result


def encode(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def decode(data: bytes, *, require_canonical: bool = True) -> Any:
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=lambda _: (_ for _ in ()).throw(CanonicalJsonError("NONFINITE_JSON_NUMBER")))
    except UnicodeDecodeError as exc:
        raise CanonicalJsonError("NON_UTF8_JSON") from exc
    except json.JSONDecodeError as exc:
        raise CanonicalJsonError("MALFORMED_JSON") from exc
    if require_canonical and encode(value) != data:
        raise CanonicalJsonError("NONCANONICAL_JSON")
    return value
