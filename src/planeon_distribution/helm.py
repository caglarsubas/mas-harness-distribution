"""Validation for already-vendored, digest-addressed chart components."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .oci import LayoutError

CHART_MEDIA = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"


def validate_vendored_charts(source_layout: Path, components: list[dict[str, Any]], layer_digests: set[str]) -> None:
    for component in components:
        if component["kind"] != "chart":
            continue
        if component["mediaType"] != CHART_MEDIA:
            raise LayoutError("UNSUPPORTED_CHART_MEDIA_TYPE")
        if component["digest"] not in layer_digests:
            raise LayoutError("UNDECLARED_CHART_BLOB")
        hexadecimal = component["digest"].removeprefix("sha256:")
        path = source_layout / "blobs/sha256" / hexadecimal
        data = path.read_bytes()
        if len(data) != component["size"] or hashlib.sha256(data).hexdigest() != hexadecimal:
            raise LayoutError("CHART_DIGEST_OR_SIZE_MISMATCH")
        lowered = data.lower()
        if any(token in lowered for token in (b"http://", b"https://", b":latest", b"repository:")):
            raise LayoutError("CHART_REMOTE_OR_MUTABLE_DEPENDENCY")
