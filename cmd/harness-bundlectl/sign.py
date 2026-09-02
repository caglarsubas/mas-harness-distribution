#!/usr/bin/env python3
"""Direct-argv entry point for offline signed-candidate creation."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.signing import SigningError, sign_candidate


def main() -> int:
    parser = argparse.ArgumentParser(prog="harness-bundlectl sign", allow_abbrev=False)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--approval-bundle", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--public-key", required=True, action="append")
    parser.add_argument("--release-key-id", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--verification-time", required=True)
    arguments = parser.parse_args()
    keys: dict[str, Path] = {}
    for assignment in arguments.public_key:
        key_id, separator, path = assignment.partition("=")
        if not separator or not key_id or key_id in keys or not path:
            parser.error("--public-key must be unique KEY_ID=PATH")
        keys[key_id] = Path(path)
    try:
        result = sign_candidate(arguments.bundle, arguments.approval, arguments.approval_bundle, arguments.trust, keys, arguments.release_key_id, arguments.private_key, arguments.destination, arguments.verification_time, password=os.environ.get("COSIGN_PASSWORD", ""))
    except SigningError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(encode(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
