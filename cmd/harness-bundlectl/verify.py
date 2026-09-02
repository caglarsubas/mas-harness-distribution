#!/usr/bin/env python3
"""Direct-argv entry point for OCI-layout or signed-release verification."""

import sys
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.cli import main as layout_main
from planeon_distribution.signing import SigningError, verify_signed_release


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "signed-release":
        try:
            result = verify_signed_release(Path(sys.argv[2]), sys.argv[3])
        except SigningError as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(2)
        sys.stdout.buffer.write(encode(result))
        raise SystemExit(0)
    raise SystemExit(layout_main(["verify", *sys.argv[1:]]))
