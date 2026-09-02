#!/usr/bin/env python3
"""Direct-argv bounded air-gap import."""

import argparse
import sys
from pathlib import Path

from planeon_distribution.airgap import AirgapError, import_archive
from planeon_distribution.canonical import encode

parser = argparse.ArgumentParser(prog="harness-bundlectl import-airgap", allow_abbrev=False)
parser.add_argument("--archive", required=True, type=Path)
parser.add_argument("--archive-digest", required=True)
parser.add_argument("--destination", required=True, type=Path)
parser.add_argument("--verification-time", required=True)
arguments = parser.parse_args()
try:
    result = import_archive(arguments.archive, arguments.archive_digest, arguments.destination, arguments.verification_time)
except AirgapError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)
sys.stdout.buffer.write(encode(result))
