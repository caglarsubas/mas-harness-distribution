#!/usr/bin/env python3
"""Direct-argv deterministic air-gap export."""

import argparse
import sys
from pathlib import Path

from planeon_distribution.airgap import AirgapError, export_archive
from planeon_distribution.canonical import encode

parser = argparse.ArgumentParser(prog="harness-bundlectl export-airgap", allow_abbrev=False)
parser.add_argument("--release", required=True, type=Path)
parser.add_argument("--evidence", required=True, action="append")
parser.add_argument("--destination", required=True, type=Path)
parser.add_argument("--verification-time", required=True)
arguments = parser.parse_args()
evidence = {}
for assignment in arguments.evidence:
    name, separator, path = assignment.partition("=")
    if not separator or not name or name in evidence or not path:
        parser.error("--evidence must be unique NAME=PATH")
    evidence[name] = Path(path)
try:
    result = export_archive(arguments.release, evidence, arguments.destination, arguments.verification_time)
except AirgapError as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)
sys.stdout.buffer.write(encode(result))
