"""Command-line surface for bounded local verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .canonical import encode
from .oci import LayoutError, verify_layout


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="harness-bundlectl", allow_abbrev=False)
    commands = root.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("layout", type=Path)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parser().parse_args(argv)
        report = verify_layout(arguments.layout)
    except LayoutError as exc:
        code = str(exc)
        print(code, file=sys.stderr)
        return 3 if code == "LAYOUT_UNAVAILABLE" else 2
    sys.stdout.buffer.write(encode(report))
    return 0
