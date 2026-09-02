#!/usr/bin/env python3
"""Validate the inert bootstrap PORTING ledger without a YAML dependency."""

from __future__ import annotations

import json
from pathlib import Path

EXPECTED = {"authorizations": [{"status": "NO_AUTHORIZATION"}], "destinationRepository": "mas-harness-distribution", "schemaVersion": "harness.planeon.ai/porting-ledger/v1alpha1"}


def validate(path: Path = Path("PORTING.yaml")) -> None:
    if json.loads(path.read_text(encoding="utf-8")) != EXPECTED:
        raise ValueError("PORTING_AUTHORIZATION_PRESENT")


if __name__ == "__main__":
    validate()
    print("porting ledger passed: NO_AUTHORIZATION")
