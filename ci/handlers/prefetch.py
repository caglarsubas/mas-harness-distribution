#!/usr/bin/env python3
"""Validation-only DIST-001 prefetch; performs no installation or network access."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from planeon_distribution.oci import verify_layout

ROOT = Path(__file__).resolve().parents[2]
BASE = "46505de17b025ade5b065d0e1021cf7c69b6f4c7"
PYTHON_INVENTORY_SHA256 = "36167810c1ec56f5d5dc55410d9e528c58700ff138608e3b116f868a4d650799"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"prefetch refused: {message}")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=ROOT, check=True, shell=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def main() -> None:
    require("HARNESS_TASK_PACKET" not in os.environ, "packet path leaked to prefetch child")
    require("HARNESS_WARM_SOURCE_ROOTS" not in os.environ, "warm-source roots leaked to prefetch child")
    require(os.environ.get("UV_OFFLINE") == "1" and os.environ.get("UV_FROZEN") == "1" and os.environ.get("UV_NO_SYNC") == "1", "offline uv flags are required")
    lock = json.loads((ROOT / "toolchain.lock").read_text(encoding="utf-8"))
    require(lock["planningBase"] == BASE, "planning base lock changed")
    require(git("merge-base", "--is-ancestor", BASE, "HEAD") == "", "planning base is not an ancestor")
    require(git("rev-list", "--max-parents=0", "HEAD") == BASE, "planning seed is not the sole root")
    require(lock["tools"]["python"]["inventorySha256"] == PYTHON_INVENTORY_SHA256, "Python inventory authority changed")
    require(lock["tools"]["uv"]["sha256"] == sha(Path(lock["tools"]["uv"]["path"])), "uv executable changed")
    require(subprocess.run([lock["tools"]["python"]["path"], "--version"], check=True, shell=False, text=True, stdout=subprocess.PIPE).stdout.strip() == "Python 3.12.14", "Python version changed")
    require(subprocess.run([lock["tools"]["uv"]["path"], "--version"], check=True, shell=False, text=True, stdout=subprocess.PIPE).stdout.startswith("uv 0.12.7 "), "uv version changed")
    uv_lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    require("source = { registry" not in uv_lock and "sdist =" not in uv_lock and "wheels =" not in uv_lock, "external dependency entered uv.lock")
    report = verify_layout(ROOT / "fixtures/oci-layout")
    require(report["indexDigest"] == "sha256:cf42fa1a8b59cbd3cf3123b0d558fc04c5b1d8a00eba95acbff5161daa5cfdb4", "fixture digest changed")
    subprocess.run([lock["tools"]["python"]["path"], "ci/validate_porting.py"], cwd=ROOT, check=True, shell=False)
    print("prefetch passed: exact ancestry, authorities, toolchain, inert porting ledger, and local OCI fixture")


if __name__ == "__main__":
    main()
