from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/harness-platform"
PROFILES = ROOT / "profiles"
HELM = Path("/opt/planeon/bin/helm")
HELM_SHA256 = "87c4f99aa4edc63a5536838123680bece0e63c51019e515b122ba27f6276a3c9"
EXPECTED = json.loads((ROOT / "fixtures/helm/expected-render.json").read_text(encoding="utf-8"))
SOURCE = re.compile(r"# Source: harness-platform/charts/([^/]+)/")


def verify_helm() -> None:
    if HELM.is_symlink() or not HELM.is_file() or HELM.stat().st_uid != 0 or HELM.stat().st_mode & 0o022:
        raise AssertionError("HELM_BINARY_UNTRUSTED")
    if hashlib.sha256(HELM.read_bytes()).hexdigest() != HELM_SHA256:
        raise AssertionError("HELM_BINARY_DIGEST_MISMATCH")


def render(profile: str) -> bytes:
    verify_helm()
    completed = subprocess.run([str(HELM), "template", "planeon", str(CHART), "--namespace", "planeon-system", "--kube-version", "1.31.0", "--values", str(PROFILES / f"{profile}.yaml")], shell=False, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"HOME": "/tmp", "PATH": "/opt/planeon/bin:/usr/bin:/bin"})
    if completed.returncode:
        raise AssertionError("HELM_RENDER_FAILED:" + completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


def sources(output: bytes) -> set[str]:
    return set(SOURCE.findall(output.decode("utf-8")))


def documents(output: bytes) -> list[str]:
    return [item for item in output.decode("utf-8").split("---") if "\nkind:" in item]
