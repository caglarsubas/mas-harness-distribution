#!/usr/bin/env python3
"""Deterministic static admission for the repository's zero-bill boundary."""

from __future__ import annotations

import re
import sys
from pathlib import Path

TEXT_SUFFIXES = {"", ".json", ".md", ".py", ".sh", ".toml", ".yaml", ".yml"}
FORBIDDEN = {
    "HOSTED_RUNNER": re.compile(r"runs-on:\s*(?:ubuntu|windows|macos)-", re.I),
    "GITHUB_STORAGE": re.compile(r"actions/(?:cache|upload-artifact|download-artifact)@|ghcr\.io|github packages", re.I),
    "CLOUD_PROVISIONING": re.compile(r"\b(?:terraform apply|pulumi up|aws_[a-z]|google_[a-z]|azurerm_[a-z])\b", re.I),
    "PAID_OR_KEYED_API": re.compile(r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|STRIPE_SECRET_KEY)\b"),
    "EXTERNAL_TELEMETRY": re.compile(r"(?:sentry\.io|datadoghq\.com|newrelic\.com)", re.I),
    "RUNTIME_DOWNLOAD": re.compile(r"\b(?:curl|wget)\b.+https?://|playwright\s+install|pip\s+install|uv\s+sync|docker\s+pull", re.I),
    "MUTABLE_IMAGE": re.compile(r"(?:image|container)[^\n]{0,80}:[ \t]*[^\s@]+:latest\b", re.I),
}
ALLOWED_DOCUMENTARY = {"README.md", "SECURITY.md", "CONTRIBUTING.md", "schemas/oci-layout-shell.schema.json"}
SCAN_EXCLUSIONS = {"ci/zero_bill_scan.py"}


def scan(root: Path) -> list[str]:
    failures: list[str] = []
    workflow = root / ".github/workflows/verify.yml"
    if not workflow.is_file():
        failures.append("WORKFLOW_MISSING:.github/workflows/verify.yml")
    else:
        body = workflow.read_text(encoding="utf-8")
        required = ["self-hosted", "harness-engineering", "ephemeral", "credential-free", "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "persist-credentials: false", "/opt/planeon/bin/harness-offline-launch"]
        for token in required:
            if token not in body:
                failures.append(f"WORKFLOW_BOUNDARY_MISSING:{token}")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        if relative in SCAN_EXCLUSIONS or relative.startswith("tests/"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for code, pattern in FORBIDDEN.items():
            if relative in ALLOWED_DOCUMENTARY and code in {"GITHUB_STORAGE", "CLOUD_PROVISIONING", "PAID_OR_KEYED_API", "EXTERNAL_TELEMETRY", "RUNTIME_DOWNLOAD"}:
                continue
            if pattern.search(text):
                failures.append(f"{code}:{relative}")
    return failures


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: zero_bill_scan.py ROOT", file=sys.stderr)
        return 2
    failures = scan(Path(argv[1]).resolve())
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("zero-bill scan passed: local-only tools, self-hosted CI, no paid/API-key/cloud/runtime-download path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
