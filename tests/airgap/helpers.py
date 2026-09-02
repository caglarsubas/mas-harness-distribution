from __future__ import annotations

import json
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.promotion import promote
from planeon_distribution.sbom import generate_spdx_bytes, load_inventory
from planeon_distribution.signing import sign_candidate
from tests.signing.helpers import NOW, ROOT, SUPPLY, prepare


def released_fixture(root: Path) -> Path:
    fixture = prepare(root)
    signed = root / "signed"
    signed_record = sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], signed, NOW)
    releases = root / "releases"
    releases.mkdir()
    promote(fixture["bundle"], signed, releases, NOW)
    return releases / signed_record["releaseDigest"].removeprefix("sha256:")


def evidence_map(root: Path, released: Path) -> dict[str, Path]:
    evidence_root = root / "evidence-source"
    evidence_root.mkdir()
    mapping = {
        "license-policy.json": ROOT / "policies/license-policy.json",
        "vulnerability-policy.json": ROOT / "policies/vulnerability-policy.json",
        "vulnerability-db.json": SUPPLY / "vulnerability-db.json",
        "dispositions.json": SUPPLY / "dispositions.json",
        "model-custody.json": SUPPLY / "model-custody.json",
    }
    inventory, _, _ = load_inventory(released / "bundle/bundle.lock.json", SUPPLY / "component-inventory.json")
    import hashlib
    for component in inventory["components"]:
        data = generate_spdx_bytes(component)
        digest = hashlib.sha256(data).hexdigest()
        path = evidence_root / f"{digest}.spdx.json"
        path.write_bytes(data)
        mapping[f"sbom/{digest}.spdx.json"] = path
    return mapping
