#!/usr/bin/env python3
"""Offline adversarial supply-chain campaign over a built, signed, released and exported fixture.

Every case in fixtures/attacks/campaign.json copies a fresh base artifact, applies one hostile mutation and
runs the production operation that must refuse it. A case is REFUSED_AS_EXPECTED only when the refusal code
equals the catalog's code and the operation left no destination behind. Nothing here opens a socket or
reads a mutable input; the base fixture is regenerated from the repository's own fixtures each run.

Run from the repository root with the package importable:
    PYTHONPATH=src python3 -B scripts/run_supply_chain_campaign.py
It prints the canonical JSON report and exits 0 only when every case is REFUSED_AS_EXPECTED.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Callable
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "fixtures/attacks/campaign.json"
CATALOG_SCHEMA = "harness.planeon.ai/supply-chain-attack-catalog/v1alpha1"
REPORT_SCHEMA = "harness.planeon.ai/supply-chain-campaign-report/v1alpha1"
LAYERS = {"archive", "candidate", "export", "layout", "promotion", "revocation", "staging", "transfer"}
LAYER_BLOB = "ce46f075a74ac873c1fb23c8efa90d3f61de82726996b7dfa724a86c21c8b072"
SUBSTITUTE_LAYER = b"planeon-campaign-substituted-layer\n"


class CampaignError(ValueError):
    pass


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_catalog(path: Path = CATALOG) -> tuple[list[dict[str, str]], str]:
    from planeon_distribution.canonical import decode

    data = path.read_bytes()
    catalog = decode(data)
    if not isinstance(catalog, dict) or set(catalog) != {"cases", "schemaVersion"} or catalog["schemaVersion"] != CATALOG_SCHEMA:
        raise CampaignError("CATALOG_INVALID")
    cases = catalog["cases"]
    if not isinstance(cases, list) or not cases:
        raise CampaignError("CATALOG_INVALID")
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"expected", "id", "layer"} or case["layer"] not in LAYERS or case["id"] not in MUTATIONS:
            raise CampaignError("CATALOG_CASE_INVALID")
    ids = [case["id"] for case in cases]
    if ids != sorted(set(ids)) or set(ids) != set(MUTATIONS):
        raise CampaignError("CATALOG_CASE_SET_INVALID")
    return cases, _sha(data)


# ---------------------------------------------------------------- base fixture and file helpers


def prepare_base(root: Path) -> dict[str, Any]:
    from planeon_distribution.airgap import export_archive
    from planeon_distribution.promotion import promote
    from planeon_distribution.signing import sign_candidate
    from tests.airgap.helpers import evidence_map
    from tests.signing.helpers import NOW, prepare

    root.mkdir()
    fixture = prepare(root)
    signed = root / "signed"
    record = sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], signed, NOW)
    releases = root / "releases"
    releases.mkdir()
    promote(fixture["bundle"], signed, releases, NOW)
    released = releases / record["releaseDigest"].removeprefix("sha256:")
    evidence = evidence_map(root, released)
    archive = root / "transfer.tar"
    exported = export_archive(released, evidence, archive, NOW)
    return {**fixture, "archive": archive, "archiveDigest": exported["archiveDigest"], "evidence": evidence, "now": NOW, "released": released, "signed": signed}


def copy_tree(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination, copy_function=shutil.copyfile)
    return destination


def tree_files(root: Path) -> dict[str, bytes]:
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}


def replace_tree(root: Path, files: dict[str, bytes]) -> None:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), reverse=True):
        path.unlink()
    for name, data in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def flip_byte(data: bytes) -> bytes:
    changed = bytearray(data)
    changed[0] ^= 0x01
    return bytes(changed)


def rewrite_layer(files: dict[str, bytes], prefix: str) -> None:
    """Substitute one image layer and re-link manifest and index so the layout itself stays valid."""
    from planeon_distribution.canonical import decode, encode

    blobs = f"{prefix}blobs/sha256/"
    index = decode(files[f"{prefix}index.json"])
    entry = index["manifests"][0]
    old_manifest = entry["digest"].removeprefix("sha256:")
    manifest = decode(files[blobs + old_manifest])
    layer = manifest["layers"][0]
    old_layer = layer["digest"].removeprefix("sha256:")
    layer["digest"], layer["size"] = _sha(SUBSTITUTE_LAYER), len(SUBSTITUTE_LAYER)
    manifest_bytes = encode(manifest)
    entry["digest"], entry["size"] = _sha(manifest_bytes), len(manifest_bytes)
    del files[blobs + old_manifest], files[blobs + old_layer]
    files[blobs + layer["digest"].removeprefix("sha256:")] = SUBSTITUTE_LAYER
    files[blobs + entry["digest"].removeprefix("sha256:")] = manifest_bytes
    files[f"{prefix}index.json"] = encode(index)


def read_archive(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:") as archive:
        return {member.name: archive.extractfile(member).read() for member in archive.getmembers()}


def _member(name: str, data: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0o644, 0, 0, 0, "", ""
    return info


def write_archive(path: Path, files: dict[str, bytes], *, format: int = tarfile.USTAR_FORMAT) -> str:
    with tarfile.open(path, "w", format=format) as archive:
        for name, data in sorted(files.items()):
            archive.addfile(_member(name, data), io.BytesIO(data))
    return _sha(path.read_bytes())


def reseal(files: dict[str, bytes]) -> None:
    """An attacker who controls the transfer medium recomputes every manifest checksum."""
    from planeon_distribution.canonical import decode, encode

    manifest = decode(files["transfer-manifest.json"])
    manifest["entries"] = [{"path": name, "role": "EVIDENCE" if name.startswith("evidence/") else "RELEASE_PAYLOAD", "sha256": _sha(data), "size": len(data)} for name, data in sorted(files.items()) if name != "transfer-manifest.json"]
    files["transfer-manifest.json"] = encode(manifest)


def revoked_trust(base: dict[str, Any], key_id: str) -> dict[str, Any]:
    from tests.signing.helpers import trust_document

    revocation = {"effectiveAt": base["now"], "keyId": key_id, "reasonDigest": "sha256:" + "e" * 64}
    return trust_document(base["trust"]["keys"], [revocation], sequence=base["trust"]["sequence"] + 1)


def reissue_approval(base: dict[str, Any], work: Path, trust: dict[str, Any]) -> tuple[Path, Path]:
    from planeon_distribution.canonical import decode, encode
    from planeon_distribution.signing import sign_blob

    approval = decode(base["approvalPath"].read_bytes())
    payload = {name: value for name, value in approval.items() if name != "approvalDigest"}
    payload["trustBundleDigest"] = trust["trustBundleDigest"]
    path, bundle = work / "approval.json", work / "approval.sigstore.json"
    path.write_bytes(encode({**payload, "approvalDigest": _sha(encode(payload))}))
    sign_blob(path, base["approvalPrivate"], bundle)
    return path, bundle


def write_trust(work: Path, trust: dict[str, Any]) -> Path:
    from planeon_distribution.canonical import encode

    path = work / "trust.json"
    path.write_bytes(encode(trust))
    return path


# ---------------------------------------------------------------- operations under attack


def _verify_layout_copy(base: dict[str, Any], work: Path, mutate: Callable[[Path], None]) -> None:
    from planeon_distribution.oci import verify_layout

    oci = copy_tree(base["bundle"] / "oci", work / "oci")
    mutate(oci)
    verify_layout(oci)


def _build(base: dict[str, Any], work: Path, staging_mutation: Callable[[Path], None] | None = None, source_mutation: Callable[[Path], None] | None = None) -> Path:
    from planeon_distribution import builder, oci
    from planeon_distribution.resolver import resolve_profile

    source = ROOT / "fixtures/oci-layout"
    resolution = resolve_profile(ROOT / "fixtures/profiles/minimal-arm64.json", source)
    if source_mutation is not None:
        source = copy_tree(source, work / "source")
        source_mutation(source)
    destination = work / "bundle"

    def hostile_verify(layout: Path) -> dict[str, Any]:
        staging_mutation(layout)
        return oci.verify_layout(layout)

    if staging_mutation is None:
        builder.build_bundle(resolution, source, destination)
    else:
        with mock.patch.object(builder, "verify_layout", hostile_verify):
            builder.build_bundle(resolution, source, destination)
    return destination


def _sign(base: dict[str, Any], work: Path, bundle: Path, *, trust_path: Path | None = None, approval: tuple[Path, Path] | None = None) -> Path:
    from planeon_distribution.signing import sign_candidate

    approval_path, approval_bundle = approval or (base["approvalPath"], base["approvalBundle"])
    destination = work / "signed"
    sign_candidate(bundle, approval_path, approval_bundle, trust_path or base["trustPath"], base["publicKeys"], base["releaseId"], base["releasePrivate"], destination, base["now"])
    return destination


def _hostile_bundle(base: dict[str, Any], work: Path, mutate: Callable[[dict[str, bytes]], None]) -> Path:
    bundle = copy_tree(base["bundle"], work / "candidate")
    files = tree_files(bundle)
    mutate(files)
    replace_tree(bundle, files)
    return bundle


def _import(base: dict[str, Any], work: Path, mutate: Callable[[dict[str, bytes]], None], *, sealed: bool = True, original_digest: bool = False) -> Path:
    from planeon_distribution.airgap import import_archive

    files = read_archive(base["archive"])
    mutate(files)
    if sealed:
        reseal(files)
    digest = write_archive(work / "hostile.tar", files)
    destination = work / "imported"
    import_archive(work / "hostile.tar", base["archiveDigest"] if original_digest else digest, destination, base["now"])
    return destination


def _import_raw(base: dict[str, Any], work: Path, build: Callable[[Path], str]) -> Path:
    from planeon_distribution.airgap import import_archive

    digest = build(work / "hostile.tar")
    destination = work / "imported"
    import_archive(work / "hostile.tar", digest, destination, base["now"])
    return destination


def _corrupt_layer(files: dict[str, bytes], prefix: str) -> None:
    files[f"{prefix}blobs/sha256/{LAYER_BLOB}"] = flip_byte(files[f"{prefix}blobs/sha256/{LAYER_BLOB}"])


def _extra_blob(files: dict[str, bytes], prefix: str) -> None:
    files[f"{prefix}blobs/sha256/{hashlib.sha256(b'extra').hexdigest()}"] = b"extra"


TRANSFER = "payload/bundle/oci/"


def _layout_symlink(oci: Path) -> None:
    blob = oci / "blobs/sha256" / LAYER_BLOB
    outside = oci.parent / "outside-layer"
    outside.write_bytes(blob.read_bytes())
    blob.unlink()
    blob.symlink_to(outside)


def _revoked_release_sign(base: dict[str, Any], work: Path) -> Path:
    trust = revoked_trust(base, base["releaseId"])
    return _sign(base, work, base["bundle"], trust_path=write_trust(work, trust), approval=reissue_approval(base, work, trust))


def _revoked_approval_sign(base: dict[str, Any], work: Path) -> Path:
    trust = revoked_trust(base, base["approvalId"])
    return _sign(base, work, base["bundle"], trust_path=write_trust(work, trust), approval=reissue_approval(base, work, trust))


def _revocation_stripped_sign(base: dict[str, Any], work: Path) -> Path:
    """Approval was issued under a trust set that revokes the release key; the attacker strips the revocation."""
    from tests.signing.helpers import trust_document

    revoked = revoked_trust(base, base["releaseId"])
    approval = reissue_approval(base, work, revoked)
    stripped = trust_document(revoked["keys"], [], sequence=revoked["sequence"])
    return _sign(base, work, base["bundle"], trust_path=write_trust(work, stripped), approval=approval)


def _released_trust_revoked_export(base: dict[str, Any], work: Path) -> Path:
    from planeon_distribution.airgap import export_archive
    from planeon_distribution.canonical import encode

    released = copy_tree(base["released"], work / "released")
    (released / "release/trust-bundle.json").write_bytes(encode(revoked_trust(base, base["releaseId"])))
    destination = work / "transfer.tar"
    export_archive(released, base["evidence"], destination, base["now"])
    return destination


def _transfer_trust_revoked(files: dict[str, bytes], base: dict[str, Any]) -> None:
    from planeon_distribution.canonical import encode

    files["payload/release/trust-bundle.json"] = encode(revoked_trust(base, base["releaseId"]))


def _promote_hostile(base: dict[str, Any], work: Path, mutate: Callable[[dict[str, bytes]], None]) -> Path:
    from planeon_distribution.promotion import promote

    bundle = _hostile_bundle(base, work, mutate)
    releases = work / "releases"
    releases.mkdir()
    promote(bundle, base["signed"], releases, base["now"])
    return releases


def _export_hostile(base: dict[str, Any], work: Path) -> Path:
    from planeon_distribution.airgap import export_archive

    released = copy_tree(base["released"], work / "released")
    files = tree_files(released)
    rewrite_layer(files, "bundle/oci/")
    replace_tree(released, files)
    destination = work / "transfer.tar"
    export_archive(released, base["evidence"], destination, base["now"])
    return destination


def _bomb_entries(path: Path) -> str:
    from planeon_distribution.airgap import MAX_ENTRIES

    return write_archive(path, {f"payload/bomb/{index:04d}": b"" for index in range(MAX_ENTRIES + 1)})


def _bomb_oversize(path: Path) -> str:
    """Members each under the 4 MiB file limit, in an archive under 16 MiB, whose total exceeds 12 MiB."""
    from planeon_distribution.airgap import MAX_FILE_BYTES, MAX_TOTAL_BYTES

    size = MAX_FILE_BYTES * 7 // 8
    count = MAX_TOTAL_BYTES // size + 1
    return write_archive(path, {f"payload/bomb/{index}": b"\0" * size for index in range(count)})


def _bomb_gzip(path: Path) -> str:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        data = b"\0" * (8 * 1024 * 1024)
        archive.addfile(_member("payload/bomb", data), io.BytesIO(data))
    path.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
    return _sha(path.read_bytes())


def _deep_path(path: Path) -> str:
    from planeon_distribution.airgap import MAX_DEPTH

    return write_archive(path, {"/".join(["payload"] + ["d"] * MAX_DEPTH): b"{}\n"})


def _long_path(path: Path) -> str:
    from planeon_distribution.airgap import MAX_PATH_BYTES

    return write_archive(path, {"payload/" + "n" * MAX_PATH_BYTES: b"{}\n"}, format=tarfile.GNU_FORMAT)


def _drop_layer(files: dict[str, bytes]) -> None:
    del files[f"{TRANSFER}blobs/sha256/{LAYER_BLOB}"]


def _staging_extra(layout: Path) -> None:
    (layout / "blobs/sha256" / hashlib.sha256(b"extra").hexdigest()).write_bytes(b"extra")


def _staging_swap(layout: Path) -> None:
    blob = layout / "blobs/sha256" / LAYER_BLOB
    blob.chmod(0o644)
    blob.write_bytes(flip_byte(blob.read_bytes()))


def _source_corrupt(source: Path) -> None:
    blob = source / "blobs/sha256" / LAYER_BLOB
    blob.write_bytes(flip_byte(blob.read_bytes()))


MUTATIONS: dict[str, Callable[[dict[str, Any], Path], Path | None]] = {
    "archive-deep-path": lambda base, work: _import_raw(base, work, _deep_path),
    "archive-entry-count-bomb": lambda base, work: _import_raw(base, work, _bomb_entries),
    "archive-gzip-bomb": lambda base, work: _import_raw(base, work, _bomb_gzip),
    "archive-long-path": lambda base, work: _import_raw(base, work, _long_path),
    "archive-oversize-bomb": lambda base, work: _import_raw(base, work, _bomb_oversize),
    "build-source-blob-corrupt": lambda base, work: _build(base, work, source_mutation=_source_corrupt),
    "build-staging-blob-swap": lambda base, work: _build(base, work, staging_mutation=_staging_swap),
    "build-staging-extra-blob": lambda base, work: _build(base, work, staging_mutation=_staging_extra),
    "export-released-layer-rewrite": _export_hostile,
    "import-checksum-not-resealed": lambda base, work: _import(base, work, lambda files: _corrupt_layer(files, TRANSFER), sealed=False),
    "import-original-digest-after-tamper": lambda base, work: _import(base, work, lambda files: _corrupt_layer(files, TRANSFER), original_digest=True),
    "import-resealed-corrupt-blob": lambda base, work: _import(base, work, lambda files: _corrupt_layer(files, TRANSFER)),
    "import-resealed-extra-blob": lambda base, work: _import(base, work, lambda files: _extra_blob(files, TRANSFER)),
    "import-resealed-layer-rewrite": lambda base, work: _import(base, work, lambda files: rewrite_layer(files, TRANSFER)),
    "import-resealed-missing-blob": lambda base, work: _import(base, work, _drop_layer),
    "import-resealed-trust-revoked": lambda base, work: _import(base, work, lambda files: _transfer_trust_revoked(files, base)),
    "import-unlisted-member": lambda base, work: _import(base, work, lambda files: files.update({"payload/unlisted.json": b"{}\n"}), sealed=False),
    "layout-corrupt-blob": lambda base, work: _verify_layout_copy(base, work, lambda oci: (oci / "blobs/sha256" / LAYER_BLOB).write_bytes(flip_byte((oci / "blobs/sha256" / LAYER_BLOB).read_bytes()))),
    "layout-extra-blob": lambda base, work: _verify_layout_copy(base, work, lambda oci: (oci / "blobs/sha256" / hashlib.sha256(b"extra").hexdigest()).write_bytes(b"extra")),
    "layout-missing-blob": lambda base, work: _verify_layout_copy(base, work, lambda oci: (oci / "blobs/sha256" / LAYER_BLOB).unlink()),
    "layout-symlink-blob": lambda base, work: _verify_layout_copy(base, work, _layout_symlink),
    "layout-truncated-blob": lambda base, work: _verify_layout_copy(base, work, lambda oci: (oci / "blobs/sha256" / LAYER_BLOB).write_bytes((oci / "blobs/sha256" / LAYER_BLOB).read_bytes()[:-1])),
    "promote-corrupt-blob": lambda base, work: _promote_hostile(base, work, lambda files: _corrupt_layer(files, "oci/")),
    "promote-layer-rewrite": lambda base, work: _promote_hostile(base, work, lambda files: rewrite_layer(files, "oci/")),
    "sign-candidate-corrupt-blob": lambda base, work: _sign(base, work, _hostile_bundle(base, work, lambda files: _corrupt_layer(files, "oci/"))),
    "sign-candidate-extra-blob": lambda base, work: _sign(base, work, _hostile_bundle(base, work, lambda files: _extra_blob(files, "oci/"))),
    "sign-candidate-layer-rewrite": lambda base, work: _sign(base, work, _hostile_bundle(base, work, lambda files: rewrite_layer(files, "oci/"))),
    "sign-revocation-stripped": _revocation_stripped_sign,
    "sign-revoked-approval-key": _revoked_approval_sign,
    "sign-revoked-release-key": _revoked_release_sign,
    "export-release-trust-revoked": _released_trust_revoked_export,
}

# Where each operation would have published; a refused case must leave none of these behind.
DESTINATIONS = ("bundle", "signed", "imported", "transfer.tar", "releases")


def _left_behind(work: Path) -> list[str]:
    result = []
    for name in DESTINATIONS:
        path = work / name
        if name == "releases" and path.is_dir():
            if any(path.iterdir()):
                result.append(name)
        elif path.exists() or path.is_symlink():
            result.append(name)
    return result


def run_campaign(work_root: Path, catalog_path: Path = CATALOG) -> dict[str, Any]:
    cases, catalog_digest = load_catalog(catalog_path)
    base = prepare_base(work_root / "base")
    results = []
    for case in cases:
        work = work_root / "cases" / case["id"]
        work.mkdir(parents=True)
        observed_error, observed_code = "NONE", "ACCEPTED"
        try:
            MUTATIONS[case["id"]](base, work)
        except ValueError as exc:
            observed_error, observed_code = type(exc).__name__, str(exc)
        left = _left_behind(work)
        outcome = "REFUSED_AS_EXPECTED" if observed_code == case["expected"] and not left else "UNEXPECTED"
        results.append({"expected": case["expected"], "id": case["id"], "layer": case["layer"], "leftBehind": left, "observedCode": observed_code, "observedError": observed_error, "outcome": outcome})
    unexpected = sorted(item["id"] for item in results if item["outcome"] != "REFUSED_AS_EXPECTED")
    return {
        "cases": results,
        "catalogDigest": catalog_digest,
        "schemaVersion": REPORT_SCHEMA,
        "summary": {"caseCount": len(results), "layers": sorted({item["layer"] for item in results}), "refusedAsExpected": len(results) - len(unexpected), "unexpected": unexpected},
        "verificationTime": base["now"],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: run_supply_chain_campaign.py", file=sys.stderr)
        return 2
    for path in (ROOT, ROOT / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from planeon_distribution.canonical import encode

    with tempfile.TemporaryDirectory(prefix="planeon-campaign-") as directory:
        report = run_campaign(Path(directory))
    sys.stdout.write(encode(report).decode("utf-8"))
    return 0 if not report["summary"]["unexpected"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
