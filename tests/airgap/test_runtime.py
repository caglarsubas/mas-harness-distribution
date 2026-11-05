"""Air-gap runtime: nothing the distribution ships or runs can reach a network or a mutable reference."""

from __future__ import annotations

import ast
import errno
import io
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from planeon_distribution import signing
from planeon_distribution.airgap import MAX_ARCHIVE_BYTES, MAX_FILE_BYTES, AirgapError, export_archive, import_archive
from planeon_distribution.builder import build_bundle
from planeon_distribution.canonical import decode, encode
from planeon_distribution.oci import MAX_FILE_BYTES as MAX_BLOB_BYTES
from planeon_distribution.promotion import promote
from planeon_distribution.resolver import resolve_profile
from planeon_distribution.sbom import build_evidence, generate_spdx_bytes, load_inventory, publish_evidence
from tests.airgap.helpers import evidence_map, released_fixture
from tests.signing.helpers import NOW, SUPPLY, keypair, prepare, sha, trust_document, trust_key, write

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = [*sorted((ROOT / "src/planeon_distribution").glob("*.py")), *sorted((ROOT / "cmd/harness-bundlectl").glob("*.py")), *sorted((ROOT / "scripts").glob("*.py"))]
NETWORK_MODULES = {"aiohttp", "asyncio", "ftplib", "http", "httpx", "imaplib", "poplib", "requests", "smtplib", "socket", "socketserver", "ssl", "telnetlib", "urllib", "urllib3", "xmlrpc"}
# The same OS denial errnos the offline network canary accepts for each isolation backend.
DENIAL_ERRNOS = {"darwin-sandbox": {errno.EACCES, errno.EPERM}, "linux-firejail": {errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH}}


def imported_modules(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in (*strings(key), *strings(child))]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


class AirgapRuntimeTests(unittest.TestCase):
    def test_shipped_code_imports_no_network_module(self) -> None:
        self.assertGreater(len(SHIPPED), 15)
        for path in SHIPPED:
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertEqual(imported_modules(path) & NETWORK_MODULES, set())

    def test_external_signing_tool_runs_offline_with_a_closed_environment(self) -> None:
        calls: list[tuple[list[str], dict[str, str]]] = []
        real_run = subprocess.run

        def recording_run(command: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            calls.append((list(command), dict(kwargs["env"])))
            return real_run(command, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = prepare(root)
            with mock.patch.object(signing.subprocess, "run", recording_run):
                signing.sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], root / "signed", NOW)
                signing.verify_signed_release(root / "signed", NOW)
        self.assertTrue(calls)
        operations = {command[1] for command, _ in calls}
        self.assertEqual(operations, {"sign-blob", "verify-blob"})
        for command, environment in calls:
            with self.subTest(command=command[1]):
                self.assertEqual(command[0], str(signing.COSIGN))
                self.assertFalse(any("://" in argument for argument in command))
                if command[1] == "sign-blob":
                    self.assertIn("--tlog-upload=false", command)
                    self.assertIn("--use-signing-config=false", command)
                else:
                    self.assertIn("--offline", command)
                    self.assertIn("--insecure-ignore-tlog", command)
                self.assertLessEqual(set(environment), {"COSIGN_PASSWORD", "HOME", "PATH"})
                self.assertEqual(environment["PATH"], "/opt/planeon/bin:/usr/bin:/bin")

    def test_imported_release_holds_no_remote_or_mutable_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released = released_fixture(root)
            archive = root / "transfer.tar"
            exported = export_archive(released, evidence_map(root, released), archive, NOW)
            imported = root / "imported"
            import_archive(archive, exported["archiveDigest"], imported, NOW)
            documents = sorted(path for path in imported.rglob("*.json") if path.is_file())
            self.assertGreater(len(documents), 10)
            for path in documents:
                # Cosign's sigstore bundles are valid JSON but not this repository's canonical form.
                values = strings(decode(path.read_bytes(), require_canonical=False))
                with self.subTest(path=path.relative_to(imported).as_posix()):
                    self.assertFalse([value for value in values if "://" in value or ":latest" in value.casefold()])

    def test_outbound_connection_is_denied_by_the_os_inside_the_offline_session(self) -> None:
        backend = os.environ.get("HARNESS_OFFLINE_BACKEND", "")
        if os.environ.get("HARNESS_OFFLINE_ENFORCED") != "1" or backend not in DENIAL_ERRNOS:
            self.skipTest("runs only inside the OS-enforced offline session; never probes an open network")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(0.5)
                result = client.connect_ex(("1.1.1.1", 443))
        except OSError as exc:
            result = exc.errno
        self.assertIn(result, DENIAL_ERRNOS[backend])


LAYER_COUNT = 5


def large_source(root: Path) -> tuple[Path, Path, str]:
    """The fixture layout with five extra 1 MiB layers: a valid release whose transfer archive exceeds 4 MiB."""
    source = root / "large-layout"
    shutil.copytree(ROOT / "fixtures/oci-layout", source, copy_function=shutil.copyfile)
    blobs = source / "blobs/sha256"
    index = decode((source / "index.json").read_bytes())
    entry = index["manifests"][0]
    old_manifest = entry["digest"].removeprefix("sha256:")
    manifest = decode((blobs / old_manifest).read_bytes())
    for number in range(LAYER_COUNT):
        data = f"planeon-large-layer-{number}\n".encode().ljust(MAX_BLOB_BYTES, b"\0")
        (blobs / sha(data).removeprefix("sha256:")).write_bytes(data)
        manifest["layers"].append({"digest": sha(data), "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(data)})
    manifest_bytes = encode(manifest)
    (blobs / old_manifest).unlink()
    (blobs / sha(manifest_bytes).removeprefix("sha256:")).write_bytes(manifest_bytes)
    old_image = entry["digest"]
    entry["digest"], entry["size"] = sha(manifest_bytes), len(manifest_bytes)
    (source / "index.json").write_bytes(encode(index))
    profile = decode((ROOT / "fixtures/profiles/minimal-arm64.json").read_bytes())
    for module in profile["modules"]:
        for artifact in module["artifacts"]:
            if artifact["digest"] == old_image:
                artifact["digest"], artifact["size"] = entry["digest"], entry["size"]
    payload = {key: value for key, value in profile.items() if key != "profileDigest"}
    profile["profileDigest"] = sha(encode(payload))
    profile_path = root / "large-profile.json"
    profile_path.write_bytes(encode(profile))
    return source, profile_path, old_image


def large_release(root: Path) -> tuple[Path, dict[str, Path]]:
    """Build, scan, sign and promote the large layout with the repository's own flow and fixture policies."""
    source, profile, old_image = large_source(root)
    bundle = root / "bundle"
    build_bundle(resolve_profile(profile, source), source, bundle)
    lock_digest = sha((bundle / "bundle.lock.json").read_bytes())
    image = decode((bundle / "bundle.lock.json").read_bytes())
    new_image = next(item["digest"] for item in image["components"] if item["kind"] == "image")
    inventory = decode((SUPPLY / "component-inventory.json").read_bytes())
    inventory["bundleLockDigest"] = lock_digest
    for component in inventory["components"]:
        if component["artifactDigest"] == old_image:
            component["artifactDigest"] = new_image
            component["custodyEvidence"]["sourceCommit"] = new_image
            component["source"] = component["source"].replace(old_image, new_image)
    custody = {**decode((SUPPLY / "model-custody.json").read_bytes()), "bundleLockDigest": lock_digest}
    inventory_path, custody_path = root / "inventory.json", root / "model-custody.json"
    write(inventory_path, inventory)
    write(custody_path, custody)
    publish_evidence(build_evidence(bundle / "bundle.lock.json", inventory_path, ROOT / "policies/license-policy.json", ROOT / "policies/vulnerability-policy.json", SUPPLY / "vulnerability-db.json", SUPPLY / "dispositions.json", custody_path), bundle / "supply-chain.evidence.json")
    approval_id, approval_private, approval_public = keypair(root, "approval")
    release_id, release_private, release_public = keypair(root, "release")
    trust = trust_document([trust_key(approval_id, approval_public, ["RELEASE_APPROVAL"]), trust_key(release_id, release_public, ["BUNDLE_RELEASE"])])
    write(root / "trust.json", trust)
    approval_payload = {
        "approvalKeyId": approval_id,
        "authority": "release-board",
        "authorizedReleaseKeyIds": [release_id],
        "bundleLockDigest": lock_digest,
        "evidenceDigest": sha((bundle / "supply-chain.evidence.json").read_bytes()),
        "notAfter": "2026-10-01T00:00:00Z",
        "notBefore": "2026-09-01T00:00:00Z",
        "organizationId": "org-white-goods",
        "profileId": image["profileId"],
        "schemaVersion": "harness.planeon.ai/release-approval/v1alpha1",
        "trustBundleDigest": trust["trustBundleDigest"],
    }
    write(root / "approval.json", {**approval_payload, "approvalDigest": sha(encode(approval_payload))})
    signing.sign_blob(root / "approval.json", approval_private, root / "approval.sigstore.json")
    keys = {approval_id: approval_public, release_id: release_public}
    record = signing.sign_candidate(bundle, root / "approval.json", root / "approval.sigstore.json", root / "trust.json", keys, release_id, release_private, root / "signed", NOW)
    releases = root / "releases"
    releases.mkdir()
    promote(bundle, root / "signed", releases, NOW)
    released = releases / record["releaseDigest"].removeprefix("sha256:")
    evidence = {
        "license-policy.json": ROOT / "policies/license-policy.json",
        "vulnerability-policy.json": ROOT / "policies/vulnerability-policy.json",
        "vulnerability-db.json": SUPPLY / "vulnerability-db.json",
        "dispositions.json": SUPPLY / "dispositions.json",
        "model-custody.json": custody_path,
    }
    loaded, _, _ = load_inventory(released / "bundle/bundle.lock.json", inventory_path)
    sboms = root / "sbom"
    sboms.mkdir()
    for component in loaded["components"]:
        data = generate_spdx_bytes(component)
        path = sboms / f"{sha(data).removeprefix('sha256:')}.spdx.json"
        path.write_bytes(data)
        evidence[f"sbom/{path.name}"] = path
    return released, evidence


class LargeTransferTests(unittest.TestCase):
    def test_release_archive_over_four_mib_exports_and_imports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            released, evidence = large_release(root)
            archive = root / "transfer.tar"
            exported = export_archive(released, evidence, archive, NOW)
            size = archive.stat().st_size
            self.assertGreater(size, MAX_FILE_BYTES)
            self.assertLessEqual(size, MAX_ARCHIVE_BYTES)
            receipt = import_archive(archive, exported["archiveDigest"], root / "imported", NOW)
            self.assertEqual(receipt["state"], "VERIFIED_IMPORT")
            self.assertEqual(len(list((root / "imported/payload/bundle/oci/blobs/sha256").iterdir())), 3 + LAYER_COUNT)

    def test_member_over_the_file_limit_is_refused_inside_an_admissible_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "member.tar"
            data = b"\0" * (MAX_FILE_BYTES + 1)
            info = tarfile.TarInfo("payload/large")
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0o644, 0, 0, 0, "", ""
            with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
                archive.addfile(info, io.BytesIO(data))
            self.assertLess(path.stat().st_size, MAX_ARCHIVE_BYTES)
            with self.assertRaisesRegex(AirgapError, "ARCHIVE_FILE_TOO_LARGE"):
                import_archive(path, sha(path.read_bytes()), Path(directory) / "imported", NOW)


if __name__ == "__main__":
    unittest.main()
