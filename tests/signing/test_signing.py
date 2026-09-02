from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.signing import SigningError, sign_candidate, verify_signed_release
from tests.signing.helpers import NOW, prepare


class SigningTests(unittest.TestCase):
    def test_component_and_root_signatures_verify_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = prepare(root)
            destination = root / "signed"
            result = sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], destination, NOW)
            self.assertEqual(result["state"], "SIGNED")
            self.assertEqual(verify_signed_release(destination, NOW), result)
            self.assertEqual(len(list((destination / "components").glob("*.sigstore.json"))), 2)
            self.assertFalse(any(path.suffix == ".key" for path in destination.rglob("*")))

    def test_mutated_component_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = prepare(root)
            destination = root / "signed"
            sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], destination, NOW)
            payload_path = next((destination / "components").glob("*.json"))
            payload = json.loads(payload_path.read_text())
            payload["platform"] = "linux/amd64"
            payload_path.write_bytes(encode(payload))
            with self.assertRaisesRegex(SigningError, "SIGNED_COMPONENT_DIGEST_MISMATCH"):
                verify_signed_release(destination, NOW)

    def test_wrong_release_private_key_fails_without_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = prepare(root)
            destination = root / "signed"
            with self.assertRaisesRegex(SigningError, "COSIGN_OPERATION_FAILED"):
                sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["approvalPrivate"], destination, NOW)
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.glob(".planeon-signed-*")), [])

    def test_missing_or_forged_approval_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = prepare(root)
            fixture["approvalBundle"].write_bytes(b"{}\n")
            with self.assertRaisesRegex(SigningError, "COSIGN_OPERATION_FAILED"):
                sign_candidate(fixture["bundle"], fixture["approvalPath"], fixture["approvalBundle"], fixture["trustPath"], fixture["publicKeys"], fixture["releaseId"], fixture["releasePrivate"], root / "signed", NOW)


if __name__ == "__main__":
    unittest.main()
