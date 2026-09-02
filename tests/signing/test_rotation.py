from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.signing import SigningError, load_trust
from tests.signing.helpers import keypair, sha, trust_document, trust_key, write


class RotationTests(unittest.TestCase):
    def test_old_and_new_release_keys_are_admitted_only_in_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_id, _, old_public = keypair(root, "old")
            new_id, _, new_public = keypair(root, "new")
            trust = trust_document([
                trust_key(old_id, old_public, ["BUNDLE_RELEASE"], "RETIRING", not_after="2026-09-15T00:00:00Z"),
                trust_key(new_id, new_public, ["BUNDLE_RELEASE"], "ACTIVE", not_before="2026-09-01T00:00:00Z"),
            ], sequence=2)
            path = root / "trust.json"
            write(path, trust)
            keys = {old_id: old_public, new_id: new_public}
            load_trust(path, keys, "BUNDLE_RELEASE", old_id, "2026-09-02T00:00:00Z")
            load_trust(path, keys, "BUNDLE_RELEASE", new_id, "2026-09-02T00:00:00Z")
            with self.assertRaisesRegex(SigningError, "TRUST_KEY_OUTSIDE_VALIDITY"):
                load_trust(path, keys, "BUNDLE_RELEASE", old_id, "2026-09-15T00:00:00Z")

    def test_effective_revocation_overrides_active_or_retiring(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_id, _, public = keypair(root, "release")
            revocation = {"effectiveAt": "2026-09-02T00:00:00Z", "keyId": key_id, "reasonDigest": "sha256:" + "d" * 64}
            trust = trust_document([trust_key(key_id, public, ["BUNDLE_RELEASE"], "ACTIVE")], [revocation], sequence=3)
            path = root / "trust.json"
            write(path, trust)
            with self.assertRaisesRegex(SigningError, "TRUST_KEY_REVOKED"):
                load_trust(path, {key_id: public}, "BUNDLE_RELEASE", key_id, "2026-09-02T00:00:00Z")

    def test_role_cannot_be_widened(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_id, _, public = keypair(root, "approval")
            path = root / "trust.json"
            write(path, trust_document([trust_key(key_id, public, ["RELEASE_APPROVAL"])]))
            with self.assertRaisesRegex(SigningError, "TRUST_KEY_OR_ROLE_NOT_ADMITTED"):
                load_trust(path, {key_id: public}, "BUNDLE_RELEASE", key_id, "2026-09-02T00:00:00Z")

    def test_trust_sequence_rollback_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_id, _, public = keypair(root, "release")
            path = root / "trust.json"
            write(path, trust_document([trust_key(key_id, public, ["BUNDLE_RELEASE"])], sequence=2))
            with self.assertRaisesRegex(SigningError, "TRUST_SEQUENCE_INVALID"):
                load_trust(path, {key_id: public}, "BUNDLE_RELEASE", key_id, "2026-09-02T00:00:00Z", minimum_sequence=3)


if __name__ == "__main__":
    unittest.main()
