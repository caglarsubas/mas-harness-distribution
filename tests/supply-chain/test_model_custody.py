from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.licenses import load_policy
from planeon_distribution.model_custody import ModelCustodyError, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "fixtures/supply-chain"
LOCK_DIGEST = "sha256:df70e01f6c5e9462fd8fade93d05c60ecb525e71d81fe825b4f1457afa460170"


def valid_model() -> dict[str, object]:
    artifact = "sha256:" + "a" * 64
    payload: dict[str, object] = {
        "approvingAuthority": "model-risk-board",
        "architecture": "arm64",
        "artifactDigest": artifact,
        "licenseExpression": "Apache-2.0",
        "modelId": "model.fixture-small",
        "quantization": "Q4_K_M",
        "redistributable": True,
        "source": "urn:planeon:model-source:fixture-small:" + artifact,
        "tokenizerDigest": "sha256:" + "b" * 64,
    }
    return {**payload, "approvalDigest": "sha256:" + hashlib.sha256(encode(payload)).hexdigest()}


class ModelCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, _ = load_policy(ROOT / "policies/license-policy.json")

    def test_explicit_empty_model_set_is_admitted(self) -> None:
        records, digest = validate_manifest(SUPPLY / "model-custody.json", LOCK_DIGEST, [], self.policy)
        self.assertEqual(records, [])
        self.assertTrue(digest.startswith("sha256:"))

    def test_exact_model_custody_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models.json"
            path.write_bytes(encode({"bundleLockDigest": LOCK_DIGEST, "models": [valid_model()], "schemaVersion": "harness.planeon.ai/model-custody-manifest/v1alpha1"}))
            records, _ = validate_manifest(path, LOCK_DIGEST, ["model.fixture-small"], self.policy)
            self.assertEqual(records[0]["licenseClassification"], "DEFAULT_ALLOWED")

    def test_redistribution_denial_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = valid_model()
            model["redistributable"] = False
            payload = {key: value for key, value in model.items() if key != "approvalDigest"}
            model["approvalDigest"] = "sha256:" + hashlib.sha256(encode(payload)).hexdigest()
            path = Path(directory) / "models.json"
            path.write_bytes(encode({"bundleLockDigest": LOCK_DIGEST, "models": [model], "schemaVersion": "harness.planeon.ai/model-custody-manifest/v1alpha1"}))
            with self.assertRaisesRegex(ModelCustodyError, "MODEL_REDISTRIBUTION_DENIED"):
                validate_manifest(path, LOCK_DIGEST, ["model.fixture-small"], self.policy)

    def test_mutable_source_and_bad_approval_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, mutate, code in [
                ("mutable", lambda model: model.__setitem__("source", "https://example.invalid/model/latest"), "MODEL_SOURCE_MUTABLE"),
                ("approval", lambda model: model.__setitem__("approvalDigest", "sha256:" + "0" * 64), "MODEL_APPROVAL_INVALID"),
            ]:
                model = valid_model()
                mutate(model)
                path = root / f"{name}.json"
                path.write_bytes(encode({"bundleLockDigest": LOCK_DIGEST, "models": [model], "schemaVersion": "harness.planeon.ai/model-custody-manifest/v1alpha1"}))
                with self.subTest(name=name), self.assertRaisesRegex(ModelCustodyError, code):
                    validate_manifest(path, LOCK_DIGEST, ["model.fixture-small"], self.policy)

    def test_missing_or_unreferenced_model_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models.json"
            path.write_bytes(encode({"bundleLockDigest": LOCK_DIGEST, "models": [valid_model()], "schemaVersion": "harness.planeon.ai/model-custody-manifest/v1alpha1"}))
            with self.assertRaisesRegex(ModelCustodyError, "MODEL_CUSTODY_INCOMPLETE_OR_UNREFERENCED"):
                validate_manifest(path, LOCK_DIGEST, [], self.policy)


if __name__ == "__main__":
    unittest.main()
