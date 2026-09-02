from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import encode
from planeon_distribution.vulnerabilities import VulnerabilityError, load_database, load_dispositions, load_policy, scan_inventory

ROOT = Path(__file__).resolve().parents[2]
SUPPLY = ROOT / "fixtures/supply-chain"


class VulnerabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, _ = load_policy(ROOT / "policies/vulnerability-policy.json")
        self.database, _ = load_database(SUPPLY / "vulnerability-db.json", self.policy)
        self.dispositions, _ = load_dispositions(SUPPLY / "dispositions.json", self.policy)
        self.components = json.loads((SUPPLY / "component-inventory.json").read_text())["components"]

    def test_offline_snapshot_reports_every_match(self) -> None:
        result = scan_inventory(self.components, self.database, self.policy, self.dispositions)
        self.assertEqual(sum(len(items) for items in result.values()), 2)
        self.assertEqual({item["severity"] for items in result.values() for item in items}, {"LOW", "HIGH"})

    def test_undisposed_high_finding_blocks(self) -> None:
        with self.assertRaisesRegex(VulnerabilityError, "VULNERABILITY_BLOCKING_UNDISPOSED"):
            scan_inventory(self.components, self.database, self.policy, {})

    def test_stale_snapshot_blocks_even_with_recomputed_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = json.loads((SUPPLY / "vulnerability-db.json").read_text())
            database["validThrough"] = "2026-09-01"
            payload = {key: value for key, value in database.items() if key != "databaseDigest"}
            import hashlib
            database["databaseDigest"] = "sha256:" + hashlib.sha256(encode(payload)).hexdigest()
            policy = dict(self.policy)
            policy["databaseDigest"] = database["databaseDigest"]
            db_path = root / "db.json"
            policy_path = root / "policy.json"
            db_path.write_bytes(encode(database))
            policy_path.write_bytes(encode(policy))
            loaded_policy, _ = load_policy(policy_path)
            with self.assertRaisesRegex(VulnerabilityError, "VULNERABILITY_DATABASE_STALE"):
                load_database(db_path, loaded_policy)

    def test_corrupt_snapshot_digest_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db.json"
            database = dict(self.database)
            database["databaseDigest"] = "sha256:" + "0" * 64
            path.write_bytes(encode(database))
            with self.assertRaisesRegex(VulnerabilityError, "VULNERABILITY_DATABASE_DIGEST_MISMATCH"):
                load_database(path, self.policy)

    def test_unreferenced_disposition_blocks(self) -> None:
        components = [item for item in self.components if item["kind"] == "image"]
        with self.assertRaisesRegex(VulnerabilityError, "VULNERABILITY_DISPOSITION_UNREFERENCED"):
            scan_inventory(components, self.database, self.policy, self.dispositions)


if __name__ == "__main__":
    unittest.main()
