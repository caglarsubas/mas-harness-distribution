from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from planeon_distribution.canonical import decode, encode

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("run_supply_chain_campaign", ROOT / "scripts/run_supply_chain_campaign.py")
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class SupplyChainCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory()
        cls.work_root = Path(cls.directory.name)
        cls.report = campaign.run_campaign(cls.work_root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.directory.cleanup()

    def test_every_attack_is_refused_with_its_exact_code_and_leaves_nothing_behind(self) -> None:
        for case in self.report["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["observedCode"], case["expected"], case)
                self.assertEqual(case["leftBehind"], [])
                self.assertEqual(case["outcome"], "REFUSED_AS_EXPECTED")
        self.assertEqual(self.report["summary"]["unexpected"], [])

    def test_report_covers_the_whole_catalog_and_every_layer(self) -> None:
        catalog = decode(campaign.CATALOG.read_bytes())
        self.assertEqual([case["id"] for case in self.report["cases"]], [case["id"] for case in catalog["cases"]])
        self.assertEqual(set(self.report["summary"]["layers"]), campaign.LAYERS)
        self.assertEqual(self.report["summary"]["caseCount"], len(catalog["cases"]))
        self.assertEqual(set(campaign.MUTATIONS), {case["id"] for case in catalog["cases"]})

    def test_report_is_canonical_and_carries_no_local_path(self) -> None:
        text = encode(self.report).decode("utf-8")
        self.assertEqual(decode(text.encode("utf-8")), self.report)
        self.assertNotIn(str(self.work_root), text)
        self.assertNotIn("/tmp", text)

    def test_catalog_drift_is_refused(self) -> None:
        catalog = decode(campaign.CATALOG.read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "campaign.json"
            path.write_bytes(encode({**catalog, "cases": catalog["cases"][1:]}))
            with self.assertRaisesRegex(campaign.CampaignError, "CATALOG_CASE_SET_INVALID"):
                campaign.load_catalog(path)
            path.write_bytes(encode({**catalog, "cases": [{**catalog["cases"][0], "layer": "network"}] + catalog["cases"][1:]}))
            with self.assertRaisesRegex(campaign.CampaignError, "CATALOG_CASE_INVALID"):
                campaign.load_catalog(path)


if __name__ == "__main__":
    unittest.main()
