from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("run_make_target", ROOT / "ci/run_make_target.py")
assert SPEC and SPEC.loader
dispatcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dispatcher
SPEC.loader.exec_module(dispatcher)


def descriptor(packet: str = "TEST-001", target: str = "verify", executable: str = "true", variables: dict | None = None) -> dict:
    return {"packetId": packet, "schemaVersion": dispatcher.SCHEMA, "targets": [{"acceptedVariables": variables or {}, "argvTemplate": [[executable]], "name": target}]}


class DispatchTests(unittest.TestCase):
    def write(self, root: Path, name: str, value: object) -> None:
        (root / name).write_text(json.dumps(value), encoding="utf-8")

    def test_valid_direct_argv_executes_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "test-001.json", descriptor())
            with patch.object(dispatcher.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertEqual(dispatcher.dispatch("verify", {}, root), 0)
                run.assert_called_once_with(("true",), shell=False, check=False)

    def test_unknown_duplicate_owner_filename_and_shell_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "test-001.json", descriptor())
            with self.assertRaisesRegex(dispatcher.DescriptorError, "zero applicable"):
                dispatcher.dispatch("missing", {}, root)
            self.write(root, "wrong.json", descriptor("WRONG-001"))
            with self.assertRaisesRegex(dispatcher.DescriptorError, "owner or filename"):
                dispatcher.load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write(root, "test-001.json", descriptor(executable="sh"))
            with self.assertRaisesRegex(dispatcher.DescriptorError, "shell transport"):
                dispatcher.load_rules(root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = descriptor()
            value["targets"].append(dict(value["targets"][0]))
            self.write(root, "test-001.json", value)
            with self.assertRaisesRegex(dispatcher.DescriptorError, "duplicate or overlapping"):
                dispatcher.load_rules(root)

    def test_malformed_duplicate_json_undeclared_and_ambiguous_are_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test-001.json").write_text('{"packetId":"TEST-001","packetId":"TEST-001"}', encoding="utf-8")
            with self.assertRaises(dispatcher.DescriptorError):
                dispatcher.load_rules(root)
        with self.assertRaisesRegex(dispatcher.DescriptorError, "undeclared Make variable"):
            dispatcher.supplied_variables({"MAKEOVERRIDES": "SECRET=x", "SECRET": "x"})
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(dispatcher.DescriptorError, "no target descriptors"):
                dispatcher.load_rules(Path(directory))

    def test_make_fallback_reaches_only_the_closed_dispatcher(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertEqual(makefile.count("python3 ci/run_make_target.py $@"), 2)
        self.assertIn(".DEFAULT:", makefile)
        for forbidden in ("$(eval", "$(shell", "include ", "$(MAKE)", "`", "$()"):
            self.assertNotIn(forbidden, makefile)
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(["make", "future-packet-target"], cwd=ROOT, env=environment, shell=False, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn("zero applicable handlers: future-packet-target", result.stderr)
        self.assertNotIn("No rule to make target", result.stderr)


if __name__ == "__main__":
    unittest.main()
