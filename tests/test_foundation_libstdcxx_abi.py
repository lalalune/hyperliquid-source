#!/usr/bin/env python3
"""Focused controls for the committed node #115 version-need checker.

The test loads tools/foundation_libstdcxx_abi.py as a module and runs its real
derive/authenticate/compare_packet path against the packet saved under
research/work-items/RE-002-node115-libstdcxx-abi/. The pinned capture is read
in place; it is never executed, copied or written. The environment variable
SLOP_SKIP_SLOW_TESTS is not consulted: a missing capture skips the class so
that offline tooling checks still run on machines without the pinned inputs.
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL_PATH = os.path.join(REPO_ROOT, "tools", "foundation_libstdcxx_abi.py")
PACKET = os.path.join(REPO_ROOT, "research", "work-items", "RE-002-node115-libstdcxx-abi")


def load_checker(path):
    spec = importlib.util.spec_from_file_location("foundation_libstdcxx_abi_under_test", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker(TOOL_PATH)
TARGET = CHECKER.target_path(REPO_ROOT)


@unittest.skipUnless(os.path.isfile(TARGET), "pinned node #115 capture is not materialized")
class FoundationLibstdcxxAbiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = CHECKER.read_bytes(TARGET)
        cls.digest = CHECKER.authenticate(cls.data)
        cls.result = {"target": {"sha256": cls.digest, "size": len(cls.data)}}
        cls.result.update(CHECKER.derive(cls.data))

    def saved_evidence(self):
        with open(os.path.join(PACKET, "evidence.json"), "r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_derivation_matches_the_saved_packet(self):
        self.assertEqual(self.digest, CHECKER.TARGET_SHA256)
        self.assertEqual(len(self.data), CHECKER.TARGET_SIZE)
        self.assertEqual(self.result["dynsym"]["symbols"], 510)
        self.assertEqual(self.result["dynsym"]["version_indices"], 510)
        self.assertEqual(self.result["dynsym"]["version_carriers"], 498)
        self.assertEqual(self.result["dynsym"]["defined_nonempty_versioned"], 0)
        self.assertEqual(self.result["version_need"]["addr"], "0x370c")
        self.assertEqual(self.result["version_need"]["num"], 7)
        self.assertEqual(self.result["version_need"]["indices"], 53)
        self.assertEqual(self.result["needed"][0], "libstdc++.so.6")
        self.assertTrue(CHECKER.compare_packet(PACKET, self.result))

    def test_compare_packet_rejects_a_modified_record(self):
        evidence = self.saved_evidence()
        evidence["derived"]["dynsym"]["version_carriers"] += 1
        with tempfile.TemporaryDirectory() as temp:
            with open(os.path.join(temp, "evidence.json"), "w", encoding="utf-8") as handle:
                json.dump(evidence, handle)
            with self.assertRaises(CHECKER.DerivationError):
                CHECKER.compare_packet(temp, self.result)

    def test_compare_packet_rejects_a_missing_packet(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(CHECKER.DerivationError):
                CHECKER.compare_packet(temp, self.result)


if __name__ == "__main__":
    unittest.main()
