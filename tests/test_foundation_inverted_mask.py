#!/usr/bin/env python3
"""Unit tests for the foundation inverted-mask checker.

Run from the repository root:

    python3 -m unittest tests.test_foundation_inverted_mask -v

Each corruption control mutates exactly one recorded fact and must make
the checker fail; the real evidence must pass.
"""

import copy
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(
    ROOT, "research", "work-items", "foundation-inverted-mask-94",
    "evidence.json")
FRAMES = os.path.join(
    ROOT, "research", "work-items", "foundation-inverted-mask-94",
    "frames.txt")
TOOL = os.path.join(ROOT, "tools", "foundation_inverted_mask.py")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "foundation_inverted_mask", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InvertedMaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(ROOT)
        cls.tool = load_tool()
        with open(EVIDENCE) as fh:
            cls.evidence = json.load(fh)

    def run_mutated(self, mutate, frames_mutate=None):
        ev = copy.deepcopy(self.evidence)
        mutate(ev)
        with tempfile.TemporaryDirectory() as tmp:
            ev_path = os.path.join(tmp, "evidence.json")
            with open(ev_path, "w") as fh:
                json.dump(ev, fh)
            with open(FRAMES) as fh:
                frames_text = fh.read()
            if frames_mutate is not None:
                frames_text = frames_mutate(frames_text)
            with open(os.path.join(tmp, "frames.txt"), "w") as fh:
                fh.write(frames_text)
            with self.assertRaises(ValueError):
                self.tool.run_all(ev_path)

    def test_real_evidence_passes(self):
        self.tool.run_all(EVIDENCE)

    def test_body_hash_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "sha256", "0" * 64))

    def test_body_length_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__("bytes", 81))

    def test_window_padding_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_bytes", 3))

    def test_window_padding_hex_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "padding_hex", "00" * 14))

    def test_target_digest_control(self):
        self.run_mutated(lambda ev: ev.__setitem__(
            "target_sha256", "0" * 64))

    def test_window_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_section_offset", "0x0016a020"))

    def test_window_next_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "next_fde_section_offset", "0x0016a040"))

    def test_window_prev_fde_offset_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "prev_fde_section_offset", "0x0016a000"))

    def test_window_cie_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "fde_cie", "0x002dc714"))

    def test_prev_gap_hex_control(self):
        self.run_mutated(lambda ev: ev["function"].__setitem__(
            "prev_gap_hex", "00" * 14))

    def test_callee_start_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "start_va", "0x3bb2291"))

    def test_callee_sha_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "sha256", "0" * 64))

    def test_callee_length_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__("bytes", 848))

    def test_callee_padding_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_bytes", 3))

    def test_callee_padding_hex_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "padding_hex", "00" * 15))

    def test_callee_cie_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "fde_cie", "0x00000000"))

    def test_callee_sites_control(self):
        self.run_mutated(lambda ev: ev["callee"].__setitem__(
            "direct_e8_call_sites",
            ["0x36f57d4", "0x36ff858"]))

    def test_caller_list_control(self):
        self.run_mutated(lambda ev: ev["incoming"].__setitem__(
            "direct_e8_callers", ["0x36f57d4"]))

    def test_edge_none_control(self):
        self.run_mutated(lambda ev: ev["rule"]["mask_edges"].__setitem__(
            "0x0000_msb_none", "pmovmskb = 0x0000 -> mask = 0x0000"))

    def test_edge_all_control(self):
        self.run_mutated(lambda ev: ev["rule"]["mask_edges"].__setitem__(
            "0xffff_all_set", "pmovmskb = 0xffff -> mask = 0xffff"))

    def test_frames_mutation_control(self):
        self.run_mutated(
            lambda ev: None,
            frames_mutate=lambda t: t.replace(
                "pc=00000000036f5790..00000000036f57e2",
                "pc=00000000036f5790..00000000036f57e1"))


if __name__ == "__main__":
    unittest.main()
