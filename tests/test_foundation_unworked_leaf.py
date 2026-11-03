#!/usr/bin/env python3
"""Focused test for the node #115 .eh_frame window census checker.

Runs the actual committed checker tools/foundation_unworked_leaf.py against
artifacts/node/115/hl-node in place and against the saved packet
research/work-items/RE-001-node115-unworked-leaf/. The captured binary is
never executed or copied; every asserted value is re-derived by the checker
from the pinned bytes.

Census recorded by the retained scratch proof at base 8fd8db68: target_sha256
a6e2897c..., fde_total 135313, the window 0x1a00000..0x1a40000 holds 67
complete FDEs and none at or below 120 bytes.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKER = os.path.join(ROOT, "tools", "foundation_unworked_leaf.py")
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-unworked-leaf")
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FDE_TOTAL = 135313
WINDOW_LO = 0x1A00000
WINDOW_HI = 0x1A40000
WINDOW_START = "0x1a00000"
WINDOW_END = "0x1a40000"
WINDOW_FDE_COUNT = 67
WINDOW_LEAF_COUNT = 0
PACKET_FILES = [
    "README.md",
    "evidence.json",
    "frames.txt",
]
COMMITTED_FILES = [
    os.path.join("tools", "foundation_unworked_leaf.py"),
    os.path.join("tests", "test_foundation_unworked_leaf.py"),
]


def run_checker(*args):
    return subprocess.run([sys.executable, "-B", CHECKER] + list(args),
                          cwd=ROOT, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def load_checker():
    spec = importlib.util.spec_from_file_location(
        "foundation_unworked_leaf", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EmitCensusTest(unittest.TestCase):
    def test_emit_reproduces_recorded_census(self):
        proc = run_checker("--emit")
        self.assertEqual(proc.returncode, 0,
                         proc.stderr.decode("utf-8", "replace"))
        derived = json.loads(proc.stdout.decode("utf-8"))
        self.assertEqual(derived["target_sha256"], TARGET_SHA256)
        self.assertEqual(derived["fde_total"], FDE_TOTAL)
        self.assertEqual(derived["window"]["start"], WINDOW_START)
        self.assertEqual(derived["window"]["end"], WINDOW_END)
        self.assertEqual(derived["window"]["fde_count"], WINDOW_FDE_COUNT)
        self.assertEqual(derived["window"]["leaf_count"], WINDOW_LEAF_COUNT)
        self.assertEqual(len(derived["window_fdes"]), WINDOW_FDE_COUNT)
        smallest = derived["smallest"]
        self.assertIs(smallest["at_or_below_leaf_limit"], False)
        self.assertEqual(len(smallest["sha256"]), 64)
        self.assertEqual(int(smallest["end"], 16) - int(smallest["start"], 16),
                         smallest["bytes"])
        for entry in derived["window_fdes"]:
            start = int(entry["start"], 16)
            end = int(entry["end"], 16)
            self.assertEqual(end - start, entry["bytes"])
            self.assertEqual(len(entry["sha256"]), 64)
            self.assertTrue(WINDOW_LO <= start)
            self.assertTrue(end <= WINDOW_HI)


class CieResolutionTest(unittest.TestCase):
    def test_every_fde_resolves_to_a_zero_id_cie_record_start(self):
        module = load_checker()
        data = module.read_target(ROOT)
        sections = module.elf_sections(data)
        eh = module.section_named(sections, ".eh_frame")
        cies, fdes = module.parse_eh_frame(
            data, eh["offset"], eh["addr"], eh["size"])
        self.assertEqual(len(fdes), FDE_TOTAL)
        self.assertTrue(cies)
        for fde in fdes:
            self.assertIn(fde["cie"], cies)
        for key in cies:
            length32 = int.from_bytes(data[key:key + 4], "little")
            self.assertNotEqual(length32, 0xFFFFFFFF)
            self.assertEqual(data[key + 4:key + 8], b"\x00\x00\x00\x00")


class SavedPacketTest(unittest.TestCase):
    def test_packet_is_complete(self):
        missing = [name for name in PACKET_FILES
                   if not os.path.isfile(os.path.join(PACKET, name))]
        self.assertEqual(missing, [],
                         "packet files missing: " + ", ".join(missing))
        absent = [name for name in COMMITTED_FILES
                  if not os.path.isfile(os.path.join(ROOT, name))]
        self.assertEqual(absent, [],
                         "committed checker/test missing: " + ", ".join(absent))

    def test_saved_packet_verifies(self):
        proc = run_checker()
        out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0,
                         out + proc.stderr.decode("utf-8", "replace"))
        self.assertIn("checker: OK", out)
        self.assertIn("target_sha256=" + TARGET_SHA256, out)
        self.assertIn("window_fde_count=%d" % WINDOW_FDE_COUNT, out)
        self.assertIn("frames_txt_lines=%d" % WINDOW_FDE_COUNT, out)


class CorruptionControlTest(unittest.TestCase):
    def test_parse_eh_frame_rejects_truncated_record(self):
        module = load_checker()
        with self.assertRaises(ValueError):
            module.parse_eh_frame(b"\x20\x00\x00\x00", 0, 0x1000, 4)

    def test_uleb_overflow_is_rejected(self):
        module = load_checker()
        with self.assertRaises(ValueError):
            module.uleb(b"\xff" * 20, 0)

    def test_objdump_bytes_must_match_target(self):
        module = load_checker()
        data = module.read_target(ROOT)
        sections = module.elf_sections(data)
        derived = module.derive(ROOT)
        start = int(derived["smallest"]["start"], 16)
        _, offset = module.va_to_offset(sections, start)
        raw = data[offset:offset + 4]
        good = "  %x:\t%s" % (start, " ".join("%02x" % byte for byte in raw) + " ")
        self.assertEqual(module.verify_objdump(good, data, sections), 1)
        altered = bytes([raw[0] ^ 0xFF]) + raw[1:]
        wrong = "  %x:\t%s" % (start, " ".join("%02x" % byte for byte in altered) + " ")
        with self.assertRaises(AssertionError):
            module.verify_objdump(wrong, data, sections)


class PacketCorruptionTest(unittest.TestCase):
    """Runs the committed checker on a faithful copy of the saved packet."""

    def setUp(self):
        self.module = load_checker()
        self.tmp = tempfile.mkdtemp(prefix="node115-packet-")
        for name in ("evidence.json", "frames.txt"):
            shutil.copyfile(os.path.join(PACKET, name),
                            os.path.join(self.tmp, name))
        self.saved = self.module.PACKET_REL
        self.module.PACKET_REL = self.tmp

    def tearDown(self):
        self.module.PACKET_REL = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def frames_path(self):
        return os.path.join(self.tmp, "frames.txt")

    def evidence_path(self):
        return os.path.join(self.tmp, "evidence.json")

    def test_clean_copy_verifies(self):
        derived, checked = self.module.verify_packet(ROOT)
        self.assertEqual(derived["window"]["fde_count"], WINDOW_FDE_COUNT)
        self.assertEqual(len(derived["window_fdes"]), WINDOW_FDE_COUNT)
        self.assertEqual(checked, 0)

    def test_mutated_frame_line_is_rejected(self):
        with open(self.frames_path(), "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        first = lines[0]
        swap = "1" if first[-1] != "1" else "2"
        lines[0] = first[:-1] + swap
        with open(self.frames_path(), "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        with self.assertRaises(AssertionError):
            self.module.verify_packet(ROOT)

    def test_mutated_derived_count_is_rejected(self):
        with open(self.evidence_path(), "r", encoding="utf-8") as handle:
            evidence = json.load(handle)
        evidence["derived"]["fde_total"] = FDE_TOTAL + 1
        with open(self.evidence_path(), "w", encoding="utf-8") as handle:
            json.dump(evidence, handle, indent=2, sort_keys=True)
        with self.assertRaises(AssertionError):
            self.module.verify_packet(ROOT)


if __name__ == "__main__":
    unittest.main()
