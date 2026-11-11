#!/usr/bin/env python3
"""Tests for the AreFilesInCompaction 0x5d9a390 packet (node #115).

The tests hold the claims, not the packet's tables: the recovered predicate is
checked case by case, the decoded-bytes emulator is run against the model and
against a doctored excerpt, and the artifact claims (bytes, anchors, the caller
census, the memory effect) are re-derived from the binary.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.rocksdb_are_files_in_compaction_5d9a390_115 import (  # noqa: E402
    START, END, EXCERPT, FLAG_OFFSET, ELEMENT_SIZE, PACKET,
    Memory, Machine, model, decoded, build_mem, begin_end, agree,
    generate_cases, accesses, instructions,
)

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
BODY_SHA256 = "6de8326a03541c2778148ae408b2f22c254ffdb5d4e5c204fc145911752d90b3"
CONSUMERS = {"arithmetic": 7, "returned": 1, "stored": 1}


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise AssertionError(f"{va:#x} is in no LOAD segment")


def window_bytes():
    data = BINARY.read_bytes()
    off = va_to_off(START)
    return data[off:off + (END - START)], data, off


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ArtifactTests(unittest.TestCase):
    def test_the_window_is_the_bound_body(self):
        body, _, _ = window_bytes()
        self.assertEqual(len(body), 63)
        self.assertEqual(hashlib.sha256(body).hexdigest(), BODY_SHA256)

    def test_the_window_is_int3_fenced(self):
        _, data, off = window_bytes()
        self.assertEqual(data[off - 8:off], b"\xcc" * 8)
        self.assertEqual(data[off + 63:off + 64], b"\xcc")

    def test_the_excerpt_bytes_are_the_artifact_bytes(self):
        body, data, off = window_bytes()
        seen = 0
        for line in (PACKET / "main.txt").read_text().splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if not m:
                continue
            va = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            self.assertEqual(data[off + (va - START):off + (va - START) + len(raw)], raw)
            seen += len(raw)
        self.assertEqual(seen, 63)

    def test_the_window_holds_no_call_or_store(self):
        body, _, _ = window_bytes()
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        ins = list(md.disasm(body, START))
        self.assertEqual(len(ins), 22)
        self.assertEqual(sum(i.size for i in ins), 63)
        loads = stores = 0
        for i in ins:
            self.assertNotIn(i.mnemonic, ("call", "jmpq"))
            for op in i.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    if op.access & capstone.CS_AC_WRITE:
                        stores += 1
                    if op.access & capstone.CS_AC_READ:
                        loads += 1
        self.assertEqual((loads, stores), (4, 0))


class AnchorTests(unittest.TestCase):
    def test_anchors_are_contiguous_and_cover_the_window(self):
        sem = _load("sem", PACKET / "semantics.py")
        anchors = sem.claim_anchors()
        self.assertEqual(len(anchors), 22)
        self.assertEqual(sum(a[1] for a in anchors), 63)
        for (a, s, _, _), b in zip(anchors, [x[0] for x in anchors[1:]]):
            self.assertEqual(a + s, b)

    def test_every_anchor_is_that_one_instruction(self):
        sem = _load("sem", PACKET / "semantics.py")
        self.assertEqual(sem.check((PACKET / "main.txt").read_text()), 22)


class ModelTests(unittest.TestCase):
    def value(self, flags):
        mem = build_mem(flags)
        b, e = begin_end(flags)
        return model(mem, b, e)

    def test_empty_vector_is_false(self):
        self.assertEqual(self.value(()), 0)

    def test_all_clear_is_false(self):
        for n in (1, 2, 3, 8, 33, 64):
            self.assertEqual(self.value((0,) * n), 0, n)

    def test_the_flag_byte_itself_is_returned(self):
        for v in (1, 2, 3, 0x7F, 0x80, 0xFF):
            self.assertEqual(self.value((0, v, 0)), v)
            self.assertEqual(self.value((v,)), v)

    def test_position_does_not_matter(self):
        for n in (1, 2, 5, 16, 64):
            for pos in range(n):
                flags = [0] * n
                flags[pos] = 1
                self.assertEqual(self.value(tuple(flags)), 1, (n, pos))

    def test_the_first_non_zero_element_wins(self):
        self.assertEqual(self.value((3, 7, 9)), 3)
        self.assertEqual(self.value((0, 0, 5, 6)), 5)

    def test_an_impossible_vector_is_refused_not_modelled(self):
        mem = Memory()
        with self.assertRaises(ValueError):
            model(mem, 0x1000, 0x0FF0)


class EmulatorTests(unittest.TestCase):
    def test_the_model_and_the_bytes_agree_on_the_ledger(self):
        cases = generate_cases(seed=7)
        self.assertEqual(len(cases), 300)
        for family, flags in cases:
            ok, want, got = agree(flags)
            self.assertTrue(ok, f"{family} {flags}: model {want} decoded {got}")

    def test_the_model_and_the_bytes_agree_on_a_sweep(self):
        for n in range(0, 17):
            for v in (1, 2, 0x7F, 0x80, 0xFF):
                for pos in list(range(n)) + [None]:
                    flags = [0] * n
                    if pos is not None:
                        flags[pos] = v
                    ok, want, got = agree(tuple(flags))
                    self.assertTrue(ok, f"n={n} pos={pos} v={v}: {want} vs {got}")

    def test_the_emulator_really_executes_the_bytes(self):
        # The count is `sar $0x3` on the byte distance; doubling the shift must
        # halve the number of elements walked, so a flag at index 2 of three
        # elements becomes invisible.
        flags = (0, 0, 1)
        self.assertEqual(agree(flags)[1], 1)               # model and bytes agree
        body = EXCERPT.read_text().replace("sar    $0x3,%rsi", "sar    $0x4,%rsi")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(body)
            path = fh.name
        try:
            ok, want, got = agree(flags, path=path)
            self.assertEqual(want, 1)                      # the model is unchanged
            self.assertEqual(got, 0)                       # the bytes are what moved
            self.assertFalse(ok)
        finally:
            Path(path).unlink()

    def test_the_emulator_raises_on_an_unimplemented_instruction(self):
        body = EXCERPT.read_text().replace(
            "movzbl 0xb4(%rdx),%edx", "ud2")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write(body)
            path = fh.name
        try:
            with self.assertRaises(NotImplementedError):
                agree((1,), path=path)
        finally:
            Path(path).unlink()

    def test_the_routine_writes_no_memory(self):
        for flags in ((), (0,), (1,), (0, 0, 1), (0,) * 8):
            a = accesses(flags)
            self.assertEqual(a["stores"], 0, flags)
            # the walk loads: begin, end, then one pointer + one flag per visited
            # element - an empty vector only touches the two header fields
            self.assertGreaterEqual(a["loads"], 2)

    def test_the_empty_vector_is_answered_from_the_header_alone(self):
        a = accesses(())
        self.assertEqual(a["loads"], 2)        # begin and end only
        self.assertEqual(a["eax"], 0)

    def test_a_short_walk_loads_one_pointer_and_one_flag_per_element(self):
        a = accesses((0, 0, 1))
        self.assertEqual(a["loads"], 2 + 2 * 3)   # header + 3 elements visited
        self.assertEqual(a["eax"], 1)


class CensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = _load("cen", PACKET / "census.py").census()

    def test_the_call_sites_and_caller_fdes(self):
        self.assertEqual(len(self.c["call_sites"]), 9)
        self.assertEqual(self.c["fdes"], 5)
        for r in self.c["call_sites"]:
            self.assertLessEqual(r["fde"][0], r["site"])
            self.assertLess(r["site"], r["fde"][1])

    def test_every_caller_reads_the_result(self):
        self.assertEqual(self.c["consumers"], CONSUMERS)
        self.assertEqual(self.c["discarded_sites"], 0)

    def test_the_committed_tables_are_this_census(self):
        rows = [l.split("\t") for l in (PACKET / "callers.tsv").read_text().splitlines()[1:] if l]
        self.assertEqual(len(rows), 9)
        for r, s in zip(rows, self.c["call_sites"]):
            self.assertEqual(r[0], f"{s['site']:#x}")
            self.assertEqual(r[1], f"{s['fde'][0]:#x}")
            self.assertEqual(r[2], f"{s['fde'][1]:#x}")
            self.assertEqual(r[3], s["use"])
        use = [l.split("\t") for l in
               (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l]
        self.assertEqual([u[1] for u in use], [s["use"] for s in self.c["call_sites"]])

    def test_the_two_distinctive_callers(self):
        use = {u[0]: (u[1], u[2]) for u in
               (l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l)}
        # one caller negates the predicate...
        self.assertEqual(use["0x5d9a539"][0], "arithmetic")
        self.assertIn("xor eax, 1", use["0x5d9a539"][1])
        # ...and one forwards it as its own return value, carrying the byte in the
        # callee-saved ebx across an intervening call
        self.assertEqual(use["0x5d9dae8"][0], "returned")
        # one keeps it in a stack local
        self.assertEqual(use["0x5d9e0b0"][0], "stored")
        self.assertIn("byte ptr", use["0x5d9e0b0"][1])


class TableTests(unittest.TestCase):
    def test_the_ledger_table_has_a_row_per_case_and_no_disagreement(self):
        lines = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(lines[0], "family\tn\tflags\tmodel\tdecoded\tagree")
        self.assertEqual(len(lines) - 1, 300)
        for line in lines[1:]:
            family, n, flags, want, got, ok = line.split("\t")
            self.assertEqual(want, got, line)
            self.assertEqual(ok, "yes", line)

    def test_the_accesses_table_reports_the_routine_only(self):
        text = (PACKET / "accesses.tsv").read_text()
        self.assertIn("loads\t6", text)
        self.assertIn("stores\t0", text)


if __name__ == "__main__":
    unittest.main()
