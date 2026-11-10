"""Tests for the node #115 rocksdb MaxFileSizeForLevel model
(0x607f450, RE-002).

Covers the closed-form table selection, the decoded execution of the
routine's own committed instructions that cross-checks it, the committed
reviewable ledger, the in-memory full sweep and random differential, the
claim anchors, and binary bindings (body hash, empty relocation record,
byte windows).
"""
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

from tools.rocksdb_max_file_size_for_level_607f450_115 import (
    ARTIFACT_SHA256,
    OPTIONS_TABLE_OFFSET,
    PACKET,
    START,
    END,
    max_file_size_for_level,
    max_file_size_for_level_decoded,
    generate_cases,
    instruction_stream,
    ledger_rows,
)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
CENSUS = (ROOT / "research" / "work-items"
          / "RE-002-node115-vendor-census" / "census.json")

TABLE = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]


def _va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


class MaxFileSizeForLevelSemanticsTest(unittest.TestCase):
    def test_default_path_uses_the_level_index(self):
        # level < base: no subtraction, index is the plain level.
        self.assertEqual(max_file_size_for_level(TABLE, 2, 0, 5, 1), 0x30)
        self.assertEqual(max_file_size_for_level(TABLE, 0, 0, 1, 1), 0x10)

    def test_subtract_path_uses_level_minus_base(self):
        # level >= base, style low byte zero, flag low byte 1.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 1), 0x40)
        self.assertEqual(max_file_size_for_level(TABLE, 3, 0, 3, 1), 0x10)

    def test_flag_low_byte_only(self):
        # The flag test is `cmp $0x1,%r8b`: only the low byte counts, and
        # 256 has a low byte of 0 while 257 has 1.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 1), 0x40)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 257), 0x40)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 256), 0x60)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 0), 0x60)

    def test_style_low_byte_only(self):
        # `test %dil,%dil` tests only the low byte of style: a style of
        # 256 has a zero low byte and therefore takes the subtract path,
        # even though style != 0.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 256, 2, 1), 0x40)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0x100, 2, 1), 0x40)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0x10000, 2, 1),
                         0x40)
        # A non-zero low byte blocks the subtraction.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 1, 2, 1), 0x60)
        self.assertEqual(max_file_size_for_level(TABLE, 5, 255, 2, 1), 0x60)

    def test_style_zero_and_flag_one_are_both_required(self):
        # level >= base but style low byte non-zero -> no subtraction.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 1, 2, 1), 0x60)
        # level >= base and style zero but flag not 1 -> no subtraction.
        self.assertEqual(max_file_size_for_level(TABLE, 5, 0, 2, 0), 0x60)
        # level < base -> no subtraction regardless of style and flag.
        self.assertEqual(max_file_size_for_level(TABLE, 2, 0, 5, 1), 0x30)

    def test_out_of_range_index_is_rejected(self):
        # The routine performs no bound check of its own: the model
        # rejects an index outside the supplied table instead of guessing.
        with self.assertRaises(IndexError):
            max_file_size_for_level(TABLE, 9, 0, 0, 0)   # index 9
        with self.assertRaises(IndexError):
            max_file_size_for_level(TABLE, 8, 0, 0, 0)   # index 8
        # ... while index 7 is the last valid entry.
        self.assertEqual(max_file_size_for_level(TABLE, 7, 0, 0, 0), 0x80)

    def test_decoded_execution_agrees(self):
        for level, style, base, flag in ((5, 0, 2, 1), (5, 1, 2, 1),
                                         (5, 0, 2, 0), (2, 0, 5, 1),
                                         (3, 256, 2, 1), (0, 0, 0, 1),
                                         (7, 0, 0, 1), (4, 2, 1, 1)):
            self.assertEqual(
                max_file_size_for_level(TABLE, level, style, base, flag),
                max_file_size_for_level_decoded(TABLE, level, style, base,
                                                flag),
                (level, style, base, flag))

    def test_table_field_offset_is_pinned(self):
        # The one field the routine reads is options+0x1e0.
        self.assertEqual(OPTIONS_TABLE_OFFSET, 0x1E0)
        self.assertEqual(
            max_file_size_for_level_decoded(TABLE, 1, 0, 0, 0),
            TABLE[1])


class MaxFileSizeForLevelLedgerTest(unittest.TestCase):
    """The committed ledger is the review artifact: small enough to read.
    The exhaustive sweep is re-derived here, in memory."""

    def test_committed_ledger_replays(self):
        rows = (PACKET / "cases.tsv").read_text().splitlines()
        header = rows[0].split("\t")
        self.assertEqual(header, ["id", "group", "param", "expected"])
        data = rows[1:]
        self.assertEqual(len(data), 300)
        groups = {line.split("\t")[1] for line in data}
        self.assertEqual(groups, {"matrix", "style", "base", "random"})
        for line in data:
            cid, group, param, expected = line.split("\t")
            p = json.loads(param)
            got = max_file_size_for_level(p["table"], p["level"], p["style"],
                                          p["base"], p["flag"])
            self.assertEqual(got, json.loads(expected)["value"], cid)

    def test_committed_ledger_is_the_documented_subset(self):
        committed = (PACKET / "cases.tsv").read_text()
        want = ["id\tgroup\tparam\texpected"]
        for r in ledger_rows():
            want.append("\t".join(r[k] for k in ("id", "group", "param",
                                                 "expected")))
        self.assertEqual(committed, "\n".join(want) + "\n")
        sweep = {r["id"]: r for r in generate_cases()}
        for r in ledger_rows():
            self.assertEqual(sweep[r["id"]]["expected"], r["expected"])

    def test_full_sweep_matches_the_decoded_execution(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        for c in cases:
            p = json.loads(c["param"])
            self.assertEqual(
                max_file_size_for_level(p["table"], p["level"], p["style"],
                                        p["base"], p["flag"]),
                max_file_size_for_level_decoded(
                    p["table"], p["level"], p["style"], p["base"], p["flag"]),
                c["id"])

    def test_random_differential_20k(self):
        rng = random.Random(0x607F450)
        for i in range(20_000):
            n = rng.randrange(1, 9)
            table = [rng.randrange(1 << 48) for _ in range(n)]
            level = rng.randrange(0, n)
            style = rng.choice((0, 1, 255, 256, 257, rng.randrange(1 << 32)))
            base = rng.randrange(0, n + 1)
            flag = rng.choice((0, 1, 255, 256, 257))
            got = max_file_size_for_level(table, level, style, base, flag)
            want = max_file_size_for_level_decoded(table, level, style, base,
                                                   flag)
            if got != want:
                self.fail(f"mismatch at case {i}: {level} {style} {base} "
                          f"{flag}")

    def test_instruction_stream_is_the_whole_routine(self):
        stream = instruction_stream()
        self.assertEqual(len(stream), 20)
        self.assertEqual(stream[0].mnemonic, "endbr64")
        self.assertEqual(stream[0].address, START)
        self.assertEqual(stream[-1].mnemonic, "ret")
        self.assertLess(stream[-1].address, END)


class MaxFileSizeForLevelCallerCensusTest(unittest.TestCase):
    """What the call sites depend on: the census classifies the first read
    of the returned table value inside each enclosing FDE."""

    def setUp(self):
        path = PACKET / "caller_use.tsv"
        if not path.is_file():
            self.skipTest("caller census not generated")
        rows = path.read_text().splitlines()
        self.header = rows[0].split("\t")
        self.rows = [dict(zip(self.header, line.split("\t")))
                     for line in rows[1:]]

    def test_every_call_site_has_a_consumer(self):
        self.assertEqual(len(self.rows), 10)
        self.assertTrue(all(r["consumer"] for r in self.rows))

    def test_value_is_passed_on_not_compared(self):
        classes = {}
        for r in self.rows:
            classes[r["consumer"]] = classes.get(r["consumer"], 0) + 1
        self.assertEqual(classes, {"stack-arg": 7, "register-copy": 2,
                                   "store": 1})

    def test_seven_sites_push_it_into_a_later_call(self):
        # Seven sites push the size as a stack argument, and all seven
        # feed the same builder -- the dependency is one callee contract.
        pushed = [r for r in self.rows if r["consumer"] == "stack-arg"]
        self.assertEqual(len(pushed), 7)
        for r in pushed:
            self.assertEqual(r["use"], "push rax")
            self.assertIn("call 0x5da8870", r["after"])
        self.assertEqual({r["after"].split("call ")[1].split(";")[0]
                          for r in pushed}, {"0x5da8870"})

    def test_caller_fdes_are_recorded(self):
        for r in self.rows:
            a, b = r["caller_fde"].split("..")
            self.assertLess(int(a, 16), int(b, 16))
            self.assertNotEqual(int(a, 16), START)


class MaxFileSizeForLevelBindingsTest(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.skipTest("node #115 binary not present")
        self.data = BINARY.read_bytes()
        self.assertEqual(hashlib.sha256(self.data).hexdigest(),
                         ARTIFACT_SHA256)

    def test_body_hash_and_no_relocations(self):
        recs = json.loads(CENSUS.read_text())["records"]
        rec = next(r for r in recs if r["start"] == START)
        self.assertEqual(rec["end"], END)
        self.assertEqual(rec["relocations"], [])
        self.assertTrue(rec["raw_equal"])
        body = self.data[_va_to_off(START):_va_to_off(END)]
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         rec["target_body_sha256"])
        self.assertEqual(rec["target_body_sha256"],
                         rec["source_body_sha256"])

    def test_byte_windows(self):
        body = self.data[_va_to_off(START):_va_to_off(END)]
        self.assertEqual(len(body), END - START)
        # This routine is entered through endbr64 and is a plain leaf.
        self.assertEqual(body[:4], b"\xf3\x0f\x1e\xfa")
        # mov rax, qword ptr [rdx + rsi*8]  -> 48 8b 04 f2, twice.
        self.assertEqual(body.count(b"\x48\x8b\x04\xf2"), 2)
        # movsxd rsi, esi                    -> 48 63 f6, twice.
        self.assertEqual(body.count(b"\x48\x63\xf6"), 2)
        # test dil, dil                      -> 40 84 ff
        self.assertEqual(body.count(b"\x40\x84\xff"), 1)
        self.assertEqual(body[-1:], b"\xc3")

    def test_claim_anchors_are_in_the_target(self):
        rows = (PACKET / "semantics.tsv").read_text().splitlines()
        header = rows[0].split("\t")
        self.assertEqual(header, ["claim", "va", "size", "bytes",
                                  "instruction", "note"])
        self.assertEqual(len(rows) - 1, 15)
        for line in rows[1:]:
            r = dict(zip(header, line.split("\t")))
            va = int(r["va"], 16)
            self.assertTrue(START <= va < END, r["claim"])
            off = _va_to_off(va)
            self.assertEqual(self.data[off:off + int(r["size"])].hex(),
                             r["bytes"], r["claim"])

    def test_fde_bounds(self):
        out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
        line = next(l for l in out.splitlines()
                    if f"pc=000000000{START:x}" in l)
        self.assertIn(f"..000000000{END:x}", line)


if __name__ == "__main__":
    unittest.main()