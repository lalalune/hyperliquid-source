"""Tests for the node #115 blst get_wval_limb model (0x5d0ed60, RE-002).

Covers the closed-form window result, the literal disassembly
transcription it is cross-checked against, the committed reviewable
ledger, the in-memory full sweep and random differential, the
caller-consumer census, and binary bindings (body hash, empty
relocation record, byte windows).
"""
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

from tools.get_wval_limb_5d0ed60_115 import (
    ARTIFACT_SHA256,
    PACKET,
    START,
    END,
    get_wval_limb,
    get_wval_limb_asm,
    generate_cases,
    ledger_rows,
)

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
CENSUS = (ROOT / "research" / "work-items"
          / "RE-002-node115-vendor-census" / "census.json")


def _va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


class WvalLimbSemanticsTest(unittest.TestCase):
    def test_byte_aligned_reads_are_exact(self):
        self.assertEqual(get_wval_limb(b"\x12", 0, 8), 0x12)
        self.assertEqual(get_wval_limb(b"\x12\x34", 0, 16), 0x3412)
        self.assertEqual(get_wval_limb(b"\x12\x34\x56\x78", 0, 32),
                         0x78563412)
        self.assertEqual(get_wval_limb(b"\x12\x34", 0, 8), 0x12)

    def test_bit_offset_shifts_the_window(self):
        # bit 4 of 0xff,0x01 is the start of a byte crossing field.
        self.assertEqual(get_wval_limb(b"\xff\x01", 4, 8), 0x1F)
        self.assertEqual(get_wval_limb(b"\x00\x80", 0, 16), 0x8000)
        self.assertEqual(get_wval_limb(b"\x80", 7, 1), 0x01)

    def test_window_is_not_masked_to_nbits(self):
        # The routine has no mask-to-nbits step: the window can carry up
        # to seven extra high bits from the last spanned byte. The
        # callers mask it themselves (see the caller census).
        self.assertEqual(get_wval_limb(b"\xa5", 0, 4), 0xA5)   # field 0x5
        self.assertEqual(get_wval_limb(b"\xa5", 0, 4) & 0x0F, 0x05)
        self.assertEqual(get_wval_limb(b"\xff\xff", 4, 8), 0xFFF)  # field 0xFF
        self.assertEqual(get_wval_limb(b"\xff\xff", 4, 8) & 0xFF, 0xFF)
        # A field that ends on a byte boundary needs no masking.
        self.assertEqual(get_wval_limb(b"\xa5", 4, 4), 0x0A)

    def test_bytes_beyond_the_span_never_leak(self):
        # Bytes past the field are all ones; a leaking implementation
        # would differ.
        self.assertEqual(get_wval_limb(b"\x00\xff\xff\xff", 0, 8), 0x00)
        self.assertEqual(get_wval_limb(b"\x00\xff\xff\xff", 0, 16), 0xFF00)
        self.assertEqual(get_wval_limb(b"\x00\xff\xff\xff", 4, 4), 0x00)

    def test_negative_bitpos_rejected(self):
        with self.assertRaises(ValueError):
            get_wval_limb(b"\x00", -1, 8)

    def test_zero_nbits_rejected(self):
        with self.assertRaises(ValueError):
            get_wval_limb(b"\x00", 0, 0)

    def test_more_than_four_spanned_bytes_rejected(self):
        # The loop shifts only 32 bits, so a wider field is truncated;
        # the model refuses it instead of guessing.
        with self.assertRaises(ValueError):
            get_wval_limb(b"\x00" * 8, 0, 40)

    def test_short_buffer_rejected(self):
        with self.assertRaises(ValueError):
            get_wval_limb(b"\x00", 0, 16)


class WvalLimbLedgerTest(unittest.TestCase):
    """The committed ledger is the review artifact: small enough to read.
    The exhaustive sweep is re-derived here, in memory."""

    def test_committed_ledger_replays(self):
        rows = (PACKET / "cases.tsv").read_text().splitlines()
        header = rows[0].split("\t")
        self.assertEqual(header, ["id", "group", "param", "expected"])
        data = rows[1:]
        self.assertEqual(len(data), 300)
        groups = {line.split("\t")[1] for line in data}
        self.assertEqual(groups, {"boundary", "shift", "mask", "random"})
        for line in data:
            cid, group, param, expected = line.split("\t")
            p = json.loads(param)
            got = get_wval_limb(bytes.fromhex(p["w"]), p["bitpos"],
                                p["nbits"])
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

    def test_full_sweep_matches_the_transcription(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        for c in cases:
            p = json.loads(c["param"])
            w = bytes.fromhex(p["w"])
            self.assertEqual(get_wval_limb(w, p["bitpos"], p["nbits"]),
                             get_wval_limb_asm(w, p["bitpos"], p["nbits"]),
                             c["id"])

    def test_random_differential_200k(self):
        rng = random.Random(0x5D0ED60)
        for i in range(200_000):
            off = rng.randrange(8)
            span = rng.randrange(4)
            maxbits = 8 * (span + 1) - off
            if maxbits < 1:
                continue
            nbits = rng.randrange(1, maxbits + 1)
            first = rng.randrange(0, 3)
            w = bytes(rng.randrange(256) for _ in range(first + span + 1))
            bitpos = first * 8 + off
            if get_wval_limb(w, bitpos, nbits) != get_wval_limb_asm(
                    w, bitpos, nbits):
                self.fail(f"mismatch at case {i}: {w.hex()} {bitpos} {nbits}")


class WvalLimbCallerCensusTest(unittest.TestCase):
    """What the call sites depend on: the census classifies the first read
    of the returned window inside each enclosing FDE."""

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

    def test_window_is_shifted_then_masked(self):
        classes = {}
        for r in self.rows:
            classes[r["consumer"]] = classes.get(r["consumer"], 0) + 1
        self.assertEqual(classes, {"shift": 8, "mask-combine": 2})

    def test_every_caller_masks_the_window(self):
        # The dependency the callers place on the routine: the window
        # must hold the field, and the caller masks it to nbits -- two
        # sites mask as their first use, the rest within three
        # instructions of the shift.
        for r in self.rows:
            combined = r["use"] + " ; " + r["after"]
            self.assertIn("and ", combined, r["site"])

    def test_caller_fdes_are_recorded(self):
        fdes = {r["caller_fde"] for r in self.rows}
        self.assertEqual(len(fdes), 4)
        for r in self.rows:
            a, b = r["caller_fde"].split("..")
            self.assertLess(int(a, 16), int(b, 16))


class WvalLimbBindingsTest(unittest.TestCase):
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
        # The routine's own register dance, present in the bytes:
        #   shl %cl,%rdx       48 d3 e2
        #   sar $0x3f,%r8      49 c1 f8 3f
        #   shr $0x3f,%rdx     48 c1 ea 3f
        #   shr %cl,%rax       48 d3 e8
        self.assertEqual(body.count(b"\x48\xd3\xe2"), 1)
        self.assertEqual(body.count(b"\x49\xc1\xf8\x3f"), 1)
        self.assertEqual(body.count(b"\x48\xc1\xea\x3f"), 1)
        self.assertEqual(body.count(b"\x48\xd3\xe8"), 1)
        # First bytes are `mov %rsi,%r9` and the function has no
        # endbr64 prologue and ends with a plain `ret`.
        self.assertEqual(body[:3], b"\x49\x89\xf1")
        self.assertNotIn(b"\xf3\x0f\x1e\xfa", body)
        self.assertEqual(body[-1:], b"\xc3")

    def test_fde_bounds(self):
        out = subprocess.check_output(["readelf", "-wf", str(BINARY)]).decode()
        line = next(l for l in out.splitlines()
                    if f"pc=000000000{START:x}" in l)
        self.assertIn(f"..000000000{END:x}", line)


if __name__ == "__main__":
    unittest.main()
