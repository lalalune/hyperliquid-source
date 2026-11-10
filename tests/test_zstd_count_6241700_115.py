"""Tests for the node #115 zstd-sys ZSTD_count model (0x6241700, RE-002).

Covers the closed-form result, the tiered walk it is cross-checked
against, the committed reviewable ledger, the in-memory full sweep and
random differential, the caller-consumer census, and binary bindings
(body hash, empty relocation record, byte windows).
"""
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

from tools.zstd_count_6241700_115 import (
    ARTIFACT_SHA256,
    PACKET,
    START,
    END,
    zstd_count,
    zstd_count_tiers,
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


class ZstdCountSemanticsTest(unittest.TestCase):
    def test_empty_limit_is_zero(self):
        self.assertEqual(zstd_count(b"", b"", 0), 0)
        self.assertEqual(zstd_count(b"\x00", b"\x00", 0), 0)

    def test_first_byte_mismatch(self):
        self.assertEqual(zstd_count(b"\x01\x02", b"\x09\x02", 2), 0)

    def test_full_match_equals_limit(self):
        self.assertEqual(zstd_count(b"ABCDE", b"ABCDE", 5), 5)

    def test_match_capped_at_limit(self):
        self.assertEqual(zstd_count(b"ABCDEFGH", b"ABCDEFGH", 3), 3)

    def test_partial_match(self):
        self.assertEqual(zstd_count(b"ABX", b"ABY", 3), 2)

    def test_match_beyond_limit_not_counted(self):
        # Equal ranges but the limit is one byte: the routine stops
        # before comparing the second byte.
        self.assertEqual(zstd_count(b"AB", b"AB", 1), 1)

    def test_qword_tier_mismatch_offset(self):
        for last in range(8):
            a = b"\x33" * 8
            b = bytearray(a)
            b[last] ^= 0x80
            self.assertEqual(zstd_count(a, bytes(b), 8), last)

    def test_dword_tier_after_qword(self):
        a = b"\x55" * 12
        b = bytearray(a)
        b[10] ^= 0x40
        self.assertEqual(zstd_count(a, bytes(b), 12), 10)

    def test_word_tier_after_dword(self):
        a = b"\x66" * 10
        b = bytearray(a)
        b[9] ^= 0x02
        self.assertEqual(zstd_count(a, bytes(b), 10), 9)

    def test_byte_tier_after_word(self):
        a = b"\x77" * 9
        b = bytearray(a)
        b[8] ^= 0x08
        self.assertEqual(zstd_count(a, bytes(b), 9), 8)

    def test_tiers_agree_with_closed_form(self):
        rng = random.Random(115)
        for _ in range(20000):
            lim = rng.randrange(0, 200)
            a = bytes(rng.randrange(256) for _ in range(lim))
            b = bytearray(a)
            if lim and rng.random() < 0.7:
                b[rng.randrange(lim)] ^= 1 << rng.randrange(8)
            b = bytes(b)
            self.assertEqual(zstd_count(a, b, lim),
                             zstd_count_tiers(a, b, lim))

    def test_negative_limit_rejected(self):
        with self.assertRaises(ValueError):
            zstd_count(b"", b"", -1)

    def test_short_range_rejected(self):
        # The binary would read past a range shorter than the limit.
        with self.assertRaises(ValueError):
            zstd_count(b"AB", b"AB", 5)


class ZstdCountLedgerTest(unittest.TestCase):
    """The committed ledger is the review artifact: small enough to read.
    The exhaustive sweep is re-derived here, in memory."""

    def test_committed_ledger_replays(self):
        rows = (PACKET / "cases.tsv").read_text().splitlines()
        header = rows[0].split("\t")
        self.assertEqual(header, ["id", "group", "param", "expected"])
        data = rows[1:]
        self.assertEqual(len(data), 300)
        # Every comparison width and both cap paths are represented.
        groups = {line.split("\t")[1] for line in data}
        self.assertEqual(groups, {"boundary", "tiers", "random", "mixed"})
        for line in data:
            cid, group, param, expected = line.split("\t")
            p = json.loads(param)
            got = zstd_count(bytes.fromhex(p["in"]),
                             bytes.fromhex(p["match"]), p["limit"])
            self.assertEqual(got, json.loads(expected)["count"], cid)

    def test_committed_ledger_is_the_documented_subset(self):
        committed = (PACKET / "cases.tsv").read_text()
        want = ["id\tgroup\tparam\texpected"]
        for r in ledger_rows():
            want.append("\t".join(r[k] for k in ("id", "group", "param",
                                                  "expected")))
        self.assertEqual(committed, "\n".join(want) + "\n")
        # And it is a subset of the generated sweep, not a separate set.
        sweep = {r["id"]: r for r in generate_cases()}
        for r in ledger_rows():
            self.assertEqual(sweep[r["id"]]["expected"], r["expected"])

    def test_full_sweep_matches_tier_walk(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        for c in cases:
            p = json.loads(c["param"])
            ip, m, lim = (bytes.fromhex(p["in"]), bytes.fromhex(p["match"]),
                          p["limit"])
            self.assertEqual(zstd_count(ip, m, lim),
                             zstd_count_tiers(ip, m, lim), c["id"])

    def test_random_differential_200k(self):
        rng = random.Random(6241700)
        for i in range(200_000):
            lim = rng.randrange(0, 41)
            ip = bytes(rng.randrange(256) for _ in range(lim))
            lcp = rng.randrange(lim + 1)
            m = bytearray(ip)
            if lcp < lim:
                m[lcp] ^= 1 << rng.randrange(8)
            m = bytes(m)
            if zstd_count(ip, m, lim) != zstd_count_tiers(ip, m, lim):
                self.fail(f"mismatch at case {i}: {ip.hex()} {m.hex()} {lim}")


class ZstdCountCallerCensusTest(unittest.TestCase):
    """What the call sites depend on: the census classifies the first read
    of the returned count inside each enclosing FDE."""

    def setUp(self):
        path = PACKET / "caller_use.tsv"
        if not path.is_file():
            self.skipTest("caller census not generated")
        rows = path.read_text().splitlines()
        self.header = rows[0].split("\t")
        self.rows = [dict(zip(self.header, line.split("\t")))
                     for line in rows[1:]]

    def test_every_call_site_has_a_consumer(self):
        self.assertEqual(len(self.rows), 25)
        self.assertTrue(all(r["consumer"] for r in self.rows))

    def test_count_is_consumed_as_a_length(self):
        # The callers depend on an exact, bounded common-prefix length:
        # the dominant use folds it into a running length.
        classes = {}
        for r in self.rows:
            classes[r["consumer"]] = classes.get(r["consumer"], 0) + 1
        self.assertEqual(classes.get("length-arithmetic"), 19)
        self.assertEqual(sum(classes.values()), 25)

    def test_minmatch_offsets_are_visible_in_the_callers(self):
        # Nine sites add zstd's MINMATCH+1 offset to the count, which is the
        # semantic the byte match alone does not state.
        plus4 = [r for r in self.rows if r["use"] == "add rax, 4"]
        self.assertEqual(len(plus4), 9)

    def test_caller_fdes_are_recorded(self):
        for r in self.rows:
            a, b = r["caller_fde"].split("..")
            self.assertLess(int(a, 16), int(b, 16))
            self.assertNotEqual(int(a, 16), START)


class ZstdCountBindingsTest(unittest.TestCase):
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
        body = self.data[_va_to_off(START):_va_to_off(END)]
        self.assertEqual(hashlib.sha256(body).hexdigest(),
                         rec["target_body_sha256"])
        self.assertEqual(rec["target_body_sha256"],
                         rec["source_body_sha256"])

    def test_byte_windows(self):
        body = self.data[_va_to_off(START):_va_to_off(END)]
        self.assertEqual(len(body), END - START)
        # The two 64-bit tzcnt instructions the qword mismatch paths
        # use are present (tzcnt r64, r64 = F3 REX.W 0F BC /r), and the
        # function has no endbr64 prologue (its first bytes are the
        # `lea` it opens with), matching the objdump excerpt in main.txt.
        self.assertEqual(body.count(b"\xf3\x48\x0f\xbc"), 2)
        self.assertEqual(body[:4], b"\x4c\x8d\x42\xf9")
        self.assertNotIn(b"\xf3\x0f\x1e\xfa", body)

    def test_claim_anchors_are_in_the_target(self):
        # Target evidence: every behavioural claim is anchored to an
        # instruction address whose bytes are really in the image.
        rows = (PACKET / "semantics.tsv").read_text().splitlines()
        header = rows[0].split("\t")
        self.assertEqual(header, ["claim", "va", "size", "bytes",
                                  "instruction", "note"])
        self.assertEqual(len(rows) - 1, 21)
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
