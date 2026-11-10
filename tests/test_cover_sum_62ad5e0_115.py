"""Evidence-packet tests for node #115 zstd COVER_sum.

Every assertion is made against the digest-verified artifact or the packet's
own committed tables; the model is additionally checked against execution of
the routine's own decoded instruction bytes.
"""
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

from tools.cover_sum_62ad5e0_115 import (
    START,
    END,
    M64,
    instruction_stream,
    cover_sum,
    cover_sum_decoded,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-cover-sum-62ad5e0-115")
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise AssertionError(f"{va:#x} is not in any LOAD segment")


def window_bytes():
    data = BINARY.read_bytes()
    return data[va_to_off(START):va_to_off(END)]


import capstone

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


def decoded(va):
    """The capstone instruction at `va`, decoded from the artifact itself.

    Assertions about operands go through the decoder rather than through
    objdump's text, which mixes decimal and hex immediates (`$1` vs `$0x4`)
    and prints branch targets without a `0x` prefix.
    """
    data = BINARY.read_bytes()
    off = va_to_off(va)
    return next(iter(MD.disasm(data[off:off + 15], va)))


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 32)

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 97 bytes

    def test_the_body_digest_matches_the_artifact(self):
        digest = hashlib.sha256(window_bytes()).hexdigest()
        recorded = (PACKET / "relocations.txt").read_text()
        self.assertIn(digest, recorded)
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["bound_context"]["target_body_sha256"], digest)
        self.assertEqual(rec["bound_context"]["source_body_sha256"], digest)
        self.assertTrue(rec["bound_context"]["raw_equal"])
        self.assertEqual(rec["bound_context"]["relocations"], [])

    def test_claim_anchors_are_in_the_target(self):
        # The `instruction` column is re-derived by decoding the recorded bytes
        # with capstone, so the table is checked against the binary rather than
        # against a transcription of itself.
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        text = (PACKET / "semantics.tsv").read_text().splitlines()
        self.assertEqual(len(text) - 1, 19)
        data = BINARY.read_bytes()
        seen = set()
        for line in text[1:]:
            claim, va, size, raw, insn, note = line.split("\t")
            off = va_to_off(int(va, 16))
            chunk = data[off:off + int(size)]
            self.assertEqual(chunk.hex(), raw, claim)
            dec = next(iter(md.disasm(chunk, int(va, 16))))
            self.assertEqual(f"{dec.mnemonic} {dec.op_str}".strip(), insn, claim)
            self.assertTrue(note.strip())
            seen.add(int(va, 16))
        for required in (0x62AD5E6, 0x62AD5EB, 0x62AD600, 0x62AD608,
                         0x62AD623, 0x62AD62C, 0x62AD638):
            self.assertIn(required, seen, hex(required))

    def test_the_two_short_circuits_are_branches(self):
        self.assertEqual(decoded(0x62AD5E4).mnemonic, "test")
        self.assertEqual(decoded(0x62AD5E6).mnemonic, "je")
        self.assertEqual(decoded(0x62AD5E6).operands[0].imm, 0x62AD638)
        cmp1 = decoded(0x62AD5E8)      # cmp esi, 1  -> [0]=esi, [1]=1
        self.assertEqual(cmp1.mnemonic, "cmp")
        self.assertEqual(MD.reg_name(cmp1.operands[0].reg), "esi")
        self.assertEqual(cmp1.operands[1].imm, 1)
        self.assertEqual(decoded(0x62AD5EB).mnemonic, "je")
        self.assertEqual(decoded(0x62AD5EB).operands[0].imm, 0x62AD63B)

    def test_there_is_exactly_one_scalar_add_from_memory(self):
        adds = [i for i in instruction_stream()
                if i.mnemonic == "add" and "(" in i.op_str and i.op_str
                .endswith("%rax")]
        self.assertEqual([(hex(i.addr), i.op_str) for i in adds],
                         [("0x62ad62c", "(%rdi,%rsi,8),%rax")])

    def test_the_vector_path_is_lane_wise_and_16_bytes_wide(self):
        self.assertEqual(decoded(0x62AD600).mnemonic, "movdqu")
        self.assertEqual(decoded(0x62AD608).mnemonic, "paddq")
        self.assertEqual(decoded(0x62AD615).mnemonic, "psrldq")
        self.assertEqual(decoded(0x62AD61E).mnemonic, "movq")
        # the loop count is n >> 1 and the byte stride is 16
        self.assertEqual(decoded(0x62AD5F6).operands[1].imm, 1)
        self.assertEqual(decoded(0x62AD5F8).operands[1].imm, 4)


class Model(unittest.TestCase):
    def test_n_zero_returns_zero(self):
        self.assertEqual(cover_sum([7, 8, 9], 0), 0)
        self.assertEqual(cover_sum_decoded([7, 8, 9], 0), 0)

    def test_n_one_returns_the_first_element(self):
        for v in (0, 1, 255, 1 << 63, M64):
            self.assertEqual(cover_sum([v, M64], 1), v)
            self.assertEqual(cover_sum_decoded([v, M64], 1), v)

    def test_odd_n_adds_the_tail_after_the_vector_fold(self):
        self.assertEqual(cover_sum([1, 2, 3], 2), 3)          # vector only
        self.assertEqual(cover_sum([1, 2, 3], 3), 6)          # + tail
        self.assertEqual(cover_sum_decoded([1, 2, 3], 3), 6)
        self.assertEqual(cover_sum_decoded([4, 5, 6, 7, 8], 5), 30)

    def test_the_sum_wraps_modulo_2_64(self):
        self.assertEqual(cover_sum([M64, 1], 2), 0)
        self.assertEqual(cover_sum_decoded([M64, 1], 2), 0)
        self.assertEqual(cover_sum_decoded([M64, M64], 2), M64 - 1)
        self.assertEqual(cover_sum([1 << 63, 1 << 63], 2), 0)

    def test_the_order_of_the_elements_does_not_matter(self):
        rng = random.Random(5)
        for _ in range(200):
            vals = [rng.getrandbits(64) for _ in range(rng.randrange(2, 10))]
            self.assertEqual(cover_sum(vals, len(vals)),
                             cover_sum(list(reversed(vals)), len(vals)))

    def test_out_of_range_n_is_rejected(self):
        with self.assertRaises(IndexError):
            cover_sum([1, 2], 3)

    def test_decoded_execution_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(cover_sum(c["splits"], c["n"]),
                             cover_sum_decoded(c["splits"], c["n"]), c)

    def test_random_differential(self):
        rng = random.Random(115)
        for _ in range(3000):
            k = rng.randrange(1, 14)
            sp = [rng.getrandbits(64) for _ in range(k)]
            n = rng.randrange(0, k + 1)
            self.assertEqual(cover_sum(sp, n), cover_sum_decoded(sp, n),
                             (n, sp))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_four_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {"empty": 600, "single": 600,
                                "pairs": 600, "odd": 600})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            self.assertEqual(replay_case(r), r["expected"], r)
            self.assertEqual(cover_sum_decoded(r["splits"], r["n"]),
                             r["expected"], r)

    def test_committed_ledger_is_the_documented_subset(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(sorted(fams.values()), [75, 75, 75, 75])
        self.assertTrue(all(r["n"] <= 4 for r in rows), "keep rows reviewable")

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "n", "splits", "expected",
                          "wraps", "tail_add"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, n, splits, expected, wraps, tail = line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(fam, r["family"])
            self.assertEqual(int(n), r["n"])
            self.assertEqual(expected, hex(r["expected"]))
            self.assertEqual(tail, "1" if r["tail"] else "0")


class CallerCensus(unittest.TestCase):
    def test_three_callers_in_one_fde(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 3)
        self.assertEqual({(r[2], r[3]) for r in rows},
                         {("0x62ac520", "0x62ac9c9")})
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_every_caller_consumes_the_returned_value(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 3)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
            self.assertNotEqual(u[1], "overwritten",
                                "no call site discards the sum")
            self.assertTrue(u[4].strip(), u)      # a recorded continuation
        self.assertEqual(counts, {"register-copy": 2, "store": 1})

    def test_records_json_agrees_with_the_tables(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["caller_census"]["direct_calls"], 3)
        self.assertEqual(rec["caller_census"]["consumers"],
                         {"register-copy": 2, "store": 1})
        self.assertEqual(rec["artifact"], "artifacts/node/115/hl-node")
        self.assertEqual(rec["claim_anchors"].split(" ")[0], "semantics.tsv")
        self.assertEqual(len(rec["caller_census"]["caller_fdes"]), 1)
        self.assertGreaterEqual(len(rec["unknowns"]), 3)
        kinds = {o["kind"] for o in rec["observations"]}
        self.assertEqual(kinds, {"observation", "inference"})


class Bindings(unittest.TestCase):
    def test_fde_bound_is_the_whole_routine(self):
        frames = (PACKET / "frames.txt").read_text()
        self.assertIn(f"pc={START:016x}..{END:016x}", frames)

    def test_the_excerpt_header_is_the_bound_address(self):
        first = (PACKET / "main.txt").read_text().splitlines()[0]
        self.assertTrue(first.startswith(f"{START:016x} <"), first)

    def test_artifact_digest_is_pinned(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(
            rec["artifact_sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(rec["bound_context"]["member"],
                         "ebb58710e9060628-cover.o")
        self.assertEqual(rec["bound_context"]["crate"], "zstd-sys")
        self.assertEqual(rec["bound_context"]["identical_source_count"], 3)


if __name__ == "__main__":
    unittest.main()
