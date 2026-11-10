"""Evidence-packet tests for node #115 rocksdb MaxFileSizeForL0MetaPin.

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

from tools.max_file_size_for_l0_meta_pin_607f490_115 import (
    GUARD,
    SENTINEL,
    START,
    END,
    instruction_stream,
    max_file_size_for_l0_meta_pin,
    max_file_size_for_l0_meta_pin_decoded,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-max-file-size-for-l0-meta-pin-607f490-115")
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


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].mnemonic, "ret")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 11)

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 43 bytes

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
        # The `instruction` column is re-derived here by decoding the recorded
        # bytes with capstone, so the table is checked against the binary
        # rather than against a transcription of itself.
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        text = (PACKET / "semantics.tsv").read_text().splitlines()
        self.assertEqual(len(text) - 1, 11)
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
        self.assertIn(0x607F4A8, seen)                     # the guard compare
        self.assertIn(0x607F4AB, seen)                     # the guard branch
        self.assertIn(0x607F4B7, seen)                     # the three-halves add

    def test_guard_compare_is_unsigned(self):
        insns = {i.addr: i for i in instruction_stream()}
        self.assertEqual(insns[0x607F4A8].op_str, "%rdx,%rcx")
        self.assertTrue(insns[0x607F4AB].mnemonic == "jb")
        self.assertEqual(insns[0x607F4AB].op_str.split()[0], "607f4ba")

    def test_the_model_reads_exactly_one_field(self):
        # mov (%rdi),%rdx is the only memory operand in the routine
        mem = [i for i in instruction_stream() if "(" in i.op_str]
        self.assertEqual([(hex(i.addr), i.mnemonic, i.op_str) for i in mem],
                         [("0x607f494", "mov", "(%rdi),%rdx")])


class Model(unittest.TestCase):
    def test_result_is_three_halves(self):
        for v in list(range(0, 41)) + [0xFFFF, 1 << 40, (1 << 40) + 1]:
            self.assertEqual(max_file_size_for_l0_meta_pin(v), 3 * (v >> 1), v)

    def test_odd_inputs_truncate_before_the_multiply(self):
        # 3*(5>>1)=6, whereas (3*5)>>1=7: the shift is first
        self.assertEqual(max_file_size_for_l0_meta_pin(5), 6)
        self.assertEqual(max_file_size_for_l0_meta_pin(7), 9)
        self.assertEqual(max_file_size_for_l0_meta_pin(6), 9)
        self.assertEqual(max_file_size_for_l0_meta_pin(1), 0)

    def test_the_guard_boundary_is_inclusive(self):
        self.assertEqual(GUARD, 0xAAAAAAAAAAAAAAAB)
        self.assertEqual(max_file_size_for_l0_meta_pin(GUARD), SENTINEL)
        self.assertEqual(max_file_size_for_l0_meta_pin(GUARD + 1), SENTINEL)
        self.assertEqual(max_file_size_for_l0_meta_pin((1 << 64) - 1), SENTINEL)

    def test_the_largest_accepted_input_equals_the_sentinel_value(self):
        # 3*(GUARD>>1) == 2**64-1 == SENTINEL: the two are indistinguishable
        self.assertEqual(3 * (GUARD >> 1), SENTINEL)
        self.assertLessEqual(max_file_size_for_l0_meta_pin(GUARD - 1), SENTINEL)

    def test_decoded_execution_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(max_file_size_for_l0_meta_pin(c["value"]),
                             max_file_size_for_l0_meta_pin_decoded(c["value"]),
                             hex(c["value"]))

    def test_random_differential_20k(self):
        rng = random.Random(115)
        for _ in range(20000):
            v = rng.getrandbits(64)
            self.assertEqual(max_file_size_for_l0_meta_pin(v),
                             max_file_size_for_l0_meta_pin_decoded(v), hex(v))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_four_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {"boundary": 600, "small": 600,
                                "parity": 600, "random": 600})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            self.assertEqual(replay_case(r), r["expected"], r)
            self.assertEqual(max_file_size_for_l0_meta_pin_decoded(r["value"]),
                             r["expected"], r)

    def test_committed_ledger_is_the_documented_subset(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(sorted(fams.values()), [75, 75, 75, 75])

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "value", "expected",
                          "the_sentinel", "accepted"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, value, expected, sentinel, accepted = line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(value, hex(r["value"]))
            self.assertEqual(expected, hex(r["expected"]))
            self.assertEqual(sentinel, "1" if r["expected"] == SENTINEL else "0")
            self.assertEqual(accepted, "0" if r["value"] > GUARD else "1")


class CallerCensus(unittest.TestCase):
    def rows(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        return [l.split("\t") for l in lines[1:] if l.strip()]

    def test_twelve_direct_calls_in_eleven_fdes(self):
        rows = self.rows()
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({(r[2], r[3]) for r in rows}), 11)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_every_caller_has_a_consumer_row(self):
        rows = self.rows()
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), len(rows))
        self.assertEqual({u[0] for u in uses}, {r[0] for r in rows})
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"stack-arg": 4, "register-copy": 4,
                                  "store": 3, "overwritten": 1})

    def test_the_single_dead_call_site(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        dead = [u for u in uses if u[1] == "overwritten"]
        self.assertEqual([u[0] for u in dead], ["0x5f96072"])
        for u in uses:
            self.assertTrue(u[4].strip(), u)          # a recorded continuation

    def test_records_json_agrees_with_the_tables(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["caller_census"]["direct_calls"], 12)
        self.assertEqual(rec["caller_census"]["consumers"],
                         {"stack-arg": 4, "register-copy": 4,
                          "store": 3, "overwritten": 1})
        self.assertEqual(rec["artifact"], "artifacts/node/115/hl-node")
        self.assertEqual(rec["claim_anchors"].split(" ")[0], "semantics.tsv")
        self.assertEqual(len(rec["caller_census"]["caller_fdes"]), 11)
        self.assertGreaterEqual(len(rec["unknowns"]), 4)
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
                         "d7ece8bd5f9dc186-cf_options.o")
        self.assertEqual(rec["bound_context"]["identical_source_count"], 3)


if __name__ == "__main__":
    unittest.main()
