"""Evidence-packet tests for node #115 libz _tr_flush_bits.

Every assertion is made against the digest-verified artifact or the packet's own
committed tables; the model is additionally checked against execution of the
routine's own decoded instruction bytes.
"""
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

import capstone

from tools.tr_flush_bits_630b9c0_115 import (
    START,
    END,
    STRUCT,
    BUFFER,
    OFF_PTR,
    OFF_PENDING,
    OFF_BIBUF,
    OFF_BIVALID,
    FAMILIES,
    BOUNDARY_CASES,
    instruction_stream,
    split_ops,
    mem_size,
    flush_bits,
    flush_bits_decoded,
    flush_accesses,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-libz-tr-flush-bits-630b9c0-115")
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


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


def decoded(va):
    """The capstone instruction at `va`, decoded from the artifact itself."""
    data = BINARY.read_bytes()
    off = va_to_off(va)
    return next(iter(MD.disasm(data[off:off + 15], va)))


def ins_at(va):
    return next(i for i in instruction_stream() if i.addr == va)


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_leaf_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 32)
        self.assertEqual([i.addr for i in insns if i.mnemonic.startswith("call")],
                         [])
        self.assertEqual([i.addr for i in insns if i.mnemonic == "ret"],
                         [0x630B9FD, 0x630BA47])

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 136 bytes

    def test_the_body_digest_matches_the_artifact(self):
        digest = hashlib.sha256(window_bytes()).hexdigest()
        recorded = (PACKET / "relocations.txt").read_text()
        self.assertIn(digest, recorded)
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["bound_context"]["target_body_sha256"], digest)
        self.assertEqual(rec["bound_context"]["source_body_sha256"], digest)
        self.assertTrue(rec["bound_context"]["raw_equal"])
        self.assertEqual(rec["bound_context"]["relocations"], [])
        self.assertEqual(rec["bound_context"]["identical_source_count"], 3)

    def test_claim_anchors_are_in_the_target(self):
        text = (PACKET / "semantics.tsv").read_text().splitlines()
        self.assertEqual(len(text) - 1, 20)
        data = BINARY.read_bytes()
        seen = set()
        for line in text[1:]:
            claim, va, size, raw, insn, note = line.split("\t")
            off = va_to_off(int(va, 16))
            chunk = data[off:off + int(size)]
            self.assertEqual(chunk.hex(), raw, claim)
            dec = next(iter(MD.disasm(chunk, int(va, 16))))
            self.assertEqual(f"{dec.mnemonic} {dec.op_str}".strip(), insn, claim)
            self.assertTrue(note.strip())
            seen.add(int(va, 16))
        for required in (0x630B9C4, 0x630B9CD, 0x630B9D2, 0x630B9EB,
                         0x630B9EE, 0x630B9F5, 0x630BA36, 0x630BA3D):
            self.assertIn(required, seen, hex(required))

    def test_the_dispatch_is_three_way_and_ordered(self):
        sixteen = decoded(0x630B9CA)
        self.assertEqual(sixteen.mnemonic, "cmp")
        self.assertEqual(sixteen.operands[1].imm, 0x10)
        self.assertEqual(decoded(0x630B9CD).mnemonic, "je")
        self.assertEqual(decoded(0x630B9CD).operands[0].imm, 0x630BA00)
        seven = decoded(0x630B9CF)
        self.assertEqual(seven.mnemonic, "cmp")
        self.assertEqual(seven.operands[1].imm, 7)

    def test_the_nothing_to_do_test_is_signed(self):
        jump = decoded(0x630B9D2)
        self.assertEqual(jump.mnemonic, "jle")          # signed, not jbe
        self.assertEqual(jump.operands[0].imm, 0x630B9FD)

    def test_the_counter_is_incremented_before_the_store(self):
        self.assertEqual(decoded(0x630B9E3).mnemonic, "lea")
        store = decoded(0x630B9E7)
        self.assertEqual(store.op_str, "qword ptr [rdi + 0x28], rsi")
        byte = decoded(0x630B9EB)
        self.assertEqual(byte.op_str, "byte ptr [rdx + rax], cl")  # pre-inc index

    def test_the_two_memory_rmws_have_different_widths(self):
        # objdump's text hides this: the count drops by 8 as a 4-byte RMW ...
        self.assertEqual(decoded(0x630B9EE).operands[0].size, 4)
        self.assertEqual(decoded(0x630B9EE).operands[1].imm, 8)
        # ... while the bit buffer shifts down as a 2-byte one
        self.assertEqual(decoded(0x630B9F5).operands[0].size, 2)
        self.assertEqual(decoded(0x630B9F5).operands[1].imm, 8)
        self.assertEqual(mem_size(ins_at(0x630B9EE)), 4)
        self.assertEqual(mem_size(ins_at(0x630B9F5)), 2)

    def test_the_zero_stores_use_each_fields_own_width(self):
        buf = decoded(0x630BA36)
        self.assertEqual(buf.op_str, "word ptr [rdi + 0x1730], ax")
        self.assertEqual(buf.operands[0].size, 2)
        valid = decoded(0x630BA3D)
        self.assertEqual(valid.op_str, "dword ptr [rdi + 0x1734], 0")
        self.assertEqual(valid.operands[0].size, 4)

    def test_the_two_emitted_bytes_come_from_the_low_and_high_halves(self):
        self.assertEqual(decoded(0x630B9D8).op_str,
                         "ecx, word ptr [rdi + 0x1730]")     # low byte source
        self.assertEqual(decoded(0x630BA1E).op_str,
                         "ecx, byte ptr [rdi + 0x1731]")     # bi_buf >> 8
        self.assertEqual((OFF_PTR, OFF_PENDING, OFF_BIBUF, OFF_BIVALID),
                         (0x10, 0x28, 0x1730, 0x1734))

    def test_the_padding_nop(self):
        ins = ins_at(0x630B9FE)
        self.assertEqual(ins.raw, bytes.fromhex("6690"))
        self.assertEqual(decoded(0x630B9FE).mnemonic, "nop")


class Model(unittest.TestCase):
    def test_the_three_way_dispatch(self):
        self.assertEqual(flush_bits(0, 0x1234, 5), (0, 0x1234, 5, [], 0))
        self.assertEqual(flush_bits(7, 0x1234, 5), (7, 0x1234, 5, [], 7))
        self.assertEqual(flush_bits(8, 0x1234, 5), (0, 0x12, 6, [0x34], 5))
        self.assertEqual(flush_bits(15, 0xABCD, 0), (7, 0xAB, 1, [0xCD], 0))
        self.assertEqual(flush_bits(16, 0x1234, 5), (0, 0, 7, [0x34, 0x12], 0))
        self.assertEqual(flush_bits(16, 0xFF00, 2), (0, 0, 4, [0x00, 0xFF], 0))

    def test_the_nothing_to_do_test_is_signed(self):
        for v in (0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF):
            self.assertEqual(flush_bits(v, 0xFFFF, 3), (v, 0xFFFF, 3, [], v),
                             hex(v))
            self.assertEqual(flush_bits_decoded(v, 0xFFFF, 3),
                             flush_bits(v, 0xFFFF, 3), hex(v))
        # one below the sign bit takes the one-byte path instead
        self.assertEqual(flush_bits(0x7FFFFFFF, 0x1234, 0)[3], [0x34])
        self.assertEqual(flush_bits(0x7FFFFFFF, 0x1234, 0)[1], 0x12)

    def test_out_of_range_positive_values_take_the_one_byte_path(self):
        for v, new_v in ((17, 9), (18, 10), (23, 15), (24, 16), (100, 92)):
            got = flush_bits(v, 0x1234, 0)
            self.assertEqual(got[0], new_v, hex(v))
            self.assertEqual(got[1], 0x12, hex(v))
            self.assertEqual(got[3], [0x34], hex(v))
            self.assertEqual(flush_bits_decoded(v, 0x1234, 0), got, hex(v))
        # 24 lands back on the two-byte value on a *later* call, not this one
        self.assertEqual(flush_bits(24, 0, 0), (16, 0, 1, [0], 0))

    def test_the_two_byte_emit_is_little_endian(self):
        for buf in (0x1234, 0xFF00, 0x00FF, 0xFFFF, 0x0000):
            emitted = flush_bits(16, buf, 0)[3]
            self.assertEqual(emitted, [buf & 0xFF, (buf >> 8) & 0xFF], hex(buf))
            self.assertEqual(bytes(emitted), buf.to_bytes(2, "little"), hex(buf))

    def test_the_three_rax_leftovers(self):
        # nothing to do -> bi_valid; one byte -> the OLD pending; two -> 0
        self.assertEqual(flush_bits(3, 0, 7)[4], 3)
        self.assertEqual(flush_bits(9, 0, 7)[4], 7)
        self.assertEqual(flush_bits(16, 0, 7)[4], 0)
        for case, expected in (((3, 0, 7), 3), ((9, 0, 7), 7), ((16, 0, 7), 0)):
            self.assertEqual(flush_bits_decoded(*case)[4], expected)

    def test_the_emit_lands_at_the_pre_increment_index(self):
        _, stores = flush_accesses(9, 0x1234, 4)
        self.assertEqual([(a, s) for a, s in stores if a >= BUFFER],
                         [(BUFFER + 4, 1)])
        _, stores = flush_accesses(16, 0x1234, 4)
        self.assertEqual([(a, s) for a, s in stores if a >= BUFFER],
                         [(BUFFER + 4, 1), (BUFFER + 5, 1)])

    def test_the_field_write_widths_per_path(self):
        # nothing to do: the routine only reads
        _, stores = flush_accesses(3, 0x1234, 4)
        self.assertEqual(stores, [])
        # one byte: pending (8), the byte (1), bi_valid (4), bi_buf (2)
        _, stores = flush_accesses(9, 0x1234, 4)
        self.assertEqual(stores, [(STRUCT + OFF_PENDING, 8), (BUFFER + 4, 1),
                                  (STRUCT + OFF_BIVALID, 4),
                                  (STRUCT + OFF_BIBUF, 2)])
        # two bytes: pending, byte, pending, byte, then both fields zeroed
        _, stores = flush_accesses(16, 0x1234, 4)
        self.assertEqual(stores, [(STRUCT + OFF_PENDING, 8), (BUFFER + 4, 1),
                                  (STRUCT + OFF_PENDING, 8), (BUFFER + 5, 1),
                                  (STRUCT + OFF_BIBUF, 2),
                                  (STRUCT + OFF_BIVALID, 4)])

    def test_the_decoded_run_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(flush_bits(c["bi_valid"], c["bi_buf"],
                                        c["pending"]),
                             flush_bits_decoded(c["bi_valid"], c["bi_buf"],
                                                c["pending"]), c)

    def test_random_differential(self):
        rng = random.Random(115)
        for _ in range(3000):
            v = rng.randrange(0, 1 << 32)
            b = rng.getrandbits(16)
            p = rng.randrange(0, 8)
            self.assertEqual(flush_bits(v, b, p), flush_bits_decoded(v, b, p),
                             (hex(v), hex(b), p))

    def test_the_invariant_inside_the_two_cases(self):
        # in the 8..15 and 16 paths the count only ever decreases to 0..15
        for v in range(8, 17):
            new_valid = flush_bits(v, 0x1234, 0)[0]
            self.assertIn(new_valid, range(0, 16), v)


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_five_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {f: 480 for f in FAMILIES})

    def test_the_ledger_keeps_the_boundary_rows_verbatim(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        for fam, bunch in BOUNDARY_CASES.items():
            head = [r for r in rows if r["family"] == fam][:len(bunch)]
            self.assertEqual([(r["bi_valid"], r["bi_buf"], r["pending"])
                              for r in head], bunch, fam)
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(fams, {f: 60 for f in FAMILIES})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            ans = replay_case(r)
            self.assertEqual((r["new_bi_valid"], r["new_bi_buf"],
                              r["new_pending"], r["emitted"], r["leftover"]),
                             ans, r)
            self.assertEqual(len(r["emitted"]),
                             2 if r["bi_valid"] == 16 else
                             (0 if (r["bi_valid"] & 0x80000000) or
                              r["bi_valid"] <= 7 else 1), r)

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "bi_valid", "bi_buf", "pending",
                          "emitted", "new_bi_valid", "new_bi_buf",
                          "new_pending", "rax_leftover"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            parts = line.split("\t")
            self.assertEqual(int(parts[0]), r["id"])
            self.assertEqual(parts[1], r["family"])
            self.assertEqual(parts[2], hex(r["bi_valid"]))
            self.assertEqual(parts[3], hex(r["bi_buf"]))
            self.assertEqual(int(parts[4]), r["pending"])
            self.assertEqual(parts[5],
                             "".join(f"{b:02x}" for b in r["emitted"]) or "-")
            self.assertEqual(parts[6], hex(r["new_bi_valid"]))
            self.assertEqual(parts[7], hex(r["new_bi_buf"]))
            self.assertEqual(int(parts[8]), r["new_pending"])
            self.assertEqual(parts[9], hex(r["leftover"]))


class CallerCensus(unittest.TestCase):
    def test_the_call_sites_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 26)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_every_call_site_discards_rax(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 26)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"overwritten": 26})
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertEqual(census["direct_calls"], 26)
        self.assertEqual(census["sites_reading_the_return"], 0)
        self.assertEqual(census["discarded_sites"], 26)
        self.assertTrue(census["contract"].startswith("void-style"))
        self.assertEqual(census["caller_fdes"], 4)

    def test_observations_and_inferences_are_separated(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual({o["kind"] for o in rec["observations"]},
                         {"observation", "inference"})
        self.assertGreaterEqual(len(rec["unknowns"]), 4)
        self.assertEqual(rec["claim_anchors"].split(" ")[0], "semantics.tsv")


class Bindings(unittest.TestCase):
    def test_fde_bound_is_the_whole_routine(self):
        frames = (PACKET / "frames.txt").read_text()
        self.assertIn(f"pc={START:016x}..{END:016x}", frames)

    def test_the_excerpt_header_is_the_bound_address(self):
        first = (PACKET / "main.txt").read_text().splitlines()[0]
        self.assertTrue(first.startswith(f"{START:016x} <"), first)

    def test_artifact_and_member_are_pinned(self):
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(
            rec["artifact_sha256"],
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
        self.assertEqual(rec["bound_context"]["member"],
                         "b9b191b8e1a44c35-trees.o")
        self.assertEqual(rec["bound_context"]["crate"], "libz-sys")
        self.assertEqual(rec["bound_context"]["symbol"], "_tr_flush_bits")
        self.assertEqual(rec["bound_context"]["candidate_versions"],
                         ["1.1.22", "1.1.31"])
        self.assertIn("ZLIB_VERSION", rec["bound_context"]["version_note"])


if __name__ == "__main__":
    unittest.main()
