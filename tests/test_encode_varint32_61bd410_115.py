"""Evidence-packet tests for node #115 rocksdb EncodeVarint32.

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

from tools.encode_varint32_61bd410_115 import (
    START,
    END,
    M32,
    BOUND1,
    BOUND2,
    BOUND3,
    BOUND4,
    STORE32_CLASS,
    instruction_stream,
    split_ops,
    varint_len,
    encode_varint32,
    encode_varint32_decoded,
    uses_single_32bit_store,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-encode-varint32-61bd410-115")
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
    """The capstone instruction at `va`, decoded from the artifact itself.

    Operand assertions go through the decoder rather than through objdump's
    text, which mixes decimal and hex immediates and prints branch targets
    without a `0x` prefix.
    """
    data = BINARY.read_bytes()
    off = va_to_off(va)
    return next(iter(MD.disasm(data[off:off + 15], va)))


def leb128_decode(bs):
    """An independent decoder, used to round-trip the encoder's output."""
    out = 0
    for i, b in enumerate(bs):
        out |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return out
    raise AssertionError("no terminal byte")


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 62)

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 217 bytes

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
        self.assertEqual(len(text) - 1, 19)
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
        for required in (0x61BD417, 0x61BD41A, 0x61BD41C, 0x61BD4A0,
                         0x61BD4CB, 0x61BD423):
            self.assertIn(required, seen, hex(required))

    def test_the_class_bounds_are_the_expected_unsigned_compares(self):
        # the instruction after each bound test is looked up in the decoded
        # stream rather than assumed to be a fixed distance away: the cmp forms
        # are 3 and 6 bytes long and the bounds are followed by ja or jbe.
        addrs = [i.addr for i in instruction_stream()]
        for va, bound, target in ((0x61BD417, 0x7F, 0x61BD430),
                                  (0x61BD43C, 0x3FFF, 0x61BD458),
                                  (0x61BD460, 0x1FFFFF, 0x61BD4B0),
                                  (0x61BD474, 0x0FFFFFFF, 0x61BD4C8)):
            cmp_ = decoded(va)
            self.assertEqual(cmp_.mnemonic, "cmp", hex(va))
            self.assertEqual(cmp_.operands[1].imm, bound, hex(va))
            jump = decoded(addrs[addrs.index(va) + 1])
            self.assertIn(jump.mnemonic, ("ja", "jbe"), hex(va))
            self.assertEqual(jump.operands[0].imm, target, hex(va))

    def test_the_4_byte_class_uses_one_32_bit_store(self):
        big = decoded(0x61BD4A0)
        self.assertEqual(big.mnemonic, "mov")
        self.assertEqual(big.operands[0].size, 4)          # mov dword [rax], ecx
        self.assertEqual(big.operands[1].size, 4)
        # every other class writes one byte per store
        for va in (0x61BD41C, 0x61BD448, 0x61BD44B, 0x61BD4B4,
                   0x61BD4BA, 0x61BD4CE, 0x61BD4E0):
            store = decoded(va)
            self.assertEqual(store.mnemonic, "mov", hex(va))
            self.assertEqual(store.operands[0].size, 1, hex(va))

    def test_the_top_byte_of_the_5_byte_class_is_v_shifted_by_28(self):
        shr = decoded(0x61BD4CB)
        self.assertEqual(shr.mnemonic, "shr")
        self.assertEqual(shr.operands[1].imm, 0x1C)

    def test_there_are_three_return_tails_not_one(self):
        tails = [i for i in instruction_stream()
                 if i.mnemonic == "mov" and i.op_str == "%rdx,%rax"]
        self.assertEqual([hex(i.addr) for i in tails],
                         ["0x61bd423", "0x61bd44e", "0x61bd4be"])
        # the 4- and 5-byte classes jump to the first of them
        for va in (0x61BD4A2, 0x61BD4E4):
            jmp = decoded(va)
            self.assertEqual(jmp.mnemonic, "jmp")
            self.assertEqual(jmp.operands[0].imm, 0x61BD423)

    def test_the_routine_reads_no_memory(self):
        # every memory operand in the body is the LAST operand of its
        # instruction, i.e. a store destination; `lea` computes an address and
        # does not access memory, so it is the only instruction exempted.
        for ins in instruction_stream():
            if "(" not in ins.op_str or ins.mnemonic == "lea":
                continue
            ops = split_ops(ins.op_str)
            self.assertIn("(", ops[-1], ins)
            self.assertTrue(ops[-1].rstrip().endswith(")"), ins)


class Model(unittest.TestCase):
    def test_the_five_classes_at_every_boundary(self):
        self.assertEqual(
            [varint_len(v) for v in (0, 1, BOUND1, BOUND1 + 1, BOUND2,
                                     BOUND2 + 1, BOUND3, BOUND3 + 1, BOUND4,
                                     BOUND4 + 1, M32)],
            [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5])

    def test_the_encoded_bytes_at_every_boundary(self):
        table = {
            0x80: [0x80, 0x01], 0x3FFF: [0xFF, 0x7F],
            0x4000: [0x80, 0x80, 0x01], 0x1FFFFF: [0xFF, 0xFF, 0x7F],
            0x200000: [0x80, 0x80, 0x80, 0x01],
            0x0FFFFFFF: [0xFF, 0xFF, 0xFF, 0x7F],
            0x10000000: [0x80, 0x80, 0x80, 0x80, 0x01],
            0xFFFFFFFF: [0xFF, 0xFF, 0xFF, 0xFF, 0x0F],
        }
        for value, expected in table.items():
            self.assertEqual(encode_varint32(value), expected, hex(value))
            self.assertEqual(len(expected), varint_len(value), hex(value))

    def test_the_encoding_round_trips(self):
        rng = random.Random(115)
        for value in [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000,
                      0x0FFFFFFF, 0x10000000, 0xFFFFFFFF] + \
                     [rng.randrange(0, 1 << 32) for _ in range(2000)]:
            self.assertEqual(leb128_decode(encode_varint32(value)), value,
                             hex(value))

    def test_continuation_bits_are_set_on_every_byte_but_the_last(self):
        rng = random.Random(7)
        for _ in range(500):
            value = rng.randrange(0, 1 << 32)
            bs = encode_varint32(value)
            for b in bs[:-1]:
                self.assertTrue(b & 0x80, hex(value))
            self.assertFalse(bs[-1] & 0x80, hex(value))
            self.assertEqual(len(bs), varint_len(value))

    def test_the_32_bit_store_class_is_exactly_the_4_byte_class(self):
        self.assertEqual(STORE32_CLASS, 4)
        rng = random.Random(3)
        for _ in range(500):
            value = rng.randrange(0, 1 << 32)
            self.assertEqual(uses_single_32bit_store(value),
                             len(encode_varint32(value)) == 4, hex(value))

    def test_decoded_execution_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(encode_varint32(c["value"]),
                             encode_varint32_decoded(c["value"]),
                             hex(c["value"]))

    def test_random_differential(self):
        rng = random.Random(11)
        for _ in range(3000):
            value = rng.randrange(0, 1 << 32)
            self.assertEqual(encode_varint32(value),
                             encode_varint32_decoded(value), hex(value))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_five_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {"one": 480, "two": 480, "three": 480,
                                "four": 480, "five": 480})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            self.assertEqual(replay_case(r), r["bytes"], r)
            self.assertEqual(encode_varint32_decoded(r["value"]), r["bytes"], r)

    def test_committed_ledger_keeps_the_boundaries_verbatim(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
            self.assertEqual(r["nbytes"], len(r["bytes"]))
            self.assertEqual(r["store32"], (r["nbytes"] == 4))
        self.assertEqual(sorted(fams.values()), [60] * 5)
        values = {r["value"] for r in rows}
        for boundary in (0, 1, BOUND1, BOUND1 + 1, BOUND2, BOUND2 + 1, BOUND3,
                         BOUND3 + 1, BOUND4, BOUND4 + 1, M32):
            self.assertIn(boundary, values, hex(boundary))

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "value", "bytes", "nbytes",
                          "single_32bit_store"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, value, bs, nbytes, store = line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(fam, r["family"])
            self.assertEqual(value, hex(r["value"]))
            self.assertEqual(bs, "".join(f"{b:02x}" for b in r["bytes"]))
            self.assertEqual(int(nbytes), r["nbytes"])
            self.assertEqual(store, "1" if r["store32"] else "0")


class CallerCensus(unittest.TestCase):
    def test_the_call_sites_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 165)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_no_caller_discards_the_end_pointer(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 165)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"arithmetic": 139, "register-copy": 24,
                                  "store": 2})
        self.assertNotIn("overwritten", counts)
        self.assertNotIn("dead", counts)

    def test_the_contract_and_the_length_recovery_count_are_stated(self):
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertTrue(census["contract"].startswith("returns dst+n"))
        self.assertEqual(census["direct_calls"], 165)
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        sub = [u for u in uses if u[3].startswith("sub rax,")]
        self.assertEqual(
            census["arithmetic_sites_recovering_the_length"], len(sub))
        self.assertGreater(len(sub), 100)

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
                         "6cca28ae25285154-coding.o")
        self.assertEqual(rec["bound_context"]["crate"], "librocksdb-sys")
        self.assertEqual(rec["bound_context"]["candidate_versions"],
                         ["0.11.0+8.1.1"])


if __name__ == "__main__":
    unittest.main()
