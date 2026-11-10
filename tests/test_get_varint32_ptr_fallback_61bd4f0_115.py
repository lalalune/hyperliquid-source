"""Evidence-packet tests for node #115 rocksdb GetVarint32PtrFallback.

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

from tools.get_varint32_ptr_fallback_61bd4f0_115 import (
    START,
    END,
    CONT,
    SHIFT_STEP,
    MAX_SHIFT,
    MAX_BYTES,
    FAMILIES,
    BOUNDARY_CASES,
    instruction_stream,
    split_ops,
    get_varint32,
    get_varint32_decoded,
    decoded_writes,
    accepts_a_fifth_continuation_byte,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-varint32-ptr-fallback-61bd4f0-115")
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
    text, which prints branch targets without a `0x` prefix and mixes the
    mnemonic spellings (`movzx`/`movzbl`).
    """
    data = BINARY.read_bytes()
    off = va_to_off(va)
    return next(iter(MD.disasm(data[off:off + 15], va)))


def leb128_encode(value):
    """An independent encoder, used to round-trip the decoder."""
    out = []
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 27)

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 75 bytes

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
        self.assertEqual(len(text) - 1, 24)
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
        for required in (0x61BD4FA, 0x61BD508, 0x61BD516, 0x61BD51B,
                         0x61BD527, 0x61BD52E, 0x61BD538):
            self.assertIn(required, seen, hex(required))

    def test_the_bound_is_checked_before_the_first_byte(self):
        cmp_ = decoded(0x61BD4F7)
        self.assertEqual(cmp_.mnemonic, "cmp")
        self.assertEqual(cmp_.op_str, "rdi, rsi")      # cmp %rsi,%rdi
        jump = decoded(0x61BD4FA)
        self.assertEqual(jump.mnemonic, "jae")         # unsigned: p >= limit
        self.assertEqual(jump.operands[0].imm, 0x61BD538)

    def test_the_continuation_test_is_the_byte_sign_bit(self):
        test_ = decoded(0x61BD524)
        self.assertEqual(test_.mnemonic, "test")
        self.assertEqual(test_.operands[0].size, 1)    # test %dil,%dil
        self.assertEqual(test_.operands[1].size, 1)
        jump = decoded(0x61BD527)
        self.assertEqual(jump.mnemonic, "js")          # SF = bit 7 of the byte
        self.assertEqual(jump.operands[0].imm, 0x61BD508)

    def test_the_pointer_advances_before_the_continuation_test(self):
        add = decoded(0x61BD520)
        self.assertEqual(add.mnemonic, "add")
        self.assertEqual(add.op_str.replace(" ", ""), "rax,1")

    def test_the_shift_guard_rejects_a_fifth_continuation_byte(self):
        self.assertEqual(decoded(0x61BD50D).op_str.replace(" ", ""), "ecx,7")
        cmp_ = decoded(0x61BD513)
        self.assertEqual(cmp_.operands[1].imm, MAX_SHIFT)      # 28
        jump = decoded(0x61BD516)
        self.assertEqual(jump.mnemonic, "ja")
        self.assertEqual(jump.operands[0].imm, 0x61BD538)

    def test_the_truncation_guard_is_after_every_continuation_byte(self):
        cmp_ = decoded(0x61BD518)
        self.assertEqual(cmp_.op_str, "rax, rsi")
        jump = decoded(0x61BD51B)
        self.assertEqual(jump.mnemonic, "jae")
        self.assertEqual(jump.operands[0].imm, 0x61BD538)

    def test_the_only_memory_write_is_one_32_bit_store(self):
        stores = [i for i in instruction_stream()
                  if "(" in i.op_str and not i.op_str.strip().startswith("(")
                  and i.mnemonic != "lea"
                  and split_ops(i.op_str)[-1].endswith(")")
                  and split_ops(i.op_str)[0] not in ("%rax",)]
        writes = [i for i in stores if i.mnemonic == "mov"
                  and i.op_str == "%edi,(%rdx)"]
        self.assertEqual([i.addr for i in writes], [0x61BD52E])
        self.assertEqual(decoded(0x61BD52E).operands[0].size, 4)   # dword

    def test_the_accumulator_and_the_final_shift_are_32_bit(self):
        self.assertEqual(decoded(0x61BD4FE).op_str, "r8d, r8d")
        self.assertEqual(decoded(0x61BD510).operands[0].size, 4)   # or r8d,edi
        self.assertEqual(decoded(0x61BD529).op_str.replace(" ", ""),
                         "edi,cl")

    def test_the_byte_load_and_the_two_returns(self):
        load = decoded(0x61BD51D)
        self.assertEqual(load.mnemonic, "movzx")
        self.assertEqual(load.operands[1].size, 1)                  # byte ptr
        rets = [i.addr for i in instruction_stream() if i.mnemonic == "ret"]
        self.assertEqual(rets, [0x61BD530, 0x61BD53A])
        self.assertEqual(decoded(0x61BD538).op_str, "eax, eax")     # nullptr


class Model(unittest.TestCase):
    def test_the_success_contract_at_every_family_boundary(self):
        table = {
            (bytes([0x00]), 1): (0, 1),
            (bytes([0x7F]), 1): (0x7F, 1),
            (bytes([0x80, 0x01]), 2): (0x80, 2),
            (bytes([0xFF, 0x7F]), 2): (0x3FFF, 2),
            (bytes([0x80, 0x80, 0x01]), 3): (0x4000, 3),
            (bytes([0xFF, 0xFF, 0x7F]), 3): (0x1FFFFF, 3),
            (bytes([0x80] * 3 + [0x01]), 4): (0x200000, 4),
            (bytes([0xFF] * 3 + [0x7F]), 4): (0x0FFFFFFF, 4),
            (bytes([0x80] * 4 + [0x01]), 5): (0x10000000, 5),
            (bytes([0xFF] * 4 + [0x0F]), 5): (0xFFFFFFFF, 5),
        }
        for (buf, limit), expected in table.items():
            self.assertEqual(get_varint32(buf, limit), expected, buf.hex())
            self.assertEqual(get_varint32_decoded(buf, limit), expected,
                             buf.hex())

    def test_the_three_nullptr_causes(self):
        # p >= limit, before any byte is read
        self.assertIsNone(get_varint32(b"", 0))
        self.assertIsNone(get_varint32(bytes([0x01]), 0))
        self.assertIsNone(get_varint32_decoded(bytes([0x01]), 0))
        # the varint runs off the limit
        self.assertIsNone(get_varint32(bytes([0x80]), 1))
        self.assertIsNone(get_varint32(bytes([0x80, 0x80]), 2))
        self.assertIsNone(get_varint32_decoded(bytes([0x80, 0x80]), 2))
        # a fifth continuation byte
        self.assertIsNone(get_varint32(bytes([0x80] * 5), 5))
        self.assertIsNone(get_varint32_decoded(bytes([0x80] * 5), 5))
        self.assertFalse(accepts_a_fifth_continuation_byte())

    def test_four_continuation_bytes_are_accepted_a_fifth_is_not(self):
        four = bytes([0x80] * 4 + [0x01])
        self.assertEqual(get_varint32(four, 5), (0x10000000, 5))
        self.assertIsNone(get_varint32(bytes([0x80] * 5 + [0x01]), 6))
        self.assertEqual(MAX_BYTES, 5)
        self.assertEqual(SHIFT_STEP * (MAX_BYTES - 1), MAX_SHIFT)

    def test_the_value_is_masked_to_32_bits(self):
        # the encoder never emits these top bytes; the decoder accepts them
        self.assertEqual(get_varint32(bytes([0x80] * 4 + [0x20]), 5), (0, 5))
        self.assertEqual(get_varint32(bytes([0x80] * 4 + [0x7F]), 5),
                         (0xF0000000, 5))
        self.assertEqual(get_varint32_decoded(bytes([0x80] * 4 + [0x7F]), 5),
                         (0xF0000000, 5))

    def test_only_the_bytes_up_to_the_limit_are_ever_read(self):
        buf = bytes([0x01, 0xAA, 0xBB])
        self.assertEqual(get_varint32(buf, 1), (1, 1))    # the tail is not read
        self.assertIsNone(get_varint32(bytes([0xAA]), 1))

    def test_the_store_is_one_32_bit_word_or_nothing(self):
        self.assertEqual(decoded_writes(bytes([0x80, 0x01]), 2), {2, 3, 4, 5})
        self.assertEqual(decoded_writes(bytes([0x7F]), 1), {1, 2, 3, 4})
        self.assertEqual(decoded_writes(bytes([0x80]), 1), set())
        self.assertEqual(decoded_writes(b"", 0), set())

    def test_the_decoded_run_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(get_varint32(c["bytes"], c["limit"]),
                             get_varint32_decoded(c["bytes"], c["limit"]), c)

    def test_random_differential(self):
        rng = random.Random(115)
        for _ in range(3000):
            n = rng.randrange(0, 9)
            buf = bytes(rng.randrange(0, 0x100) for _ in range(n))
            limit = rng.randrange(0, n + 1)
            self.assertEqual(get_varint32(buf, limit),
                             get_varint32_decoded(buf, limit),
                             (buf.hex(), limit))

    def test_it_round_trips_the_encoder_for_every_family(self):
        rng = random.Random(7)
        values = [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000,
                  0x0FFFFFFF, 0x10000000, 0xFFFFFFFF]
        values += [rng.randrange(0, 1 << 32) for _ in range(1000)]
        for v in values:
            buf = leb128_encode(v)
            self.assertEqual(get_varint32(buf, len(buf)), (v, len(buf)), hex(v))
            self.assertEqual(get_varint32_decoded(buf, len(buf)),
                             (v, len(buf)), hex(v))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_six_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {f: 400 for f in FAMILIES})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            ans = replay_case(r)
            if ans is None:
                self.assertEqual(r["result"], "null", r)
                self.assertIsNone(r["value"])
                self.assertIsNone(r["next"])
            else:
                self.assertEqual(r["result"], "ok", r)
                self.assertEqual((r["value"], r["next"]), ans, r)

    def test_the_ledger_keeps_the_boundary_rows_verbatim(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        for fam, bunch in BOUNDARY_CASES.items():
            head = [r for r in rows if r["family"] == fam][:len(bunch)]
            self.assertEqual([(r["bytes"], r["limit"]) for r in head],
                             [(list(bs), lim) for bs, lim in bunch], fam)
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(fams, {f: 50 for f in FAMILIES})
        self.assertEqual(sum(1 for r in rows if r["result"] == "null"), 50)

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "bytes", "limit", "result",
                          "value", "next"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, bs, lim, result, value, nxt = line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(fam, r["family"])
            self.assertEqual(bs, "".join(f"{b:02x}" for b in r["bytes"]))
            self.assertEqual(int(lim), r["limit"])
            self.assertEqual(result, r["result"])
            self.assertEqual(value,
                             "-" if r["value"] is None else hex(r["value"]))
            self.assertEqual(nxt,
                             "-" if r["next"] is None else str(r["next"]))


class CallerCensus(unittest.TestCase):
    def test_the_call_sites_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 149)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_the_consumer_table_and_the_null_check_count(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 149)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"arithmetic": 3, "compare": 27, "dead": 4,
                                  "overwritten": 1, "register-copy": 95,
                                  "store": 19})
        nulls = [u for u in uses if u[3].strip() == "test rax, rax"]
        self.assertEqual(len(nulls), 27)
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertEqual(census["null_checks"], len(nulls))
        self.assertEqual(census["direct_calls"], 149)
        self.assertEqual(census["discarded_sites"],
                         sum(1 for u in uses if u[1] in ("dead", "overwritten")))
        self.assertTrue(census["contract"].startswith("returns p+n"))

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
        self.assertEqual(rec["bound_context"]["symbol"],
                         "_ZN7rocksdb22GetVarint32PtrFallbackEPKcS1_Pj")


if __name__ == "__main__":
    unittest.main()
