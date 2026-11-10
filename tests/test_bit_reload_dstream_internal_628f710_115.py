"""Evidence-packet tests for node #115 zstd BIT_reloadDStream_internal.

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

from tools.bit_reload_dstream_internal_628f710_115 import (
    START,
    END,
    BIT_SHIFT,
    BIT_MASK,
    CONTAINER_BYTES,
    STATUS_UNFINISHED,
    STRUCT_CONTAINER,
    STRUCT_BITS,
    STRUCT_PTR,
    PTR_BASE,
    FAMILIES,
    BOUNDARY_CASES,
    instruction_stream,
    split_ops,
    reload,
    reload_decoded,
    access_addresses,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-bit-reload-dstream-internal-628f710-115")
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
    mnemonic spellings.
    """
    data = BINARY.read_bytes()
    off = va_to_off(va)
    return next(iter(MD.disasm(data[off:off + 15], va)))


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_leaf_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "mov")      # no endbr64
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 12)
        self.assertEqual([i.addr for i in insns if i.mnemonic == "call"], [])
        self.assertEqual([i.addr for i in insns if i.mnemonic == "ret"],
                         [0x628F731])

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 34 bytes

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
        self.assertEqual(len(text) - 1, 12)
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
        for required in (0x628F710, 0x628F719, 0x628F71C, 0x628F722,
                         0x628F729, 0x628F72C, 0x628F72F):
            self.assertIn(required, seen, hex(required))

    def test_the_body_has_no_comparison_and_no_branch(self):
        for ins in instruction_stream():
            self.assertNotIn(ins.mnemonic, ("cmp", "test"), ins)
            self.assertFalse(ins.mnemonic.startswith("j"), ins)

    def test_the_split_masks_and_shifts(self):
        load = decoded(0x628F710)
        self.assertEqual(load.mnemonic, "mov")
        self.assertEqual(load.operands[0].size, 4)            # edx
        self.assertEqual(decoded(0x628F717).op_str, "ecx, edx")  # zero-extends
        self.assertEqual(decoded(0x628F719).op_str.replace(" ", ""), "edx,7")
        self.assertEqual(decoded(0x628F71C).op_str.replace(" ", ""), "ecx,3")

    def test_the_remainder_is_written_back(self):
        store = decoded(0x628F71F)
        self.assertEqual(store.mnemonic, "mov")
        self.assertEqual(store.operands[0].size, 4)           # dword [rdi+8]
        self.assertEqual(decoded(0x628F725).operands[0].size, 8)   # qword [rdi+10]

    def test_the_pointer_moves_backward(self):
        sub = decoded(0x628F722)
        self.assertEqual(sub.mnemonic, "sub")
        self.assertEqual(sub.op_str, "rax, rcx")              # rax -= rcx

    def test_the_reload_is_one_8_byte_load_that_replaces(self):
        load = decoded(0x628F729)
        self.assertEqual(load.mnemonic, "mov")
        self.assertEqual(load.op_str, "rax, qword ptr [rax]")
        store = decoded(0x628F72C)
        self.assertEqual(store.op_str, "qword ptr [rdi], rax")   # whole container
        self.assertEqual(CONTAINER_BYTES, 8)

    def test_the_constant_return(self):
        self.assertEqual(decoded(0x628F72F).op_str, "eax, eax")   # xor
        self.assertEqual(STATUS_UNFINISHED, 0)
        self.assertEqual((STRUCT_CONTAINER, STRUCT_BITS, STRUCT_PTR),
                         (0x00, 0x08, 0x10))


class Model(unittest.TestCase):
    def test_the_split_identity_at_every_boundary(self):
        for bits in (0, 1, 7, 8, 9, 0xF, 0x10, 0x3F, 0x40, 0xFFFFFFFF,
                     0x80000000, 0x01000000):
            container, bits_after, ptr, status = reload(bits, 0xABCDEF, PTR_BASE)
            self.assertEqual(bits_after, bits & BIT_MASK, hex(bits))
            self.assertEqual(ptr, PTR_BASE - (bits >> BIT_SHIFT), hex(bits))
            self.assertEqual(container, 0xABCDEF)
            self.assertEqual(status, 0)

    def test_the_rewind_is_unsigned_and_backward(self):
        # a sign-extending copy or an arithmetic shift would differ here
        self.assertEqual(reload(0x80000000, 0, PTR_BASE)[2],
                         PTR_BASE - 0x10000000)
        self.assertEqual(reload(0xFFFFFFFF, 0, PTR_BASE)[2],
                         PTR_BASE - 0x1FFFFFFF)
        self.assertEqual(reload(0xFFFFFFFF, 0, PTR_BASE)[1], 7)
        for bits in (8, 9, 0x100, 0xFFFF):
            self.assertLess(reload(bits, 0, PTR_BASE)[2], PTR_BASE)

    def test_the_container_is_replaced_not_merged(self):
        # the previous container is irrelevant: only the loaded word survives
        self.assertEqual(reload(9, 0x0, PTR_BASE)[0], 0)
        self.assertEqual(reload(9, 0xFFFFFFFFFFFFFFFF, PTR_BASE)[0],
                         0xFFFFFFFFFFFFFFFF)

    def test_the_access_set_is_one_load_and_three_stores(self):
        loads, stores = access_addresses(9, 0x1122334455667788)
        rewound = PTR_BASE - 1
        # one 4-byte load of the bits field, one 8-byte load of the pointer
        # field, and one 8-byte load of the container AT the rewound pointer
        self.assertEqual(sorted(loads), sorted(
            [(0x1000 + STRUCT_BITS, 4), (0x1000 + STRUCT_PTR, 8),
             (rewound, 8)]))
        self.assertEqual([(a, s) for a, s in loads if a == rewound],
                         [(rewound, 8)])
        self.assertEqual(sorted(s for _, s in stores), [4, 8, 8])
        self.assertEqual({a for a, _ in stores},
                         {0x1000 + STRUCT_CONTAINER, 0x1000 + STRUCT_BITS,
                          0x1000 + STRUCT_PTR})

    def test_the_decoded_run_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(reload(c["bits"], c["word"], PTR_BASE),
                             reload_decoded(c["bits"], c["word"], PTR_BASE), c)

    def test_random_differential(self):
        rng = random.Random(115)
        for _ in range(3000):
            bits = rng.randrange(0, 1 << 32)
            word = rng.getrandbits(64)
            self.assertEqual(reload(bits, word, PTR_BASE),
                             reload_decoded(bits, word, PTR_BASE),
                             (hex(bits), hex(word)))

    def test_the_result_is_always_a_valid_window(self):
        # bits_after is always a sub-byte count, whatever the input
        rng = random.Random(5)
        for _ in range(500):
            bits = rng.randrange(0, 1 << 32)
            self.assertIn(reload(bits, 0, PTR_BASE)[1], range(8))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_four_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {f: 600 for f in FAMILIES})

    def test_the_ledger_keeps_the_boundary_rows_verbatim(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        for fam, bunch in BOUNDARY_CASES.items():
            head = [r for r in rows if r["family"] == fam][:len(bunch)]
            self.assertEqual([r["bits"] for r in head], bunch, fam)
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(fams, {f: 75 for f in FAMILIES})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            ans = replay_case(r)
            self.assertEqual((r["container"], r["bits_after"], r["new_ptr"],
                              r["status"]), ans, r)
            self.assertEqual(r["bytes_consumed"], r["bits"] >> BIT_SHIFT, r)
            self.assertEqual(r["bits_after"], r["bits"] & BIT_MASK, r)
            self.assertEqual(r["status"], STATUS_UNFINISHED, r)

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "bits_consumed", "bytes_consumed",
                          "bits_after", "new_ptr", "container", "status"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, bits, nbytes, after, ptr, cont, status = line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(fam, r["family"])
            self.assertEqual(bits, hex(r["bits"]))
            self.assertEqual(int(nbytes), r["bytes_consumed"])
            self.assertEqual(int(after), r["bits_after"])
            self.assertEqual(ptr, hex(r["new_ptr"]))
            self.assertEqual(cont, hex(r["container"]))
            self.assertEqual(int(status), r["status"])


class CallerCensus(unittest.TestCase):
    def test_the_call_sites_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 16)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_every_call_site_discards_the_return(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 16)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"dead": 6, "overwritten": 10})
        self.assertLessEqual(set(counts), {"dead", "overwritten"})
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertEqual(census["direct_calls"], 16)
        self.assertEqual(census["sites_reading_the_return"], 0)
        self.assertEqual(census["discarded_sites"], 16)
        self.assertTrue(census["contract"].startswith("returns the constant 0"))

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
                         "865a32d3ef5dbaad-huf_decompress.o")
        self.assertEqual(rec["bound_context"]["crate"], "zstd-sys")
        self.assertEqual(rec["bound_context"]["symbol"],
                         "BIT_reloadDStream_internal")
        self.assertEqual(rec["bound_context"]["candidate_versions"],
                         ["2.0.15+zstd.1.5.7", "2.1.2+zstd.1.5.7"])


if __name__ == "__main__":
    unittest.main()
