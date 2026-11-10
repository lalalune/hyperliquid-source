"""Evidence-packet tests for node #115 libz zmemcpy.

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

from tools.zmemcpy_630c430_115 import (
    START,
    END,
    M64,
    SMALL_MAX,
    CHUNK,
    instruction_stream,
    zmemcpy_path,
    zmemcpy,
    zmemcpy_decoded,
    zmemcpy_counterfactual,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-libz-zmemcpy-630c430-115")
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


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[0].mnemonic, "endbr64")
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 90)

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 296 bytes

    def test_the_body_digest_matches_the_artifact(self):
        digest = hashlib.sha256(window_bytes()).hexdigest()
        recorded = (PACKET / "relocations.txt").read_text()
        self.assertIn(digest, recorded)
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertEqual(rec["bound_context"]["target_body_sha256"], digest)
        self.assertEqual(rec["bound_context"]["source_body_sha256"], digest)
        self.assertTrue(rec["bound_context"]["raw_equal"])
        self.assertEqual(rec["bound_context"]["relocations"], [])
        self.assertEqual(rec["bound_context"]["identical_source_count"], 1)

    def test_claim_anchors_are_in_the_target(self):
        # The `instruction` column is re-derived by decoding the recorded bytes
        # with capstone, so the table is checked against the binary rather than
        # against a transcription of itself.
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
        for required in (0x630C43B, 0x630C443, 0x630C453, 0x630C460,
                         0x630C465, 0x630C490, 0x630C496):
            self.assertIn(required, seen, hex(required))

    def test_the_guard_compares_against_source_plus_one(self):
        probe = decoded(0x630C445)                    # lea rsi, [rsi + 1]
        self.assertEqual(probe.mnemonic, "lea")
        self.assertEqual(probe.operands[1].mem.disp, 1)
        sub = decoded(0x630C44C)                      # sub rcx, rsi
        self.assertEqual((sub.mnemonic, sub.op_str), ("sub", "rcx, rsi"))
        cmp_c = decoded(0x630C44F)                    # cmp rcx, 0xe
        self.assertEqual(cmp_c.operands[1].imm, 14)
        ja = decoded(0x630C453)
        self.assertEqual(ja.mnemonic, "ja")
        self.assertEqual(ja.operands[0].imm, 0x630C478)

    def test_the_small_length_test_is_on_length_minus_one(self):
        lea = decoded(0x630C43D)
        self.assertEqual(lea.mnemonic, "lea")
        self.assertEqual(lea.operands[1].mem.disp, -1)
        self.assertEqual(decoded(0x630C440).operands[1].imm, 6)
        jbe = decoded(0x630C443)
        self.assertEqual(jbe.mnemonic, "jbe")
        self.assertEqual(jbe.operands[0].imm, 0x630C455)

    def test_one_byte_copy_then_one_byte_store(self):
        load = decoded(0x630C460)          # movzx ecx, byte ptr [r8 + rax]
        self.assertEqual(load.mnemonic, "movzx")
        self.assertEqual(load.operands[0].size, 4)     # into a 32-bit register
        self.assertEqual(load.operands[1].size, 1)     # from ONE byte
        store = decoded(0x630C465)         # mov byte ptr [rdi + rax], cl
        self.assertEqual(store.mnemonic, "mov")
        self.assertEqual(store.operands[0].size, 1)     # ONE byte out

    def test_the_chunk_path_loads_then_stores_sixteen_bytes(self):
        load = decoded(0x630C490)
        self.assertEqual(load.mnemonic, "movdqu")
        self.assertEqual(load.operands[0].size, 16)
        store = decoded(0x630C496)
        self.assertEqual(store.mnemonic, "movups")
        self.assertEqual(store.operands[0].size, 16)

    def test_both_loops_are_forward(self):
        self.assertEqual(decoded(0x630C468).op_str, "rax, 1")     # add $1,%rax
        self.assertEqual(decoded(0x630C49A).op_str, "rdx, 0x10")  # add $16,%rdx


class PathLaw(unittest.TestCase):
    def test_empty_length(self):
        self.assertEqual(zmemcpy_path(0, 0), "empty")
        self.assertEqual(zmemcpy_path(0, 99), "empty")

    def test_short_copies_use_the_byte_loop(self):
        for length in range(1, SMALL_MAX + 1):
            for distance in (0, 1, 7, 15, 16, 100, M64):
                self.assertEqual(zmemcpy_path(length, distance), "byte",
                                 (length, distance))

    def test_the_overlap_guard_boundary_is_inclusive(self):
        for distance in range(1, 16):                 # 1..15 -> byte loop
            self.assertEqual(zmemcpy_path(64, distance), "byte", distance)
        for distance in (16, 17, 31, 32, 128):        # no overlap -> chunks
            self.assertEqual(zmemcpy_path(64, distance), "vector", distance)

    def test_destination_below_source_wraps_and_takes_the_chunk_path(self):
        # sub is unsigned: dest < source yields a huge difference, so the guard
        # does NOT fire and the chunk path runs
        self.assertEqual(zmemcpy_path(64, M64), "vector")          # source-1
        self.assertEqual(zmemcpy_path(64, (-16) & M64), "vector")
        self.assertEqual(zmemcpy_path(64, 0), "vector")            # dest == source

    def test_the_long_distance_boundary_is_unchanged_by_length(self):
        for length in (8, 64, 1000):
            self.assertEqual(zmemcpy_path(length, 15), "byte", length)
            self.assertEqual(zmemcpy_path(length, 16), "vector", length)


class Model(unittest.TestCase):
    def test_empty_copy_writes_nothing(self):
        self.assertEqual(zmemcpy([1, 2, 3], 0, 0), [])
        self.assertEqual(zmemcpy_decoded(0, 0, src_bytes=[1, 2, 3]), [])

    def test_a_non_overlapping_copy_is_a_plain_copy(self):
        src = [11, 22, 33, 44]
        self.assertEqual(zmemcpy(src, 4, 64), src)
        self.assertEqual(zmemcpy_decoded(4, 64, src_bytes=src), src)
        self.assertEqual(zmemcpy(src, 3, 16), src[:3])

    def test_an_overlapping_copy_repeats_forward(self):
        self.assertEqual(zmemcpy([1, 2, 3, 4], 4, 1), [1, 1, 1, 1])
        self.assertEqual(zmemcpy([1, 2, 3, 4], 4, 2), [1, 2, 1, 2])
        self.assertEqual(zmemcpy_decoded(4, 1, src_bytes=[1, 2, 3, 4]),
                         [1, 1, 1, 1])
        self.assertEqual(zmemcpy_decoded(4, 2, src_bytes=[1, 2, 3, 4]),
                         [1, 2, 1, 2])

    def test_the_guard_changes_the_result_it_prevents(self):
        # A chunk copy of the same overlapping call does NOT repeat forward: the
        # first 16 bytes are snapshotted before they are stored, and the tail
        # then reads a byte the first chunk already overwrote.
        src = list(range(1, 19))
        byte_way = zmemcpy(src, 18, 1)
        chunk_way = zmemcpy_counterfactual(src, 18, 1)
        self.assertEqual(byte_way, [1] * 18)          # forward repeat
        self.assertNotEqual(byte_way, chunk_way)
        self.assertEqual(chunk_way[:16], src[:16])    # the snapshot is intact
        self.assertEqual(chunk_way[16:], [16, 18])    # the tail read a stored byte

    def test_decoded_execution_agrees_over_the_sweep(self):
        for c in generate_cases():
            self.assertEqual(
                zmemcpy(c["src"], c["length"], c["distance"]),
                zmemcpy_decoded(c["length"], c["distance"], src_bytes=c["src"]),
                c)

    def test_random_differential(self):
        rng = random.Random(115)
        for _ in range(600):
            length = rng.randrange(0, 96)
            distance = rng.choice([0, 1, 2, 7, 15, 16, 17, 31, 32, 200])
            src = [rng.randrange(256) for _ in range(length + 1)]
            self.assertEqual(zmemcpy(src, length, distance),
                             zmemcpy_decoded(length, distance, src_bytes=src),
                             (length, distance))


class Ledger(unittest.TestCase):
    def test_the_sweep_is_2400_cases_over_four_families(self):
        cases = generate_cases()
        self.assertEqual(len(cases), 2400)
        fams = {}
        for c in cases:
            fams[c["family"]] = fams.get(c["family"], 0) + 1
        self.assertEqual(fams, {"empty": 600, "small": 600,
                                "overlap": 600, "vector": 600})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            self.assertEqual(replay_case(r), r["expected"], r)
            self.assertEqual(zmemcpy_decoded(r["length"], r["distance"],
                                             src_bytes=r["src"]),
                             r["expected"], r)

    def test_committed_ledger_is_the_documented_subset(self):
        rows = ledger_rows()
        self.assertEqual(len(rows), 300)
        self.assertEqual([r["id"] for r in rows], list(range(1, 301)))
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(sorted(fams.values()), [75, 75, 75, 75])
        paths = {}
        for r in rows:
            paths[r["path"]] = paths.get(r["path"], 0) + 1
        self.assertEqual(paths, {"empty": 75, "byte": 150, "vector": 75})
        self.assertTrue(all(r["length"] <= 32 for r in rows),
                        "keep the committed rows reviewable")

    def test_the_ledger_shows_where_the_guard_matters(self):
        differ = [r for r in ledger_rows() if r["expected"] != r["counterfactual"]]
        self.assertGreater(len(differ), 50)
        self.assertTrue(all(r["path"] == "byte" for r in differ),
                        "only the byte path can differ from a chunk copy")

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "len", "distance", "path", "src",
                          "expected", "vector_only_differs"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            cid, fam, length, distance, path, src, expected, differs = \
                line.split("\t")
            self.assertEqual(int(cid), r["id"])
            self.assertEqual(fam, r["family"])
            self.assertEqual(int(length), r["length"])
            self.assertEqual(int(distance), r["distance"])
            self.assertEqual(path, r["path"])
            self.assertEqual(src, "".join(f"{b:02x}" for b in r["src"]))
            self.assertEqual(expected, "".join(f"{b:02x}" for b in r["expected"]))
            self.assertEqual(differs,
                             "1" if r["expected"] != r["counterfactual"] else "0")


class CallerCensus(unittest.TestCase):
    def test_forty_four_calls_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 44)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))

    def test_the_void_contract_is_stated_not_assumed(self):
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertEqual(census["direct_calls"], 44)
        self.assertTrue(census["contract"].startswith("memory effect only"))
        self.assertIn("void", census["contract"])
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 44)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"overwritten": 42, "dead": 2})
        self.assertEqual(rec["caller_census"]["consumers"], counts)

    def test_every_anchor_claim_is_either_an_observation_or_an_inference(self):
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
                         "f0389296f42960e9-zutil.o")
        self.assertEqual(rec["bound_context"]["crate"], "libz-sys")
        # the census warns that this window does not pin the zlib release
        self.assertIn("is not pinned", rec["bound_context"]["version_note"])
        self.assertIn("ZLIB_VERSION", rec["bound_context"]["version_note"])


if __name__ == "__main__":
    unittest.main()
