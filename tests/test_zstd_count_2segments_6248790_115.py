"""Evidence-packet tests for node #115 zstd-sys ZSTD_count_2segments.

Every assertion is made against the digest-verified artifact or the packet's own
committed tables; the model is additionally checked against execution of the
routine's own decoded instruction bytes.
"""
import ctypes
import hashlib
import json
import random
import subprocess
import unittest
from pathlib import Path

import capstone

from tools.zstd_count_2segments_6248790_115 import (
    START,
    END,
    PAD,
    IP_BASE,
    MATCH_BASE,
    FAMILIES,
    BOUNDARY_CASES,
    instruction_stream,
    split_ops,
    mem_size,
    geometry,
    count_2segments,
    count_2segments_decoded,
    accesses,
    generate_cases,
    ledger_rows,
    replay_case,
)

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-count-2segments-6248790-115")
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


def case(family, n, tail, dist, p1, p2):
    from tools.zstd_count_2segments_6248790_115 import _case
    return _case({"family": family, "n": n, "tail": tail, "dist": dist,
                  "plant1": p1, "plant2": p2})


class Semantics(unittest.TestCase):
    def test_the_window_is_one_complete_leaf_routine(self):
        insns = instruction_stream()
        self.assertEqual(insns[0].addr, START)
        self.assertEqual(insns[-1].end(), END)
        self.assertEqual(len(insns), 150)
        self.assertEqual([i.addr for i in insns
                          if i.mnemonic.startswith("call")], [])
        self.assertEqual([i.addr for i in insns if i.mnemonic == "ret"],
                         [0x6248827, 0x6248876])

    def test_the_excerpt_is_the_binary_bytes(self):
        blob = b"".join(i.raw for i in instruction_stream())
        self.assertEqual(blob, window_bytes())
        self.assertEqual(len(blob), END - START)          # 522 bytes

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

    def test_there_is_no_cet_landing_pad_and_the_padding_below(self):
        insns = instruction_stream()
        self.assertFalse([i for i in insns if i.mnemonic == "endbr64"])
        self.assertEqual(insns[0].mnemonic, "mov")
        self.assertEqual(insns[0].op_str, "%rdx,%r9")
        data = BINARY.read_bytes()
        below = data[va_to_off(START) - 4:va_to_off(START)]
        self.assertEqual(below, b"\xcc\xcc\xcc\xcc")
        rec = json.loads((PACKET / "records.json").read_text())
        self.assertFalse(rec["bound_context"]["cet_landing_pad"])
        self.assertIn("int3", rec["bound_context"]["boundary_below"])

    def test_the_prologue_and_epilogue_pair_up(self):
        self.assertEqual(decoded(0x6248796).op_str, "rbp")
        self.assertEqual(decoded(0x624879D).op_str, "rbx")
        self.assertEqual(decoded(0x6248825).op_str, "rbx")
        self.assertEqual(decoded(0x6248874).op_str, "rbx")
        self.assertEqual(decoded(0x6248875).op_str, "rbp")
        pushes = [i for i in instruction_stream() if i.mnemonic == "push"]
        pops = [i for i in instruction_stream() if i.mnemonic == "pop"]
        # one prologue, but two return paths, each restoring both registers
        self.assertEqual(len(pushes), 2)
        self.assertEqual(len(pops), 4)
        self.assertEqual([i.addr for i in pops],
                         [0x6248825, 0x6248826, 0x6248874, 0x6248875])

    def test_claim_anchors_are_in_the_target(self):
        text = (PACKET / "semantics.tsv").read_text().splitlines()
        self.assertEqual(len(text) - 1, 40)
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
        for required in (0x6248790, 0x6248793, 0x6248797, 0x62487A4,
                         0x62487A8, 0x62487E1, 0x62487F3, 0x62487FB,
                         0x6248836, 0x624884A, 0x6248863, 0x6248886,
                         0x62488E8):
            self.assertIn(required, seen, hex(required))

    def test_the_bound_is_an_unsigned_minimum(self):
        cmov = decoded(0x62487A4)
        self.assertEqual(cmov.mnemonic, "cmovbe")          # unsigned "below"
        self.assertEqual(cmov.op_str, "rdx, r9")
        self.assertEqual(decoded(0x62487A1).op_str, "r9, rdx")
        lea = decoded(0x62487A8)
        self.assertEqual(lea.mnemonic, "lea")
        self.assertEqual(lea.op_str, "rbx, [rdx - 7]")

    def test_the_fast_loop_guards_use_the_narrowed_bounds(self):
        # the 8-byte loop, the dword tail and the word tail each test a bound
        self.assertEqual(decoded(0x62487AF).mnemonic, "jae")
        self.assertEqual(decoded(0x6248836).op_str, "rcx, [rdx - 3]")
        self.assertEqual(decoded(0x624884A).op_str, "rcx, [rdx - 1]")
        self.assertEqual(decoded(0x6248863).mnemonic, "jb")
        self.assertEqual(decoded(0x62487FB).op_str, "rsi, [r9 - 7]")

    def test_the_unaligned_whole_word_loads(self):
        self.assertEqual(decoded(0x62487B1).op_str, "rax, qword ptr [rsi]")
        self.assertEqual(decoded(0x62487B4).op_str, "rcx, qword ptr [rdi]")
        self.assertEqual(decoded(0x62487B1).operands[1].size, 8)

    def test_the_first_difference_uses_tzcnt_not_bsf(self):
        sites = {i.addr: i for i in instruction_stream()
                 if i.mnemonic == "tzcnt"}
        self.assertEqual(sorted(sites), [0x62487E1, 0x624881A, 0x624889B,
                                         0x624894F])
        self.assertFalse([i for i in instruction_stream()
                          if i.mnemonic == "bsf"])
        # each tzcnt acts on a word that a compare just found unequal
        for va, ins in sites.items():
            self.assertEqual(mem_size(ins), 0)            # register-only form
            self.assertEqual(len(split_ops(ins.op_str)), 2)
        self.assertEqual(decoded(0x62487E6).op_str, "eax, 3")

    def test_the_byte_tail_turns_equality_into_an_advance(self):
        self.assertEqual(decoded(0x6248880).op_str, "ebx, byte ptr [r11]")
        self.assertEqual(decoded(0x6248884).op_str, "byte ptr [rax], bl")
        self.assertEqual(decoded(0x6248884).operands[0].size, 1)
        self.assertEqual(decoded(0x6248886).mnemonic, "sete")
        self.assertEqual(decoded(0x6248886).op_str, "al")
        self.assertEqual(decoded(0x624888C).op_str, "r11, rax")

    def test_the_wrap_tests_and_the_shared_sum(self):
        self.assertEqual(decoded(0x62487F3).op_str, "r10, rdx")
        self.assertEqual(decoded(0x624886F).op_str, "r10, rdx")
        self.assertEqual(decoded(0x62487F6).mnemonic, "jne")
        self.assertEqual(decoded(0x6248872).mnemonic, "je")
        self.assertEqual(decoded(0x6248872).op_str, "0x62487f8")
        self.assertEqual(decoded(0x6248822).op_str, "rax, rdx")
        jumps = [i for i in instruction_stream() if i.mnemonic == "jmp"]
        self.assertIn(0x6248822, [int(i.op_str, 16) for i in jumps])


class Model(unittest.TestCase):
    def test_a_prefix_that_misses_the_match_end(self):
        for n, tail, dist, p1, want in ((8, 16, 16, 0, 0), (8, 16, 16, 1, 1),
                                        (16, 8, 16, 7, 7), (4, 4, 8, 3, 3),
                                        (64, 64, 80, 63, 63)):
            b = case("prefix", n, tail, dist, p1, 0)
            got = count_2segments(b["mem"], b["geometry"])
            self.assertEqual(got, (want, want, 0, False), (n, tail, dist, p1))
            self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]),
                             want, (n, tail, dist, p1))

    def test_a_wrap_adds_the_second_segment(self):
        for n, tail, dist, p1, p2, want in ((16, 4, 16, 4, 0, 4),
                                            (16, 4, 16, 4, 1, 5),
                                            (32, 8, 40, 8, 3, 11),
                                            (16, 1, 16, 1, 7, 8),
                                            (72, 64, 80, 64, 5, 69)):
            b = case("wrap", n, tail, dist, p1, p2)
            got = count_2segments(b["mem"], b["geometry"])
            self.assertEqual(got, (want, tail, want - tail, True), (n, tail))
            self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]),
                             want, (n, tail, dist))

    def test_an_empty_tail_wraps_immediately(self):
        for n, p2, want in ((8, 0, 0), (8, 1, 1), (16, 15, 15), (9, 9, 9),
                            (40, 40, 40)):
            b = case("empty_tail", n, 0, n + 8, 0, p2)
            self.assertEqual(count_2segments(b["mem"], b["geometry"]),
                             (want, 0, want, True), (n, p2))
            self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]),
                             want, (n, p2))

    def test_phase_one_can_be_stopped_by_the_input_end(self):
        # n <= tail: phase 1 stops at iEnd, so len1 = n and there is no wrap...
        b = case("iend_first", 4, 16, 16, 4, 0)
        self.assertEqual(count_2segments(b["mem"], b["geometry"]),
                         (4, 4, 0, False))
        self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]), 4)
        # ... unless n == tail, in which case phase 2 runs with nothing to add
        b = case("iend_first", 8, 8, 16, 8, 0)
        self.assertEqual(count_2segments(b["mem"], b["geometry"]),
                         (8, 8, 0, True))
        self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]), 8)

    def test_phase_two_can_run_into_the_input_end(self):
        for n, tail, p2, want in ((8, 4, 4, 8), (12, 4, 8, 12),
                                  (40, 8, 32, 40), (9, 1, 8, 9)):
            b = case("wrap_iend", n, tail, n + 8, tail, p2)
            self.assertEqual(count_2segments(b["mem"], b["geometry"]),
                             (want, tail, want - tail, True), (n, tail, p2))
            self.assertEqual(count_2segments_decoded(b["mem"], b["geometry"]),
                             want, (n, tail, p2))

    def test_the_return_is_the_input_side_length_only(self):
        """Moving mStart (the distance) must not change the answer: the routine
        returns input bytes, never a match-side distance."""
        answers = []
        for dist in (8, 16, 24, 64, 200):
            b = case("wrap", 40, 8, dist, 8, 5)
            answers.append(count_2segments(b["mem"], b["geometry"])[0])
        self.assertEqual(len(set(answers)), 1, answers)
        self.assertEqual(answers[0], 13)
        for dist in (8, 40, 120):
            b = case("prefix", 32, 32, dist, 11, 0)
            self.assertEqual(count_2segments(b["mem"], b["geometry"])[0], 11)
            self.assertEqual(count_2segments_decoded(b["mem"],
                                                     b["geometry"]), 11)

    def test_the_bound_uses_an_unsigned_comparison(self):
        """A geometry straddling bit 63: iEnd below it, ip + (mEnd-match) above.
        The unsigned cmovbe keeps vEnd = iEnd (answer 3); a signed comparison
        would take the wrapped value and count past the input end."""
        rng = random.Random(7)
        n, tail, dist = 3, 16, 16
        ip = 0x7FFFFFFFFFFFFFFC
        iend, match = ip + n, MATCH_BASE
        mend, mstart = match + tail, match - dist
        mem = {a: rng.randrange(256) for a in range(ip, ip + n + PAD)}
        mem.update({a: rng.randrange(256)
                    for a in range(match - dist, match + tail + PAD)})
        for j in range(n + 8):                       # agreement past iEnd too
            mem[ip + j] = mem[match + j]
        g = {"ip": ip, "iend": iend, "match": match, "mend": mend,
             "mstart": mstart}
        self.assertEqual(count_2segments(mem, g), (3, 3, 0, False))
        self.assertEqual(count_2segments_decoded(mem, g), 3)

        def s64(x):
            return ctypes.c_int64(x).value
        rdx = ip + (mend - match)
        signed_vEnd = iend if s64(iend) <= s64(rdx) else rdx
        self.assertNotEqual(signed_vEnd, min(iend, rdx))
        # what the signed model would have counted: everything planted
        len1 = 0
        while ip + len1 < signed_vEnd and mem[ip + len1] == mem[match + len1]:
            len1 += 1
        self.assertGreater(len1, 3)

    def test_the_decoded_run_agrees_over_the_sweep(self):
        for c in generate_cases():
            b = case(c["family"], c["n"], c["tail"], c["dist"], c["plant1"],
                     c["plant2"])
            model = count_2segments(b["mem"], b["geometry"])
            self.assertEqual(
                model[0], count_2segments_decoded(b["mem"], b["geometry"]), c)
            self.assertEqual(model[0], model[1] + model[2], c)
            if not model[3]:
                self.assertEqual(model[2], 0, c)

    def test_random_content_differential(self):
        rng = random.Random(115041)
        for _ in range(3000):
            n, tail = rng.randrange(1, 80), rng.randrange(0, 80)
            dist = rng.randrange(1, max(2, n + 8))
            mem = {a: rng.randrange(256)
                   for a in range(IP_BASE, IP_BASE + n + PAD)}
            mem.update({a: rng.randrange(256)
                        for a in range(MATCH_BASE - dist,
                                       MATCH_BASE + tail + PAD)})
            g = geometry(n, tail, dist)
            self.assertEqual(count_2segments(mem, g)[0],
                             count_2segments_decoded(mem, g), (n, tail, dist))

    def test_the_routine_writes_nothing(self):
        for fam, vals in BOUNDARY_CASES.items():
            for n, tail, dist, p1, p2 in vals:
                b = case(fam, n, tail, dist, p1, p2)
                loads, stores = accesses(b["mem"], b["geometry"])
                self.assertEqual(stores, [], (fam, vals))
                self.assertTrue(loads, (fam, vals))
                self.assertLessEqual({s for _, s in loads}, {1, 2, 4, 8})
                # reads stay inside the two modelled regions: the whole-word
                # loads are bounded by vEnd (input side) and by mEnd (tail side)
                g = b["geometry"]
                self.assertGreaterEqual(min(a for a, _ in loads),
                                        min(g["ip"], g["mstart"]), (fam, vals))
                self.assertLessEqual(max(a + s for a, s in loads),
                                     max(g["mend"], g["iend"]) + 8, (fam, vals))


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
            self.assertEqual([(r["n"], r["tail"], r["dist"], r["plant1"],
                               r["plant2"]) for r in head], bunch, fam)
        fams = {}
        for r in rows:
            fams[r["family"]] = fams.get(r["family"], 0) + 1
        self.assertEqual(fams, {f: 60 for f in FAMILIES})

    def test_committed_ledger_replays(self):
        for r in ledger_rows():
            self.assertEqual(r["expected"], replay_case(r), r)
            self.assertEqual(r["len1"] + r["len2"], r["expected"], r)
            self.assertEqual(r["wrapped"], 1 if r["len2"] or
                             r["len1"] == r["tail"] else 0, r)

    def test_cases_tsv_is_the_ledger(self):
        committed = (PACKET / "cases.tsv").read_text().splitlines()
        self.assertEqual(committed[0].split("\t"),
                         ["id", "family", "n", "tail_len", "mstart_dist",
                          "phase1_len", "phase2_len", "expected",
                          "reached_mend"])
        self.assertEqual(len(committed) - 1, 300)
        for line, r in zip(committed[1:], ledger_rows()):
            parts = line.split("\t")
            self.assertEqual(int(parts[0]), r["id"])
            self.assertEqual(parts[1], r["family"])
            self.assertEqual(int(parts[2]), r["n"])
            self.assertEqual(int(parts[3]), r["tail"])
            self.assertEqual(int(parts[4]), r["dist"])
            self.assertEqual(int(parts[5]), r["len1"])
            self.assertEqual(int(parts[6]), r["len2"])
            self.assertEqual(int(parts[7]), r["expected"])
            self.assertEqual(int(parts[8]), r["wrapped"])


class CallerCensus(unittest.TestCase):
    def test_the_call_sites_are_attributed_to_their_fdes(self):
        lines = (PACKET / "callers.tsv").read_text().splitlines()
        self.assertEqual(lines[0].split("\t"),
                         ["site", "kind", "caller_fde_start", "caller_fde_end"])
        rows = [l.split("\t") for l in lines[1:] if l.strip()]
        self.assertEqual(len(rows), 56)
        for site, kind, f0, f1 in rows:
            self.assertEqual(kind, "call")
            self.assertLess(int(f0, 16), int(site, 16))
            self.assertLessEqual(int(site, 16), int(f1, 16))
        self.assertEqual(len({(r[2], r[3]) for r in rows}), 12)

    def test_every_call_site_consumes_the_count(self):
        uses = [l.split("\t") for l in
                (PACKET / "caller_use.tsv").read_text().splitlines()[1:]
                if l.strip()]
        self.assertEqual(len(uses), 56)
        counts = {}
        for u in uses:
            counts[u[1]] = counts.get(u[1], 0) + 1
        self.assertEqual(counts, {"arithmetic": 37, "register-copy": 14,
                                  "overwritten": 5})
        rec = json.loads((PACKET / "records.json").read_text())
        census = rec["caller_census"]
        self.assertEqual(census["direct_calls"], 56)
        self.assertEqual(census["sites_reading_the_return"], 56)
        self.assertEqual(census["tail_jumps"], 0)
        self.assertEqual(census["consumers"], counts)
        self.assertTrue(census["contract"].startswith("value-returning"))

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
                         "7c9960efb53c0b35-zstd_lazy.o")
        self.assertEqual(rec["bound_context"]["crate"], "zstd-sys")
        self.assertEqual(rec["bound_context"]["symbol"], "ZSTD_count_2segments")
        self.assertEqual(rec["bound_context"]["candidate_versions"],
                         ["2.0.15+zstd.1.5.7", "2.1.2+zstd.1.5.7"])
        self.assertEqual(rec["bound_context"]["size_bytes"], 522)
        self.assertIn("not the zstd revision",
                      rec["bound_context"]["version_note"])


if __name__ == "__main__":
    unittest.main()
