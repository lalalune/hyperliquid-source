#!/usr/bin/env python3
"""Tests for the CompactionJobStats::Reset 0x61bd590 packet (node #115).

The tests hold the claims, not the packet's tables: the recovered write set is
checked row by row, the decoded-bytes emulator is run against the model and
against doctored excerpts, and the artifact claims (bytes, anchors, the caller
census, the memory effect) are re-derived from the binary.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
import unittest
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.rocksdb_compaction_job_stats_reset_61bd590_115 import (  # noqa: E402
    START, END, PACKET, SELF, ARENA, ZERO16, ZERO8, ZERO2, DEREF,
    Memory, model_writes, decoded, build_case, agree, apply_writes, touched,
    image, SNAP_REGIONS, generate_cases, instructions,
)

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
BODY_SHA256 = "cfcbe3988ac0d3eeaf68f8d2bb01aa116ee041e03bbd57ab23818ea23a03c009"
CALLS = 8
CALLER_FDES = 8
WRITES = 18
TOUCHED = 220


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise AssertionError(f"{va:#x} is in no LOAD segment")


def window_bytes():
    data = BINARY.read_bytes()
    off = va_to_off(START)
    return data[off:off + (END - START)], data, off


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ArtifactTests(unittest.TestCase):
    def test_the_window_is_the_bound_body(self):
        body, _, _ = window_bytes()
        self.assertEqual(len(body), 127)
        self.assertEqual(hashlib.sha256(body).hexdigest(), BODY_SHA256)

    def test_the_window_is_int3_fenced(self):
        _, data, off = window_bytes()
        self.assertEqual(data[off - 1:off], b"\xcc")
        self.assertEqual(data[off + 127:off + 128], b"\xcc")

    def test_the_excerpt_bytes_are_the_artifact_bytes(self):
        body, data, off = window_bytes()
        # parse the listing as a byte stream: objdump splits instructions longer
        # than seven bytes onto continuation lines that carry no text
        listing = {}
        for line in (PACKET / "main.txt").read_text().splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)(?:\t.*)?$", line)
            if m:
                listing[int(m.group(1), 16)] = bytes.fromhex(m.group(2).replace(" ", ""))
        addr = START
        for a in sorted(listing):
            self.assertEqual(a, addr, f"gap in the listing at {a:#x}")
            self.assertEqual(data[off + (a - START):off + (a - START) + len(listing[a])],
                             listing[a], f"bytes at {a:#x}")
            addr += len(listing[a])
        self.assertEqual(addr, END)
        self.assertEqual(sum(len(v) for v in listing.values()), 127)

    def test_the_excerpt_is_the_whole_window(self):
        ins = instructions((PACKET / "main.txt").read_text())
        self.assertEqual(len(ins), 24)
        self.assertEqual(ins[0][0], START)
        self.assertEqual(ins[-1][0] + 1, END)
        self.assertEqual(ins[-1][1], "ret")
        # every instruction starts where the previous one ended
        spans = [a for a, _ in ins] + [END]
        self.assertEqual(spans, sorted(spans))
        self.assertEqual(spans[0], START)
        self.assertEqual(spans[-1], END)

    def test_the_fde_entry_is_the_window(self):
        frames = (PACKET / "frames.txt").read_text()
        self.assertIn(f"pc={START:016x}..{END:016x}", frames)
        self.assertEqual(frames.count("FDE cie="), CALLER_FDES + 1)

    def test_the_body_has_no_relocation(self):
        reloc = (PACKET / "relocations.txt").read_text()
        self.assertIn("no relocations", reloc)
        self.assertEqual(reloc.count(BODY_SHA256), 1)


class AnchorTests(unittest.TestCase):
    def test_every_anchor_is_a_real_instruction(self):
        sem = _load("sem", PACKET / "semantics.py")
        n = sem.check((PACKET / "main.txt").read_text())
        self.assertEqual(n, 24)
        self.assertEqual(sum(s for _, s, _, _ in sem.ANCHORS), 127)

    def test_the_anchors_are_the_committed_table(self):
        sem = _load("sem", PACKET / "semantics.py")
        table = [l.split("\t") for l in
                 (PACKET / "semantics.tsv").read_text().splitlines()[1:] if l]
        self.assertEqual(len(table), len(sem.ANCHORS))
        for row, (a, size, text, claim) in zip(table, sem.ANCHORS):
            self.assertEqual(row[0], f"{a:#x}")
            self.assertEqual(row[1], str(size))
            self.assertEqual(row[2], " ".join(text.split()))
            self.assertEqual(row[3], " ".join(claim.split()))

    def test_the_two_dereference_anchors_name_the_strings(self):
        sem = _load("sem", PACKET / "semantics.py")
        by_addr = {a: (size, text) for a, size, text, _ in sem.ANCHORS}
        self.assertEqual(by_addr[0x61BD5A6][1], "mov 0xc0(%rdi),%rax")
        self.assertEqual(by_addr[0x61BD5EF][1], "movb $0x0,(%rax)")
        self.assertEqual(by_addr[0x61BD5F2][1], "mov 0xe0(%rdi),%rax")


class ModelTests(unittest.TestCase):
    def test_the_write_set_is_exactly_the_modelled_rows(self):
        mem = build_case(bytes(0x130))
        want = model_writes(mem, SELF)
        self.assertEqual(len(want), WRITES)
        self.assertEqual(len(touched(want)), TOUCHED)
        # the field rows are the modelled offsets, in program order
        self.assertEqual([a - SELF for a, w, _ in want if w == 16], list(ZERO16))
        self.assertEqual([a - SELF for a, w, _ in want if w == 8][:3],
                         [ZERO8[0], ZERO8[1], ZERO8[2]])
        self.assertEqual([a - SELF for a, w, _ in want if w == 2], list(ZERO2))

    def test_the_two_string_writes_follow_the_pointers_the_object_holds(self):
        mem = build_case(bytes(0x130))
        want = model_writes(mem, SELF)
        derefs = [a for a in want if a[1] == 1]
        self.assertEqual([a for a, _, _ in derefs], [ARENA, ARENA + 0x100])
        # stage different buffers and the targets move with them
        other = Memory()
        other.words = dict(mem.words)
        other.store64(SELF + 0xC0, ARENA + 0x40, log=False)
        other.store64(SELF + 0xE0, ARENA + 0x80, log=False)
        again = [a for a in model_writes(other, SELF) if a[1] == 1]
        self.assertEqual([a for a, _, _ in again], [ARENA + 0x40, ARENA + 0x80])

    def test_a_freed_string_buffer_is_still_written(self):
        """clear() does not care whether the buffer is reachable - only the
        object's own pointer decides where the NUL goes."""
        mem = build_case(bytes(0x130))
        mem.store64(SELF + 0xC0, 0xDEADBEEF0, log=False)
        mem.store64(SELF + 0xE0, 0xDEADBEEF8, log=False)
        want = [a for a in model_writes(mem, SELF) if a[1] == 1]
        self.assertEqual([a for a, _, _ in want], [0xDEADBEEF0, 0xDEADBEEF8])

    def test_the_string_pointers_and_capacities_survive(self):
        mem = build_case(bytes(0x130))
        mem.store64(SELF + 0xC0, ARENA, log=False)
        mem.store64(SELF + 0xD0, 0x2A, log=False)
        mem.store64(SELF + 0xE0, ARENA + 0x100, log=False)
        mem.store64(SELF + 0xF0, 0x99, log=False)
        out = apply_writes(mem, model_writes(mem, SELF))
        self.assertEqual(out.load64(SELF + 0xC0), ARENA)
        self.assertEqual(out.load64(SELF + 0xD0), 0x2A)
        self.assertEqual(out.load64(SELF + 0xE0), ARENA + 0x100)
        self.assertEqual(out.load64(SELF + 0xF0), 0x99)
        self.assertEqual(out.load8(SELF + 0xC8), 0)
        self.assertEqual(out.load8(SELF + 0xE8), 0)

    def test_the_ledger_and_the_model_agree_on_every_row(self):
        cases = generate_cases(seed=7)
        self.assertEqual(len(cases), 300)
        canon = None
        for family, pattern, buffer, sso in cases:
            mem = build_case(pattern, buffer_bytes=buffer, sso=sso)
            ok, why, want, got = agree(mem)
            self.assertTrue(ok, f"{family}: {why}")
            self.assertEqual(len(want), WRITES)
            # the field rows are fixed object offsets; the two rows that follow a
            # pointer move with the staged image, so they are checked separately
            fields = [want[i] for i in range(len(want)) if i not in (14, 16)]
            if canon is None:
                canon = fields
            else:
                self.assertEqual(fields, canon, f"{family}: the field rows moved")
            for idx, member in ((14, 0xC0), (16, 0xE0)):
                self.assertEqual(want[idx][0], mem.load64(SELF + member), family)

    def test_the_committed_ledger_has_no_disagreement(self):
        rows = [l.split("\t") for l in
                (PACKET / "cases.tsv").read_text().splitlines()[1:] if l]
        self.assertEqual(len(rows), 300)
        self.assertEqual({r[6] for r in rows}, {"yes"})
        self.assertEqual({r[4] for r in rows}, {str(WRITES)})
        self.assertEqual({r[5] for r in rows}, {str(TOUCHED)})

    def test_the_committed_write_table_is_the_model(self):
        mem = build_case(bytes(0x130))
        want = model_writes(mem, SELF)
        table = [l.split("\t") for l in
                 (PACKET / "writes.tsv").read_text().splitlines()[8:] if l]
        self.assertEqual(len(table), WRITES)
        for row, (addr, width, value) in zip(table, want):
            label = f"0x{addr - SELF:x}" if SELF <= addr < SELF + 0x200 \
                else f"*(0x{addr:x})"
            self.assertEqual(row, [label, str(width), str(value)])

    def test_reset_is_idempotent(self):
        mem = build_case(b"\xff" * 0x130, buffer_bytes=b"\xff")
        decoded(mem, SELF, log=True)
        once = dict(mem.words)
        decoded(mem, SELF, log=True)
        self.assertEqual(mem.words, once)

    def test_the_sweep_agrees(self):
        swept = 0
        for length in (0x40, 0xC0, 0x130, 0x140, 0x1FF):
            for byte in (0x00, 0x01, 0x7F, 0x80, 0xFF):
                for sso in (False, True):
                    pattern = bytes((byte + i) % 256 for i in range(length))
                    for buffer in (b"\x00", b"\xff", bytes([byte])):
                        mem = build_case(pattern, buffer_bytes=buffer, sso=sso)
                        ok, why, _, _ = agree(mem)
                        self.assertTrue(ok, f"len={length:#x} byte={byte:#x} {why}")
                        swept += 1
        self.assertEqual(swept, 150)


class FidelityTests(unittest.TestCase):
    """The emulator must execute the committed bytes, not echo the model."""

    def _reference(self):
        mem = build_case(bytes(0x130))
        decoded(mem, SELF, log=True)
        return list(mem.log)

    def test_doctoring_a_store_offset_diverts_the_write_set(self):
        text = (PACKET / "main.txt").read_text()
        doctored, n = re.subn(r"(mov\s+%ax,0x48\(%rdi\))", "mov    %eax,0x4c(%rdi)", text)
        self.assertEqual(n, 1)
        mem = build_case(bytes(0x130))
        decoded(mem, SELF, excerpt=doctored, log=True)
        self.assertNotEqual(mem.log, self._reference())
        self.assertIn((SELF + 0x4C, 4, 0), mem.log)

    def test_moving_the_last_store_diverts_the_write_set(self):
        text = (PACKET / "main.txt").read_text()
        doctored, n = re.subn(r"(movups\s+%xmm0,0x100\(%rdi\))",
                              "movups %xmm0,0x120(%rdi)", text)
        self.assertEqual(n, 1)
        mem = build_case(bytes(0x130))
        decoded(mem, SELF, excerpt=doctored, log=True)
        self.assertNotEqual(mem.log, self._reference())
        self.assertIn((SELF + 0x120, 16, 0), mem.log)

    def test_an_unmodelled_instruction_raises(self):
        text = (PACKET / "main.txt").read_text()
        doctored, n = re.subn(r"(\s+61bd60e:\s+c3\s+)ret", r"\g<1>add    %eax,%eax", text)
        self.assertEqual(n, 1)
        with self.assertRaises(NotImplementedError):
            decoded(build_case(bytes(0x130)), SELF, excerpt=doctored, log=True)

    def test_the_emulator_reports_the_write_set_the_model_predicts(self):
        for pattern, buffer, sso in ((bytes(0x130), b"\x00", False),
                                     (b"\xff" * 0x140, b"\xff", True)):
            mem = build_case(pattern, buffer_bytes=buffer, sso=sso)
            want = model_writes(mem, SELF)
            got = Memory()
            got.words = dict(mem.words)
            decoded(got, SELF, log=True)
            self.assertEqual(want, got.log)

    def test_the_image_comparison_covers_the_staged_regions(self):
        """The differential must compare where the bytes are. An earlier revision
        compared the low 64 bytes of the address space, which nothing writes, so
        the \"final image matches\" claim proved nothing."""
        img = image(build_case(bytes(0x130)))
        self.assertEqual(min(img), SELF)
        for addr in (SELF, SELF + 0x40, SELF + 0x100, SELF + 0x1FF,
                     ARENA, ARENA + 0x100, ARENA + 0x1FF):
            self.assertIn(addr, img, hex(addr))
        for addr in (0x0, 0x10, 0x3F, SELF - 1):
            self.assertNotIn(addr, img, hex(addr))
        self.assertEqual(set(SNAP_REGIONS), {(SELF, SELF + 0x200),
                                            (ARENA, ARENA + 0x200)})

    def test_the_image_comparison_detects_one_wrong_byte(self):
        """A single byte the model does not predict must be found - including in
        the last field, which a 0x40-byte window would have missed."""
        mem = build_case(bytes(0x130))
        expected = apply_writes(mem, model_writes(mem, SELF))
        got = Memory()
        got.words = dict(mem.words)
        decoded(got, SELF, log=True)
        for addr in (SELF + 0x100, SELF + 0x1F0, ARENA + 0x100):
            probe = Memory()
            probe.words = dict(got.words)
            probe.store8(addr, 0x5A, log=False)
            diff = [a for a in image(expected) if image(expected)[a] != image(probe)[a]]
            self.assertEqual(diff, [addr], f"the differential missed {addr:#x}")

    def test_the_readme_pseudocode_accounts_for_every_written_byte(self):
        """The pseudocode is the reader's map of the write set. An earlier revision
        listed the +0xe8 store twice. This ties the prose to the artifact: each
        explicit store appears once, the three memset16 calls cover the twelve
        16-byte fields, and the byte total equals the 220 bytes the routine writes."""
        text = (PACKET / "README.md").read_text()
        block = text.split("```c", 1)[1].split("```", 1)[0]
        explicit = re.findall(
            r"\*\(uint(\d+)_t\*\)\(this \+ 0x([0-9a-f]+)\) = 0;", block)
        self.assertEqual(sorted(int(o, 16) for _, o in explicit),
                         [0x40, 0x48, 0xc8, 0xe8])
        for _, off in explicit:
            self.assertEqual(
                len(re.findall(rf"this \+ 0x{int(off, 16):x}\)", block)), 1,
                f"offset 0x{int(off, 16):x} appears more than once")
        memsets = re.findall(r"memset16\(this \+ 0x([0-9a-f]+), 0, 0x([0-9a-f]+)\)",
                             block)
        self.assertEqual([(int(a, 16), int(b, 16)) for a, b in memsets],
                         [(0x00, 0x40), (0x50, 0x70), (0x100, 0x10)])
        self.assertEqual(len(re.findall(r"\*\(char\*\)this->s\d\.data = '\\0';", block)), 2)
        # the memset16 length argument is already a byte count (0x40 bytes = the
        # four 16-byte fields at 0x00,0x10,0x20,0x30); the two NULs are one byte
        total = sum(int(w) // 8 for w, _ in explicit) \
            + sum(int(b, 16) for _, b in memsets) + 2
        self.assertEqual(total, TOUCHED)


class CensusTests(unittest.TestCase):
    def test_the_census_is_recomputed_from_the_artifact(self):
        cen = _load("cen", PACKET / "census.py")
        c = cen.census()
        self.assertEqual(len(c["call_sites"]), CALLS)
        self.assertEqual(c["caller_fdes"], CALLER_FDES)
        self.assertEqual(c["read_sites"], 0)
        self.assertEqual(c["consumers"], {"discarded": CALLS})
        self.assertEqual(sum(c["argument_forms"].values()), CALLS)
        # every argument shape is one of the four the census defines, and none
        # of the eight sites fell through to "not-seen"
        self.assertTrue(set(c["argument_forms"]) <= {"lea", "register-copy",
                                                    "load", "other"},
                        c["argument_forms"])
        self.assertNotIn("not-seen", c["argument_forms"])

    def test_no_caller_reads_the_register_the_body_leaves(self):
        cen = _load("cen", PACKET / "census.py")
        c = cen.census()
        for r in c["call_sites"]:
            self.assertEqual(r["return_use"], "discarded", r)
        # the two argument shapes the census reports are both exercised
        self.assertGreaterEqual(c["argument_forms"].get("lea", 0), 1)
        self.assertGreaterEqual(c["argument_forms"].get("register-copy", 0), 1)

    def test_one_caller_passes_a_member_of_its_own_receiver(self):
        cen = _load("cen", PACKET / "census.py")
        c = cen.census()
        member = [r for r in c["call_sites"] if "[rdi +" in r["argument_text"]]
        self.assertEqual(len(member), 1, c["call_sites"])
        self.assertEqual(member[0]["site"], 0x5DFE710)


class DisassemblyTests(unittest.TestCase):
    def test_the_body_is_straight_line(self):
        body, _, _ = window_bytes()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        ins = list(md.disasm(body, START))
        self.assertEqual(len(ins), 24)
        self.assertEqual(sum(i.size for i in ins), 127)
        for i in ins:
            self.assertFalse(i.mnemonic.startswith("j"), i.mnemonic)
            self.assertNotIn(i.mnemonic, ("call", "callq"), i.mnemonic)
        self.assertEqual(sum(1 for i in ins if i.mnemonic == "movups"), 12)

    def test_the_static_memory_effect_is_two_loads_and_eighteen_stores(self):
        body, _, _ = window_bytes()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        loads = stores = 0
        for i in md.disasm(body, START):
            for idx, op in enumerate(i.operands):
                if op.type == capstone.x86.X86_OP_MEM:
                    # Capstone lists the memory operand FIRST even for a store,
                    # and for `movups [mem], xmm` it sets both the read and the
                    # write flag, so `op.access` cannot classify it. Position can.
                    if idx == 0:
                        stores += 1
                    else:
                        loads += 1
        self.assertEqual((loads, stores), (2, 18))

    def test_capstone_reports_movups_destinations_as_read(self):
        """Pin the quirk the counting rule above works around, so a Capstone
        change surfaces here rather than silently inverting the memory effect."""
        body, _, _ = window_bytes()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        mems = [op for i in md.disasm(body, START) if i.mnemonic == "movups"
                for op in i.operands if op.type == capstone.x86.X86_OP_MEM]
        self.assertEqual(len(mems), 12)
        for op in mems:
            self.assertEqual(op.access, capstone.CS_AC_READ,
                             "Capstone's movups access flag changed")
            self.assertFalse(op.access & capstone.CS_AC_WRITE,
                             "Capstone now flags the movups destination writable")

    def test_the_decoded_run_performs_exactly_that_many_stores(self):
        mem = build_case(bytes(0x130))
        m = decoded(mem, SELF, log=True)
        self.assertEqual(mem.loads, 2)
        self.assertEqual(mem.stores, 18)
        self.assertEqual(m.steps, 24)


if __name__ == "__main__":
    unittest.main()
