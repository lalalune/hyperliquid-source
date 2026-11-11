#!/usr/bin/env python3
"""Re-derive every claim of the `CompactionJobStats::Reset` packet from the artifact.

  python3 verify.py

Checks, in order:
  manifest     every MANIFEST.sha256 row matches the file it names
  artifact     the 127-byte window equals the committed digest and the committed
               excerpt bytes, is int3-fenced on both sides, and its `.eh_frame`
               entry is the one the packet commits
  anchors      24 contiguous claim anchors, each a real decoded instruction
  census       8 direct calls in 8 caller FDEs, recomputed from .text/.eh_frame,
               and every caller ignores the register the body leaves in rax
  model        the closed-form write set and the decoded-bytes emulator agree on
               the 300-row ledger and on a generated sweep; the write set is the
               same for every staged image (including a self-referential string)
  fidelity     doctoring the excerpt changes the emitted write set, and an
               instruction the interpreter does not model makes it raise
  disassembly  24 instructions, no call, no indirect branch, 2 loads / 18 stores
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
START = 0x61BD590
END = 0x61BD60F
SIZE = END - START
DIGEST = "cfcbe3988ac0d3eeaf68f8d2bb01aa116ee041e03bbd57ab23818ea23a03c009"
SNAP_REGIONS = ((0x100000, 0x100200), (0x200000, 0x200200))   # object + string arena
CALLS = 8
CALLER_FDES = 8
WRITES = 18
TOUCHED = 220
LOADS = 2
STORES = 18
INSTRUCTIONS = 24


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def window_bytes():
    data = BINARY.read_bytes()
    segs = []
    for line in subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode().splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    for v, o, f in segs:
        if v <= START < v + f:
            return data, o + (START - v)
    raise AssertionError("the window is in no LOAD segment")


def tool_listing(text):
    """An objdump listing as {address: bytes}, continuation lines included.

    objdump prints at most seven bytes on an instruction's own line; the rest of a
    longer instruction follows on lines that carry an address and bytes but no
    text. Reading only the instruction lines sees this 127-byte window as 118
    bytes - the three 11-byte `movq` stores lose nine bytes between them.
    """
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)(?:\t.*)?$", line)
        if m:
            out[int(m.group(1), 16)] = bytes.fromhex(m.group(2).replace(" ", ""))
    return out


def instructions(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
        if m:
            out.append((int(m.group(1), 16), m.group(3).strip()))
    return out


def check_manifest():
    rows = 0
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        path = PACKET / rel
        if not path.exists():
            path = ROOT / rel
        assert path.exists(), f"manifest names a missing file: {rel}"
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        assert got == digest, f"digest mismatch for {rel}"
        rows += 1
    return rows


def check_artifact():
    data, off = window_bytes()
    body = data[off:off + SIZE]
    assert len(body) == SIZE == 127, len(body)
    assert hashlib.sha256(body).hexdigest() == DIGEST, "window digest"
    assert (PACKET / "relocations.txt").read_text().count(DIGEST) == 1
    assert data[off - 1] == 0xCC, "the window is not int3-fenced below"
    assert data[off + SIZE] == 0xCC, "the window is not int3-fenced above"
    seen = 0
    text = (PACKET / "main.txt").read_text()
    listing = tool_listing(text)
    addr = START
    for a in sorted(listing):
        assert a == addr, f"the excerpt listing has a gap at {a:#x}"
        raw = listing[a]
        at = off + (a - START)
        assert data[at:at + len(raw)] == raw, f"bytes at {a:#x}"
        addr += len(raw)
        seen += len(raw)
    assert addr == END and seen == SIZE, (addr, seen)
    assert len(instructions(text)) == INSTRUCTIONS
    frames = (PACKET / "frames.txt").read_text()
    assert f"pc={START:016x}..{END:016x}" in frames
    assert frames.count("FDE cie=") == CALLER_FDES + 1, frames.count("FDE cie=")
    reloc = (PACKET / "relocations.txt").read_text()
    assert "no relocations" in reloc and reloc.count("sha256") == 1
    return len(body)


def check_anchors():
    sem = load("sem", PACKET / "semantics.py")
    n = sem.check((PACKET / "main.txt").read_text())
    assert n == INSTRUCTIONS, n
    assert len(sem.ANCHORS) == INSTRUCTIONS
    assert sum(s for _, s, _, _ in sem.ANCHORS) == SIZE
    table = [l.split("\t") for l in (PACKET / "semantics.tsv").read_text().splitlines()[1:]]
    assert len(table) == INSTRUCTIONS
    for row, (a, size, text, _) in zip(table, sem.ANCHORS):
        assert row[0] == f"{a:#x}" and row[1] == str(size) and row[2] == " ".join(text.split())
    return n


def check_census():
    cen = load("cen", PACKET / "census.py")
    c = cen.census()
    assert len(c["call_sites"]) == CALLS, len(c["call_sites"])
    assert c["caller_fdes"] == CALLER_FDES, c["caller_fdes"]
    # Reset is void: every caller must ignore the register the body left in rax
    # (which holds the last std::string data pointer it loaded, not a result).
    assert c["consumers"] == {"discarded": CALLS}, c["consumers"]
    assert c["read_sites"] == 0, c["read_sites"]
    assert c["argument_forms"].get("not-seen", 0) == 0, c["argument_forms"]
    assert set(c["argument_forms"]) <= {"lea", "register-copy", "load", "other"}, \
        c["argument_forms"]
    rows = [l.split("\t") for l in (PACKET / "callers.tsv").read_text().splitlines()[1:] if l]
    assert len(rows) == CALLS
    for r, s in zip(rows, c["call_sites"]):
        assert r[0] == f"{s['site']:#x}" and r[1] == f"{s['fde'][0]:#x}" and \
            r[2] == f"{s['fde'][1]:#x}" and r[3] == s["return_use"] and \
            r[4] == s["argument"], (r, s)
        lo, hi, site = int(r[1], 16), int(r[2], 16), int(r[0], 16)
        assert lo <= site < hi, r
    use = [l.split("\t") for l in (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l]
    assert len(use) == CALLS
    assert all(u[1] == "discarded" for u in use), use
    return CALLS, CALLER_FDES, c["consumers"], c["argument_forms"]


def check_model():
    tool = load("tool", ROOT / "tools" / "rocksdb_compaction_job_stats_reset_61bd590_115.py")
    # the differential must compare where the staged bytes are, never a nominal
    # window: a revision that compared `snapshot(0, 0x40)` proved nothing, because
    # the object is staged at SELF and nothing writes the low addresses.
    assert tool.SNAP_REGIONS == ((tool.SELF, tool.SELF + 0x200),
                                 (tool.ARENA, tool.ARENA + 0x200)), tool.SNAP_REGIONS
    cases = tool.generate_cases(seed=7)
    assert len(cases) == 300, len(cases)
    canon = None
    for family, pattern, buffer, sso in cases:
        mem = tool.build_case(pattern, buffer_bytes=buffer, sso=sso)
        ok, why, want, got = tool.agree(mem)
        assert ok, f"{family}: {why}"
        assert len(want) == WRITES and len(tool.touched(want)) == TOUCHED, (family, want)
        # the two rows that follow a pointer leave the object, so their addresses
        # move with the staged image while the shape stays fixed
        # the sixteen field rows are the same object offsets in program order in
        # every case; rows 14 and 16 follow a pointer and therefore move with the
        # staged image (outside the object, or inside it for a self-referential
        # string), which the two assertions below check against the object itself
        fields = [want[i] for i in range(len(want)) if i not in (14, 16)]
        if canon is None:
            canon = fields
        else:
            assert fields == canon, f"{family}: the field rows moved"
        # the two argument-dependent rows are the buffers the object named
        assert want[14][0] == mem.load64(tool.SELF + 0xC0), f"{family}: string 1 target"
        assert want[16][0] == mem.load64(tool.SELF + 0xE0), f"{family}: string 2 target"
    # independent sweep: every object pattern byte value x every buffer byte x
    # both string shapes x several object lengths
    swept = 0
    for length in (0x40, 0xC0, 0x130, 0x140, 0x1FF):
        for byte in (0x00, 0x01, 0x7F, 0x80, 0xFF):
            for sso in (False, True):
                pattern = bytes((byte + i) % 256 for i in range(length))
                for buffer in (b"\x00", b"\xff", bytes([byte])):
                    mem = tool.build_case(pattern, buffer_bytes=buffer, sso=sso)
                    ok, why, want, got = tool.agree(mem)
                    assert ok, f"sweep len={length:#x} byte={byte:#x} {why}"
                    swept += 1
    # idempotence: the routine is a pure zeroing initializer, so a second run
    # leaves the image byte-identical (all 18 writes store zero)
    mem = tool.build_case(b"\xff" * 0x130, buffer_bytes=b"\xff")
    tool.decoded(mem, tool.SELF, log=True)
    first = dict(mem.words)
    tool.decoded(mem, tool.SELF, log=True)
    assert mem.words == first, "the second application changed the object"
    # the write set is reported once, in program order, and the committed table is it
    want = tool.model_writes(tool.build_case(bytes(0x130)), tool.SELF)
    table = [l.split("\t") for l in (PACKET / "writes.tsv").read_text().splitlines()[8:] if l]
    assert len(table) == WRITES, len(table)
    for row, (addr, width, value) in zip(table, want):
        label = f"0x{addr - tool.SELF:x}" if tool.SELF <= addr < tool.SELF + 0x200 \
            else f"*(0x{addr:x})"
        assert row == [label, str(width), str(value)], (row, addr, width, value)
    return len(cases), swept


def check_fidelity():
    """The emulator must execute the committed bytes, not echo the model."""
    tool = load("tool", ROOT / "tools" / "rocksdb_compaction_job_stats_reset_61bd590_115.py")
    text = (PACKET / "main.txt").read_text()
    base = tool.build_case(bytes(0x130))
    tool.decoded(base, tool.SELF, log=True)
    reference = list(base.log)
    # (a) widen the two-byte store and move it
    doctored, n = re.subn(r"(mov\s+%ax,0x48\(%rdi\))", "mov    %eax,0x4c(%rdi)", text)
    assert n == 1, "the two-byte store is not in the excerpt as expected"
    mem = tool.build_case(bytes(0x130))
    tool.decoded(mem, tool.SELF, excerpt=doctored, log=True)
    assert mem.log != reference, "a doctored store offset did not change the write set"
    # (b) move the last movups out of the window's last field
    doctored2, n2 = re.subn(r"(movups\s+%xmm0,0x100\(%rdi\))",
                            "movups %xmm0,0x120(%rdi)", text)
    assert n2 == 1
    mem = tool.build_case(bytes(0x130))
    tool.decoded(mem, tool.SELF, excerpt=doctored2, log=True)
    assert mem.log != reference and (tool.SELF + 0x120, 16, 0) in mem.log
    # (c) an instruction the interpreter does not model must raise, not be guessed
    doctored3, n3 = re.subn(r"(\s+61bd60e:\s+c3\s+)ret",
                            r"\g<1>add    %eax,%eax", text)
    assert n3 == 1, "the `ret` line is not in the excerpt as expected"
    try:
        tool.decoded(tool.build_case(bytes(0x130)), tool.SELF, excerpt=doctored3, log=True)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("an unmodelled instruction was silently executed")
    return "store width/offset and an unmodelled instruction all divert"


def check_disassembly():
    data, off = window_bytes()
    body = data[off:off + SIZE]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(body, START))
    assert len(ins) == INSTRUCTIONS, len(ins)
    assert sum(i.size for i in ins) == SIZE
    loads = stores = 0
    for i in ins:
        assert i.mnemonic not in ("call", "callq", "jmp", "jmpq"), i.mnemonic
        if i.mnemonic.startswith("j"):
            raise AssertionError(f"branch {i.mnemonic} - the body is straight line")
        for idx, op in enumerate(i.operands):
            if op.type == capstone.x86.X86_OP_MEM:
                # Capstone lists the memory operand FIRST even for a store, and
                # for `movups xmmword ptr [mem], xmm` it sets BOTH the read and
                # the write flag on it. Deriving "is it a store" from
                # `op.access & CS_AC_WRITE` therefore counts all twelve widest
                # stores as loads as well; position is the reliable signal, and
                # the quirk is pinned below so a Capstone change surfaces here.
                if idx == 0:
                    stores += 1
                else:
                    loads += 1
    movups_mem = [op for i in ins if i.mnemonic == "movups" for op in i.operands
                  if op.type == capstone.x86.X86_OP_MEM]
    assert len(movups_mem) == 12
    assert all(op.access == capstone.CS_AC_READ for op in movups_mem), \
        "Capstone's movups access flag changed; revisit check_disassembly"
    assert (loads, stores) == (LOADS, STORES), (loads, stores)
    # the twelve movups are what makes the store count large
    assert sum(1 for i in ins if i.mnemonic == "movups") == 12
    # the decoded run really performs that many stores
    tool = load("tool", ROOT / "tools" / "rocksdb_compaction_job_stats_reset_61bd590_115.py")
    mem = tool.build_case(bytes(0x130))
    m = tool.decoded(mem, tool.SELF, log=True)
    assert (mem.loads, mem.stores, m.steps) == (LOADS, STORES, INSTRUCTIONS), \
        (mem.loads, mem.stores, m.steps)
    return len(ins), loads, stores


def main():
    rows = check_manifest()
    size = check_artifact()
    anchors = check_anchors()
    calls, fdes, consumers, args = check_census()
    cases, swept = check_model()
    fidelity = check_fidelity()
    nins, loads, stores = check_disassembly()
    print(f"verify OK: {rows} manifest rows, {size}-byte window sha {DIGEST[:12]}..., "
          f"{anchors} claim anchors, {nins} instructions, {calls} calls / {fdes} caller "
          f"FDEs {consumers}, argument forms {args}, {cases}-row ledger + {swept}-case "
          f"sweep agree (write set {WRITES} rows / {TOUCHED} bytes, idempotent, image "
          f"differential over {len(SNAP_REGIONS)} staged regions), "
          f"{loads} loads / {stores} stores static and executed; fidelity: {fidelity}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
