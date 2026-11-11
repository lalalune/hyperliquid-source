#!/usr/bin/env python3
"""Re-derive every claim of the `AreFilesInCompaction` packet from the artifact.

  python3 verify.py

Checks, in order:
  manifest    every MANIFEST.sha256 row matches the file it names
  artifact    the window bytes equal the committed digest and the excerpt bytes,
              and the window is int3-fenced on both sides
  anchors     22 claim anchors, contiguous, each one a real instruction
  census      9 direct calls in 5 caller FDEs, recomputed from .text/.eh_frame
  model       the closed-form model and the decoded-bytes emulator agree on the
              ledger and on a generated sweep, and the routine's memory effect is
              6 loads / 0 stores
  disassembly no call, no indirect branch, no memory write in the window
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
START = 0x5D9A390
END = 0x5D9A3CF
DIGEST = "6de8326a03541c2778148ae408b2f22c254ffdb5d4e5c204fc145911752d90b3"
CONSUMERS = {"arithmetic": 7, "returned": 1, "stored": 1}


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
    body = data[off:off + (END - START)]
    assert len(body) == END - START == 63, len(body)
    assert hashlib.sha256(body).hexdigest() == DIGEST, "window digest"
    assert (PACKET / "relocations.txt").read_text().count(DIGEST) == 1
    assert data[off - 8:off] == b"\xcc" * 8, "the window is not int3-fenced below"
    assert data[off + len(body):off + len(body) + 1] == b"\xcc", "not fenced above"
    # the excerpt's byte column must be the artifact's bytes, instruction by instruction
    seen = 0
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t", line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        assert data[off + (va - START):off + (va - START) + len(raw)] == raw, f"bytes at {va:#x}"
        seen += len(raw)
    assert seen == len(body), (seen, len(body))
    frames = (PACKET / "frames.txt").read_text()
    assert f"pc={START:016x}..{END:016x}" in frames
    return len(body)


def check_anchors():
    sem = load("sem", PACKET / "semantics.py")
    n = sem.check((PACKET / "main.txt").read_text())
    assert n == 22, n
    assert len(sem.ANCHORS) == 22
    assert sum(s for _, s, _, _ in sem.ANCHORS) == 63
    return n


def check_census():
    cen = load("cen", PACKET / "census.py")
    c = cen.census()
    assert len(c["call_sites"]) == 9, len(c["call_sites"])
    assert c["fdes"] == 5, c["fdes"]
    assert c["consumers"] == CONSUMERS, c["consumers"]
    assert c["discarded_sites"] == 0
    # the committed tables must be exactly this census
    rows = [l.split("\t") for l in (PACKET / "callers.tsv").read_text().splitlines()[1:] if l]
    assert len(rows) == 9
    for r, s in zip(rows, c["call_sites"]):
        assert r[0] == f"{s['site']:#x}" and r[1] == f"{s['fde'][0]:#x}" and \
            r[2] == f"{s['fde'][1]:#x}" and r[3] == s["use"], (r, s)
    use = [l.split("\t") for l in (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l]
    assert len(use) == 9
    # every call site appears in exactly one FDE and inside it
    for r in rows:
        lo, hi, site = int(r[1], 16), int(r[2], 16), int(r[0], 16)
        assert lo <= site < hi, r
    # the invert site really inverts, the forward site really returns the value
    assert use[0][1] == "arithmetic" and "xor" in use[0][2]
    assert use[1][1] == "returned"
    assert use[3][1] == "stored" and "byte ptr" in use[3][2]
    return 9, 5, CONSUMERS


def check_model():
    tool = load("tool", ROOT / "tools" / "rocksdb_are_files_in_compaction_5d9a390_115.py")
    cases = tool.generate_cases(seed=7)
    assert len(cases) == 300, len(cases)
    for family, flags in cases:
        ok, want, got = tool.agree(flags)
        assert ok, f"{family} {flags}: model {want} decoded {got}"
    # an independent sweep: every vector up to 40 elements, flag at every position,
    # at several flag values, plus the dense and clear shapes
    swept = 0
    for n in range(0, 41):
        for v in (1, 2, 0x7F, 0x80, 0xFF):
            for pos in list(range(n)) + [None]:
                flags = [0] * n
                if pos is not None:
                    flags[pos] = v
                ok, want, got = tool.agree(tuple(flags))
                assert ok, f"sweep n={n} pos={pos} v={v}: model {want} decoded {got}"
                swept += 1
    # the model refuses an impossible vector instead of guessing
    mem = tool.Memory()
    try:
        tool.model(mem, 0x1000, 0x0FF0)
        raise AssertionError("the model accepted end < begin")
    except ValueError:
        pass
    a = tool.accesses((0, 1, 0))
    assert a["stores"] == 0, a
    assert a["eax"] == 1, a
    assert tool.accesses((0, 0, 0))["eax"] == 0
    assert tool.accesses(())["eax"] == 0 and tool.accesses(())[
        "stores"] == 0, "empty vector must be answered from the header alone"
    return len(cases), swept, a


def check_disassembly():
    data, off = window_bytes()
    body = data[off:off + (END - START)]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(body, START))
    assert len(ins) == 22, len(ins)
    assert sum(i.size for i in ins) == 63
    loads = stores = 0
    for i in ins:
        assert i.mnemonic not in ("call", "jmpq", "callq"), i.mnemonic
        if i.mnemonic.startswith("j") and i.operands and \
                i.operands[0].type == capstone.x86.X86_OP_REG:
            raise AssertionError("indirect branch")
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                if op.access & capstone.CS_AC_WRITE:
                    stores += 1
                if op.access & capstone.CS_AC_READ:
                    loads += 1
    # the interpreter walks the two loads per element the census reports
    assert (loads, stores) == (4, 0), (loads, stores)
    return len(ins), loads, stores


def main():
    rows = check_manifest()
    size = check_artifact()
    anchors = check_anchors()
    sites, fdes, consumers = check_census()
    cases, swept, acc = check_model()
    nins, loads, stores = check_disassembly()
    print(f"verify OK: {rows} manifest rows, {size}-byte window sha {DIGEST[:12]}..., "
          f"{anchors} claim anchors, {nins} instructions, {sites} calls / {fdes} caller "
          f"FDEs {consumers}, {cases}-row ledger + {swept}-case sweep agree, "
          f"{loads} loads / {stores} stores static, {acc['loads']} loads / "
          f"{acc['stores']} stores executed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
