#!/usr/bin/env python3
"""Census of the node #115 DBOptions OptionTypeInfo map.

Parses the verbatim objdump of the static initializer
``__static_initialization_and_destruction_0v`` (0x60aa2b0..0x60b1d78) and
extracts every OptionTypeInfo entry it builds: (name, offset, flags).

Method (validated on the six entries #4146 recorded, and cross-checked
against the ImmutableDBOptions ctor pack and BuildDBOptions):
- Entry blocks are delimited by calls to the pair constructor 0x5d400f0.
  Each block builds one (key string, OptionTypeInfo temp) pair:
  * ``lea <str>(%rip),%rsi`` + ``call 0x609fb90`` constructs the key string.
  * The OptionTypeInfo temp at stack base D has:
        movq $OFFSET, D(%rbp)   (or movl $OFFSET when the compiler
                                  proves the high half is zero)
        movups %xmm0, D+0x08/%rbp ...   -- the five std::function functors
        movq $0, D+0x18/%rbp ...        -- the five std::function managers
        movl $FLAGS, D+0xb0(%rbp)       -- flags
    The temp base D is recovered from the movups pattern (D+0x08, D+0x28,
    D+0x48, D+0x68, D+0x88) and confirmed by the temp pointer passed in
    %rdx to the pair-constructor call (via ``lea D(%rbp),%rdx`` or a saved
    slot).  Blocks that build a second temp for a teardown or a nested
    entry pick the temp the pair-constructor call actually consumes.
- Strings are read from .rodata at file offset == vaddr (LOAD1 identity
  mapping, verified against readelf).
- The +0x21b census is a separate whole-binary displacement scan
  (see census_21b.py): it counts every ``0x21b(%reg)`` instruction.

Usage: python3 census.py  (run from the repo root)
Writes entries.tsv (and prints a summary) next to this file.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
DUMP = Path(__file__).resolve().parent / "static-initializer-60aa2b0.objdump.txt"
OUT = Path(__file__).resolve().parent / "entries.tsv"

PAIR_CTOR = 0x5D400F0
STR_CTOR = 0x609FB90

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
LEA_STR = re.compile(r"lea\s+-?0x[0-9a-f]+\(%rip\),%rsi\s+# ([0-9a-f]+)")
LEA_RDX = re.compile(r"lea\s+(-0x[0-9a-f]+)\(%rbp\),%rdx")
LEA_RAX = re.compile(r"lea\s+(-0x[0-9a-f]+)\(%rbp\),%rax")
MOV_RDX_RAX = re.compile(r"mov\s+%rax,%rdx")
MOV_RDX_SLOT = re.compile(r"mov\s+(-0x[0-9a-f]+)\(%rbp\),%rdx")
SAVE_RDX = re.compile(r"mov\s+%rdx,(-0x[0-9a-f]+)\(%rbp\)")
MOVQ_IMM = re.compile(r"movq\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOVL_IMM = re.compile(r"movl\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOVUPS = re.compile(r"movups\s+%xmm\d,(-0x[0-9a-f]+)\(%rbp\)")
CALL = re.compile(r"call\s+([0-9a-f]+)")


def read_cstr(data, vaddr):
    off = vaddr  # .rodata file offset == vaddr (LOAD1 identity mapping)
    end = data.index(b"\x00", off)
    return data[off:end].decode("utf-8", "replace")


def parse_dump(path):
    insns = []
    with open(path) as f:
        for line in f:
            m = INSN.match(line)
            if m:
                insns.append((int(m.group(1), 16), m.group(2).strip()))
    return insns


def split_blocks(insns):
    blocks = []
    cur = []
    for ins in insns:
        cur.append(ins)
        if ins[1].startswith("call"):
            m = CALL.search(ins[1])
            if m and int(m.group(1), 16) == PAIR_CTOR:
                blocks.append(cur)
                cur = []
    if cur:
        blocks.append(cur)
    return blocks


def main():
    data = BIN.read_bytes()
    insns = parse_dump(DUMP)
    blocks = split_blocks(insns)
    # Saved temp pointers: slot -> temp displacement, from `mov %rdx,SLOT(%rbp)`
    # where %rdx was set by `lea D(%rbp),%rdx` earlier in the same function.
    saved = {}
    last_lea_rdx = None
    for addr, text in insns:
        m = LEA_RDX.search(text)
        if m:
            last_lea_rdx = int(m.group(1), 16)
        m = SAVE_RDX.search(text)
        if m and last_lea_rdx is not None:
            saved[int(m.group(1), 16)] = last_lea_rdx

    rows = []
    for bi, block in enumerate(blocks):
        name = None
        for addr, text in block:
            m = LEA_STR.search(text)
            if text.startswith("lea") and m:
                try:
                    name = read_cstr(data, int(m.group(1), 16))
                except ValueError:
                    name = None
        # temp candidates via the movups pattern
        ups = set()
        for addr, text in block:
            m = MOVUPS.search(text)
            if m:
                ups.add(int(m.group(1), 16))
        cands = [d - 0x08 for d in ups
                 if all((d - 0x08 + o) in ups
                        for o in (0x08, 0x28, 0x48, 0x68, 0x88))]
        if not cands:
            rows.append((bi, name, None, None, None, "no-temp"))
            continue
        # temp consumed by the pair-constructor call: track %rdx at the call
        call_rdx = None
        last_lea_rax = None
        for addr, text in block:
            m = LEA_RDX.search(text)
            if m:
                call_rdx = int(m.group(1), 16)
            m = LEA_RAX.search(text)
            if m:
                last_lea_rax = int(m.group(1), 16)
            if MOV_RDX_RAX.search(text) and last_lea_rax is not None:
                call_rdx = last_lea_rax
            m = MOV_RDX_SLOT.search(text)
            if m and int(m.group(1), 16) in saved:
                call_rdx = saved[int(m.group(1), 16)]
        chosen = call_rdx if call_rdx in cands else None
        if chosen is None:
            # fall back to the unique candidate, else the one with an offset
            if len(cands) == 1:
                chosen = cands[0]
            else:
                for c in cands:
                    if any(MOVQ_IMM.search(t) and
                           int(MOVQ_IMM.search(t).group(2), 16) == c
                           for _, t in block):
                        chosen = c
                        break
        if chosen is None:
            rows.append((bi, name, None, None, None, "ambiguous-temp"))
            continue
        offset = None
        for addr, text in block:
            m = MOVQ_IMM.search(text)
            if m and int(m.group(2), 16) == chosen:
                offset = int(m.group(1), 16)
        if offset is None:
            for addr, text in block:
                m = MOVL_IMM.search(text)
                if m and int(m.group(2), 16) == chosen:
                    offset = int(m.group(1), 16)
        flags = None
        for addr, text in block:
            m = MOVL_IMM.search(text)
            if m and int(m.group(2), 16) == chosen + 0xB0:
                flags = int(m.group(1), 16)
        rows.append((bi, name, chosen, offset, flags,
                     "ok" if offset is not None else "no-offset"))

    with open(OUT, "w") as f:
        f.write("block\tname\ttemp_base\toffset\tflags\tnote\n")
        for bi, name, temp, offset, flags, note in rows:
            f.write(f"{bi}\t{name}\t"
                    f"{temp if temp is None else hex(temp)}\t"
                    f"{offset if offset is None else hex(offset)}\t"
                    f"{flags if flags is None else hex(flags)}\t{note}\n")
    named = [r for r in rows if r[1]]
    with_off = [r for r in rows if r[3] is not None]
    print(f"blocks={len(blocks)} named={len(named)} "
          f"with_offset={len(with_off)}")
    for r in rows:
        if r[5] != "ok":
            print(f"  non-ok: block {r[0]} name={r[1]!r} note={r[5]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
