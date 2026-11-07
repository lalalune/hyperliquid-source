#!/usr/bin/env python3
"""Census of node #115's named-enum registries (RE-001).

Parses the verbatim objdump of the static initializer
``__static_initialization_and_destruction_0v`` (0x60c78a0..0x60c870d,
re-shipped byte-identical from #4237) and resolves, for each of the
twelve registry blocks, the registry address, the builder function,
the entry count, and the (name, value) pairs.

Record layouts (proven from the builders' own code, not assumed):
- std::map<unsigned char, std::string> builders (0x60bd6e0, 0x60bd980,
  0x60bdc20, 0x60bdec0): record = {u8 key @ +0, std::string @ +8};
  the builder reads the key with ``movzbl 0x0(%rbp)`` and the string
  pointer/size at +0x8/+0x10.  The tag byte lives at dest-8.
- std::unordered_map<std::string, unsigned char> builders (the other
  eight): record = {std::string @ +0, u8 value @ +0x20}; the builder
  reads the string pointer/size at +0x0/+0x8 and the value with
  ``movzbl 0x20(%rbp)``.  The tag byte lives at dest+0x20.

The tag store for a pair is emitted next to its string-ctor call, so
tags are resolved at block close from the tag stores seen so far --
never at string-ctor time, where the store may not have been emitted
yet (that off-by-one produced shifted values in an earlier draft).

Also resolves the __cxa_atexit calls (dtor, object, dso) per block,
including the twelfth registration, which is a tail jump to
__cxa_atexit (dtor 0x60b8090, object 0x6506fa0, dso 0x64efa20).

Usage: python3 census.py  (run from the repo root)
Writes registries.tsv next to this file.
"""

import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
DUMP = HERE / "static-initializer-60c78a0.objdump.txt"

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$")
LEA_RIP = re.compile(
    r"lea\s+(-?0x[0-9a-f]+)\(%rip\),(%\w+)\s+# ([0-9a-f]+)")
LEA_RBP = re.compile(r"lea\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
MOV_REG = re.compile(r"mov\s+(%\w+),(%\w+)")
MOV_RBP_LOAD = re.compile(r"mov\s+(-0x[0-9a-f]+)\(%rbp\),(%\w+)")
MOV_RBP_STORE = re.compile(r"mov\s+(%\w+),(-0x[0-9a-f]+)\(%rbp\)")
MOV_IMM = re.compile(r"mov\s+\$(-?0x[0-9a-f]+),(%\w+)")
TAG_STORE = re.compile(r"mov[bwl]\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
XOR_ZERO = re.compile(r"xor\s+(%\w+),(%\w+)")
CALL = re.compile(r"call\s+([0-9a-f]+)")
JMP = re.compile(r"jmp\s+([0-9a-f]+)")

STR_CTOR = 0x60B7D80
ATEXIT = 0x63F0F80
PLT_LOW = 0x63F0000
# Builders whose record is {u8 key @ +0, std::string @ +8}.
MAP_BUILDERS = {0x60BD6E0, 0x60BD980, 0x60BDC20, 0x60BDEC0}

# registry -> (enum name, option-type number or None)
ENUMS = {
    0x6507260: ("CompactionStyle", None),
    0x6507220: ("CompactionPri", None),
    0x65071E0: ("CompactionStopStyle", None),
    0x65071A0: ("Temperature", None),
    0x6507160: ("ChecksumType", 15),
    0x6507120: ("CompressionType", 13),
    0x65070E0: ("EncodingType", 16),
    0x65070A0: ("CompactionStyle", 11),
    0x6507060: ("CompactionPri", 12),
    0x6507020: ("CompactionStopStyle", 14),
    0x6506FE0: ("Temperature", 24),
    0x6506FA0: ("PrepopulateBlobCache", None),
}


def read_cstr(data, vaddr):
    if vaddr >= len(data):
        return None
    try:
        end = data.index(b"\x00", vaddr)
    except ValueError:
        return None
    s = data[vaddr:end].decode("utf-8", "replace")
    if not s or not all(32 <= ord(c) < 127 for c in s):
        return None
    return s


def main():
    data = open(BIN, "rb").read()
    insns = []
    for line in open(DUMP):
        m = INSN.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip()))

    regs = {}
    slots = {}
    tags = {}
    blocks = []
    pairs = []  # (name, literal, dest_rbp) per open block
    atexit = []
    last_edx = None

    def fmt(v):
        if v is None:
            return None
        if v[0] == "rip":
            return hex(v[1])
        if v[0] == "rbp":
            return f"rbp{v[1]}"
        if v[0] == "imm":
            return hex(v[1])
        return str(v)

    def record_atexit():
        atexit.append((fmt(regs.get("%rdi")), fmt(regs.get("%rsi")),
                       fmt(regs.get("%rdx"))))

    for addr, t in insns:
        m = LEA_RIP.match(t)
        if m:
            regs[m.group(2)] = ("rip", int(m.group(3), 16))
            continue
        m = LEA_RBP.match(t)
        if m:
            regs[m.group(2)] = ("rbp", int(m.group(1), 16))
            continue
        m = MOV_REG.match(t)
        if m:
            regs[m.group(2)] = regs.get(m.group(1))
            continue
        m = MOV_RBP_LOAD.match(t)
        if m:
            regs[m.group(2)] = slots.get(int(m.group(1), 16))
            continue
        m = MOV_RBP_STORE.match(t)
        if m:
            slots[int(m.group(2), 16)] = regs.get(m.group(1))
            continue
        m = MOV_IMM.match(t)
        if m:
            regs[m.group(2)] = ("imm", int(m.group(1), 16))
            if m.group(2) == "%edx":
                last_edx = int(m.group(1), 16)
            continue
        m = TAG_STORE.match(t)
        if m:
            tags[int(m.group(2), 16)] = int(m.group(1), 16)
            continue
        m = XOR_ZERO.match(t)
        if m and m.group(1) == m.group(2):
            regs[m.group(1)] = ("imm", 0)
            continue
        m = CALL.match(t)
        if m:
            tgt = int(m.group(1), 16)
            if tgt == STR_CTOR:
                dest = regs.get("%rdi")
                lit = regs.get("%rsi")
                name = (read_cstr(data, lit[1])
                        if lit and lit[0] == "rip" else None)
                pairs.append((name, lit[1] if lit else None,
                              dest[1] if dest and dest[0] == "rbp" else None))
            elif tgt == ATEXIT:
                record_atexit()
            elif tgt < PLT_LOW:
                reg = regs.get("%rdi")
                registry = reg[1] if reg and reg[0] == "rip" else None
                is_map = tgt in MAP_BUILDERS
                fixed = []
                for name, lit, dest in pairs:
                    if dest is None:
                        tag = None
                    elif is_map:
                        tag = tags.get(dest - 8)
                    else:
                        tag = tags.get(dest + 0x20)
                    fixed.append((name, tag, lit, dest))
                blocks.append({
                    "builder": tgt,
                    "registry": registry,
                    "count": last_edx if is_map else len(fixed),
                    "pairs": fixed,
                    "call": addr,
                    "is_map": is_map,
                })
                pairs = []
                last_edx = None
            continue
        m = JMP.match(t)
        if m and int(m.group(1), 16) == ATEXIT:
            record_atexit()
            continue

    rows = []
    for b in blocks:
        enum_name, opt_type = ENUMS[b["registry"]]
        for name, tag, lit, dest in b["pairs"]:
            rows.append((f"0x{b['registry']:x}", enum_name,
                         opt_type if opt_type is not None else "",
                         f"0x{b['builder']:x}",
                         "map" if b["is_map"] else "unordered_map",
                         name, tag, f"0x{lit:x}"))
    out = HERE / "registries.tsv"
    with open(out, "w") as f:
        f.write("registry\tenum\toption_type\tbuilder\tcontainer\tname\t"
                "value\tliteral\n")
        for r in rows:
            f.write("\t".join(str(c) for c in r) + "\n")
    print(f"blocks: {len(blocks)}")
    for b in blocks:
        enum_name, opt_type = ENUMS[b["registry"]]
        print(f"builder 0x{b['builder']:x} registry 0x{b['registry']:x} "
              f"({enum_name}, type {opt_type}) "
              f"{'map' if b['is_map'] else 'unordered_map'} "
              f"count={b['count']} pairs={len(b['pairs'])}")
        for name, tag, lit, dest in b["pairs"]:
            print(f"  value={tag} name={name!r} lit=0x{lit:x}")
    print(f"total pairs: {len(rows)}")
    print(f"atexit registrations: {len(atexit)}")
    for dtor, obj, dso in atexit:
        print(f"  dtor={dtor} obj={obj} dso={dso}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
