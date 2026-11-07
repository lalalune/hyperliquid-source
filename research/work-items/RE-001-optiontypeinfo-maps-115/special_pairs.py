#!/usr/bin/env python3
"""Extract the enum-map contents and the 8 special pairs (node #115).

Enum maps: the four unordered_map<string,int> maps (0x6506ec0/e80/e40/e00)
are built by range ctors whose pair temps live on the static initializer's
stack.  Each pair is built as: ``lea <str>(%rip),%rsi`` + string ctor
(0x609fb90) with %rdi = the pair slot, then ``movb/movl $val, <pair+0x20>``.
Regions are bounded by the four range-ctor call sites in the initializer
excerpt (0x60aa4c2 ec0, 0x60aa5a2 e80, 0x60aa64b e40, 0x60aa737 e00).

Special pairs: the 8 gap slots in range 2 of the DBOptions map.  For each,
the key string (ctor 0x609fb90 at the pair slot) and the value temp's
OptionTypeInfo fields are recovered from the static-initializer excerpt:
  wal_filter                pair -0x3dd0, temp -0x4550 (via -0x8b68/-0x8150)
  wal_recovery_mode         pair -0x1c10, mid helper 0x60a64d0 (map ec0)
  access_hint_on_compaction_start  pair -0x17d8, mid helper 0x60a65c0 (e80)
  info_log_level            pair -0x1700, mid helper 0x60a66b0 (map e00)
  env                       pair -0x620,  temp -0x7e50
  file_checksum_gen_factory pair -0x470,  temp -0x4550 (via -0x8d50)
  statistics                pair -0x398,  temp -0x4550 (via -0x8d90)
  lowest_used_cache_tier    pair -0x1e8,  mid helper 0x60a67a0 (map e40)
The mid helpers hardcode typeverif 0x12 (type 18, verif 0); offset = %esi
and flags = %ecx at the call site.  The -0x4550 temp is reused across
builds, so each field read is scoped to the lines between the build's
offset write and its move-ctor call.

Usage: python3 special_pairs.py  (run from the repo root)
Writes enum_maps.tsv and special_pairs.tsv next to this file.
"""

import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
SRC = HERE.parent / "RE-001-optiontypeinfo-mismatches-115" / \
    "static-initializer-60aa2b0.objdump.txt"

LEA_SLOT = re.compile(r"lea\s+-0x([0-9a-f]+)\(%rbp\),%(\w+)")
LEA_STR = re.compile(r"lea\s+.*\(%rip\),%rsi\s+#\s*([0-9a-f]+)")
CALL_STRCTOR = re.compile(r"call\s+609fb90\b")
MOV_REG = re.compile(r"mov\s+%(\w+),%(\w+)\b")
MOVB_L = re.compile(r"mov[b|l]\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOVQ_IMM = re.compile(r"movq\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
MOV_REG_SLOT = re.compile(r"mov\s+%(\w+),(-0x[0-9a-f]+)\(%rbp\)")
MOV_RODATA = re.compile(
    r"mov\s+-0x[0-9a-f]+\(%rip\),%(\w+)\s+#\s*([0-9a-f]+)")
ADDR = re.compile(r"^\s*([0-9a-f]+):")

RANGE_CTORS = [
    (0x60AA4C2, "ec0"),
    (0x60AA5A2, "e80"),
    (0x60AA64B, "e40"),
    (0x60AA737, "e00"),
]


def rodata_string(addr):
    # Only .rodata addresses are readable from the file; .bss/.data
    # globals (e.g. a map address loaded into %rsi) are not strings.
    if not (0x430400 <= addr < 0xB9F040):
        return None
    with open(ROOT / "work/hl-node-115.bin", "rb") as f:
        f.seek(addr)
        raw = f.read(128)
    return raw.split(b"\0", 1)[0].decode(errors="replace")


def rodata_qword(addr):
    with open(ROOT / "work/hl-node-115.bin", "rb") as f:
        f.seek(addr)
        return struct.unpack("<Q", f.read(8))[0]


def lines_of(path):
    return open(path).read().splitlines()


def enum_map_pairs(lines, start_addr, end_addr, regs=None):
    """(slot, name, value) pairs built between two addresses.

    ``regs`` is the register->stack-slot map carried across regions: the
    later maps reuse %rbx/%r12/%r13/%r14, which were loaded once for the
    first map and never reloaded.
    """
    if regs is None:
        regs = {}      # reg -> stack slot (negative int, e.g. -0x4490)
    pending_str = None
    strings = {}       # slot -> name
    values = {}        # slot -> value
    active = False
    for ln in lines:
        a = ADDR.match(ln)
        if not a:
            continue
        addr = int(a.group(1), 16)
        if addr == start_addr:
            active = True
        if addr >= end_addr:
            break
        if not active:
            continue
        m = LEA_SLOT.search(ln)
        if m:
            regs[m.group(2)] = -int(m.group(1), 16)
            continue
        m = LEA_STR.search(ln)
        if m:
            s = rodata_string(int(m.group(1), 16))
            if s is not None:
                pending_str = s
            continue
        m = MOV_REG.search(ln)
        if m and m.group(1) in regs:
            # register copy (mov %rax,%r15 / mov %rbx,%rdi): propagate
            # the tracked stack slot to the destination register
            regs[m.group(2)] = regs[m.group(1)]
            continue
        if CALL_STRCTOR.search(ln) and pending_str is not None:
            slot = regs.get("rdi")
            if slot is not None:
                strings[slot] = pending_str
            pending_str = None
            continue
        m = MOVB_L.search(ln)
        if m:
            val = int(m.group(1), 16)
            slot = int(m.group(2), 16)  # already negative, e.g. -0x4470
            # value is written at pair+0x20
            values[slot - 0x20] = val
    # pairs in slot order
    out = []
    for slot in sorted(strings):
        out.append((slot, strings[slot], values.get(slot)))
    return out, regs


MID_HELPERS = {
    0x60A64D0: "wal_recovery_mode",
    0x60A65C0: "access_hint_on_compaction_start",
    0x60A66B0: "info_log_level",
    0x60A67A0: "lowest_used_cache_tier",
}
# (pair slot, key, value-temp, build-lo, build-hi) for the four
# non-mid-helper specials.  The -0x4550 temp is reused across builds, so
# each field read is scoped to its build window (offset write .. move).
TEMP_BUILDS = [
    # wal_filter: temp -0x4550, offset write 0x60ac4ed, move 0x60ac603
    (-0x3DD0, "wal_filter", -0x4550, 0x60AC4ED, 0x60AC603),
    # env: temp -0x7e50, offset write 0x60b0111, move 0x60b0371
    (-0x620, "env", -0x7E50, 0x60B0111, 0x60B0371),
    # file_checksum_gen_factory: temp -0x4550, offset 0x60b0475, move 0x60b058b
    (-0x470, "file_checksum_gen_factory", -0x4550, 0x60B0475, 0x60B058B),
    # statistics: temp -0x4550, offset 0x60b05cd, move 0x60b06b6
    (-0x398, "statistics", -0x4550, 0x60B05CD, 0x60B06B6),
]

IMM_MOV = re.compile(r"mov[q|l]\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")
REG_MOV_SLOT = re.compile(r"mov\s+%(\w+),(-0x[0-9a-f]+)\(%rbp\)")
LOAD_RODATA = re.compile(
    r"mov\s+.*\(%rip\),%(\w+)\s+#\s*([0-9a-f]+)")
MOV_IMM_REG = re.compile(r"mov\s+\$0x([0-9a-f]+),%(\w+)\b")
XOR_REG = re.compile(r"xor\s+%(\w+),%\1\b")
LEA_RIP = re.compile(r"lea\s+.*\(%rip\),%(\w+)\s+#\s*([0-9a-f]+)")


def resolve_reg(lines, idx, reg):
    """Value of %reg at lines[idx]: immediate, or a .rodata qword load.

    Scans backward for the last write to the register.  Callee-saved
    registers (%r12-%r15, %rbx, %rbp) survive calls, so calls do not stop
    the scan; the nearest preceding write wins.
    Returns ("imm", v) / ("qword", addr, v) / ("?", None).
    """
    for j in range(idx - 1, max(0, idx - 200), -1):
        ln = lines[j]
        m = MOV_IMM_REG.search(ln)
        if m and m.group(2) == reg:
            return ("imm", int(m.group(1), 16))
        m = XOR_REG.search(ln)
        if m and m.group(1) == reg:
            return ("imm", 0)
        m = LOAD_RODATA.search(ln)
        if m and m.group(1) == reg:
            addr = int(m.group(2), 16)
            return ("qword", addr, rodata_qword(addr))
    return ("?", None)


def temp_fields(lines, temp, lo, hi):
    """(offset, type, verif, flags) of the value temp built in [lo, hi)."""
    off = tv = fl = None
    for i, ln in enumerate(lines):
        a = ADDR.match(ln)
        if not a:
            continue
        addr = int(a.group(1), 16)
        if addr < lo or addr >= hi:
            continue
        m = IMM_MOV.search(ln)
        if m:
            slot = int(m.group(2), 16)
            v = int(m.group(1), 16)
            if slot == temp:
                off = v
            elif slot == temp + 0xA8:
                tv = v
            elif slot == temp + 0xB0:
                fl = v
            continue
        m = REG_MOV_SLOT.search(ln)
        if m:
            slot = int(m.group(2), 16)
            if slot in (temp + 0xA8, temp + 0xB0):
                kind = resolve_reg(lines, i, m.group(1))
                v = kind[-1]
                if slot == temp + 0xA8:
                    tv = v
                else:
                    fl = v
    if tv is None:
        raise ValueError(f"temp -0x{-temp:x}: typeverif not resolved")
    return off, tv & 0xFFFFFFFF, tv >> 32, fl


def mid_helper_fields(lines, helper):
    """(offset, flags, enum_map) from a mid-helper call site."""
    for i, ln in enumerate(lines):
        if re.search(rf"call\s+{helper:x}\b", ln):
            off = fl = mp = None
            for j in range(max(0, i - 14), i):
                m = re.search(r"mov\s+\$0x([0-9a-f]+),%esi\b", lines[j])
                if m:
                    off = int(m.group(1), 16)
                m = re.search(r"mov\s+\$0x([0-9a-f]+),%ecx\b", lines[j])
                if m:
                    fl = int(m.group(1), 16)
                if re.search(r"xor\s+%ecx,%ecx", lines[j]):
                    fl = 0
                m = LEA_RIP.search(lines[j])
                if m and m.group(1) == "rdx":
                    mp = int(m.group(2), 16)
            # The helper hardcodes typeverif 0x12 (type 18, verif 0);
            # verified in helper-mid*-60a64d0.objdump.txt:
            #   movq $0x12,0xa8(%rax) ; mov %ecx,0xb0(%rax)
            return off, 18, 0, fl, mp
    raise ValueError(f"mid-helper call 0x{helper:x} not found")


def main():
    lines = lines_of(SRC)
    # Each region runs from its start up to (exclusive) its range-ctor
    # call: the pairs are built before the call.  ec0 begins at the first
    # lea -0x4490 (0x60aa406); the later maps begin right after the
    # previous range-ctor call.
    starts = {0x60AA4C2: 0x60AA406}
    for i, (call, _) in enumerate(RANGE_CTORS):
        if i:
            starts[call] = RANGE_CTORS[i - 1][0]
    regs = None
    with open(HERE / "enum_maps.tsv", "w") as f:
        f.write("map\tpair_index\tname\tvalue\tpair_slot\n")
        for i, (call, tag) in enumerate(RANGE_CTORS):
            pairs, regs = enum_map_pairs(lines, starts[call], call, regs)
            print(f"enum map 0x6506{tag}: {len(pairs)} pairs "
                  f"(range-ctor call 0x{call:x})")
            for j, (slot, name, val) in enumerate(pairs):
                print(f"  [{j}] {name} = {val}  (slot -0x{-slot:x})")
                f.write(f"0x6506{tag}\t{j}\t{name}\t{val}\t"
                        f"-0x{-slot:x}\n")
    # --- special pairs ---
    rows = []
    for helper, key in MID_HELPERS.items():
        off, typ, ver, fl, mp = mid_helper_fields(lines, helper)
        rows.append((key, off, typ, ver, fl, f"mid-helper 0x{helper:x}",
                     f"enum-map 0x{mp:x}"))
    for slot, key, temp, lo, hi in TEMP_BUILDS:
        off, typ, ver, fl = temp_fields(lines, temp, lo, hi)
        rows.append((key, off, typ, ver, fl,
                     f"value temp -0x{-temp:x} (build 0x{lo:x}..0x{hi:x})",
                     ""))
    rows.sort(key=lambda r: r[1] if r[1] is not None else -1)
    with open(HERE / "special_pairs.tsv", "w") as f:
        f.write("key\toffset\ttype\tverification\tflags\t"
                "value_source\tenum_map\n")
        for key, off, typ, ver, fl, src, mp in rows:
            print(f"special {key}: off=0x{off:x} type={typ} verif={ver} "
                  f"flags=0x{fl:x} [{src}] {mp}")
            f.write(f"{key}\t0x{off:x}\t{typ}\t{ver}\t0x{fl:x}\t{src}\t{mp}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
