#!/usr/bin/env python3
"""Census for RE-001-iterator-vtable-tail-115.

Part 1 -- vtable enumeration. `.data.rel.ro` is zero-filled in the
file, so every vtable slot value comes from a `.rela.dyn`
R_X86_64_RELATIVE entry. Scanning those entries for the nine shared
tail stubs (the base-class defaults) and back-computing each vtable's
stored pointer enumerates every InternalIterator vtable; the typeinfo
pointer (stored_ptr - 8) names the class. Writes vtables_all.txt
(all 24 slots per candidate), windows.txt (distinct tail-window
functions) and tail_table.tsv (slots [11], [14]-[23]).

Part 2 -- dispatch-site census. Scans .text for indirect call/jmp
encodings through each tail slot offset, verifies every candidate by
disassembling its containing FDE from the FDE start, and keeps only
the sites whose containing FDE is an iterator consumer: either the
FDE is itself one of the tail windows (a wrapper delegation), or it
dispatches through Valid (0x10) and key (0x50) plus at least two more
core InternalIterator slots. Offsets 0x98/0xa0/0xb0 are shared with
other hierarchies, so the core-slot bar is what separates a real
InternalIterator dispatch from a same-offset dispatch through another
class's vtable. Writes callers.tsv.

Part 3 -- relocations. Writes relocations.txt: the .rela.dyn
R_X86_64_RELATIVE entries whose offset falls inside any of the 21
real vtables (typeinfo slot at stored_ptr - 8 plus slots 0-23), i.e.
the relocation evidence each vtable entry is built from.

Usage (from the repository root):
    python3 research/work-items/RE-001-iterator-vtable-tail-115/census.py

The binary must be present at work/hl-node-115.bin. Outputs land in
this directory.
"""
import bisect
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700
VA_BASE = 0x1000  # file offset -> VA for .text

SHARED = {
    0x5DF7650: 11,
    0x5DF7670: 14,
    0x5DF7680: 15,
    0x5DF7690: 16,
    0x5D485B0: 17,
    0x5DF7800: 20,
    0x5DF76D0: 21,
    0x5DF76E0: 22,
    0x5DF7640: 23,
}
FALSE_POSITIVES = {0x64ECE78, 0x64ED2A8, 0x64ED2D0, 0x64ED2F8, 0x64ED308}
SLOTS = {
    0x58: 11, 0x70: 14, 0x78: 15, 0x80: 16, 0x88: 17, 0x90: 18,
    0x98: 19, 0xA0: 20, 0xA8: 21, 0xB0: 22, 0xB8: 23,
}
CORE = {0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x50, 0x60, 0x68}

SEGMENTS = [
    (0x0000000, 0x1418254, 0x0000000),
    (0x1419300, 0x4FD88A0, 0x1418300),
    (0x63F2BA0, 0x000FBE80, 0x63F0BA0),
    (0x64EFA20, 0x000103E8, 0x64ECA20),
]


def va_to_off(va):
    for start, size, off in SEGMENTS:
        if start <= va < start + size:
            return off + (va - start)
    return None


def read_cstr(data, va, limit=200):
    off = va_to_off(va)
    if off is None:
        return None
    end = data.index(b"\x00", off, off + limit)
    return data[off:end].decode("ascii", "replace")


def enumerate_vtables(data):
    rel = {}
    n = RELA_SIZE // 24
    for i in range(n):
        off, info, add = struct.unpack_from("<QQq", data, RELA_OFF + i * 24)
        if (info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
            rel[off] = add
    vtables = {}
    for va, add in rel.items():
        if add in SHARED:
            slot = SHARED[add]
            ptr = va - slot * 8
            vtables.setdefault(ptr, set()).add((slot, add))
    out = [f"RELATIVE entries: {len(rel)}",
           f"candidate iterator vtables: {len(vtables)}", ""]
    real = {}
    for ptr in sorted(vtables):
        ti_va = rel.get(ptr - 8)
        name = None
        if ti_va is not None:
            name_va = rel.get(ti_va + 8)
            if name_va is not None:
                name = read_cstr(data, name_va)
        slots = [rel.get(ptr + 8 * i) for i in range(24)]
        shared_hits = sorted(vtables[ptr])
        out.append(
            f"=== vtable stored_ptr 0x{ptr:x} typeinfo={name} "
            f"(shared-stub slots: {[s for s, _ in shared_hits]})")
        for i, t in enumerate(slots):
            mark = "  <== shared stub" if t in SHARED else ""
            out.append(f"  [{i:2d}] 0x{t:x}" if t is not None
                       else f"  [{i:2d}] ???")
            out[-1] += mark
        out.append("")
        if ptr not in FALSE_POSITIVES:
            real[ptr] = (name, slots)
    (HERE / "vtables_all.txt").write_text("\n".join(out))
    windows = {}
    rows = []
    for ptr, (name, slots) in sorted(real.items()):
        for slot in (11, *range(14, 24)):
            addr = slots[slot]
            if addr is None:
                continue
            rows.append((name, slot, addr))
            windows.setdefault(addr, set()).add((name, slot))
    with open(HERE / "windows.txt", "w") as f:
        for a in sorted(windows):
            f.write(f"0x{a:x}\t" + "; ".join(
                f"{c}[{s}]" for c, s in sorted(windows[a])) + "\n")
    with open(HERE / "tail_table.tsv", "w") as f:
        f.write("class\tslot\taddress\n")
        for cls, slot, addr in sorted(rows, key=lambda r: (r[0], r[1])):
            f.write(f"{cls}\t{slot}\t0x{addr:x}\n")
    print(f"vtables: {len(real)} real (+{len(vtables) - len(real)} "
          f"false positives excluded), {len(windows)} distinct windows, "
          f"{len(rows)} tail rows", file=sys.stderr)
    return set(windows)


def load_fdes():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    pat = re.compile(
        r"^[0-9a-f]{8} [0-9a-f]{16} [0-9a-f]{8} FDE cie=[0-9a-f]+ "
        r"pc=([0-9a-f]+)\.\.([0-9a-f]+)")
    for line in out.splitlines():
        m = pat.match(line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing_fde(fdes, starts, va):
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
        return fdes[i]
    return None


def scan_dispatch(data):
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    cands = {off: [] for off in SLOTS}
    n = len(text)
    for i in range(n - 2):
        if text[i] != 0xFF:
            continue
        b1 = text[i + 1]
        if 0x50 <= b1 <= 0x57 or 0x60 <= b1 <= 0x67:
            d = text[i + 2]
            if d in (0x58, 0x70, 0x78):
                cands[d].append(TEXT_OFF + i + VA_BASE)
    for i in range(n - 5):
        if text[i] != 0xFF:
            continue
        b1 = text[i + 1]
        if 0x90 <= b1 <= 0x97 or 0xA0 <= b1 <= 0xA7:
            d = int.from_bytes(text[i + 2:i + 6], "little")
            if d in (0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8):
                cands[d].append(TEXT_OFF + i + VA_BASE)
    return cands


def disasm(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(BIN)],
        capture_output=True, text=True).stdout
    instr = {}
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t", line)
        if m:
            instr[int(m.group(1), 16)] = line
    return instr


def dispatch_census(data, windows):
    fdes = load_fdes()
    starts = [s for s, _ in fdes]
    cands = scan_dispatch(data)
    by_fde = {}
    for off, vas in cands.items():
        for va in vas:
            fde = containing_fde(fdes, starts, va)
            if fde is None:
                continue
            by_fde.setdefault(fde, []).append((off, va))
    kept = []
    raw = 0
    for (start, end), items in sorted(by_fde.items()):
        instr = disasm(start, end)
        core_seen = set()
        verified = []
        for off, va in items:
            line = instr.get(va)
            if line is None:
                continue
            m = re.search(rf"\b(call|jmp)\s+\*0x{off:x}\(%(\w+)\)", line)
            if m:
                verified.append((off, va, m.group(1), m.group(2)))
        raw += len(verified)
        if not verified:
            continue
        for va, line in instr.items():
            m = re.search(r"\b(call|jmp)\s+\*0x([0-9a-f]+)\(%", line)
            if m and int(m.group(2), 16) in CORE:
                core_seen.add(int(m.group(2), 16))
        is_window = start in windows
        if is_window or (0x10 in core_seen and 0x50 in core_seen
                         and len(core_seen) >= 4):
            for off, va, kind, reg in verified:
                kept.append((SLOTS[off], off, va, start, kind, reg,
                             ",".join(f"0x{c:x}" for c in sorted(core_seen)),
                             "window" if is_window else "consumer"))
    kept.sort()
    with open(HERE / "callers.tsv", "w") as f:
        f.write("slot\tslot_offset\tsite\tcontaining_fde\tkind\tregister\t"
                "core_slots_in_fde\tevidence\n")
        for slot, off, va, fde, kind, reg, core, ev in kept:
            f.write(f"{slot}\t0x{off:x}\t0x{va:x}\t0x{fde:x}\t{kind}\t%{reg}\t"
                    f"{core}\t{ev}\n")
    print(f"dispatch: {raw} verified sites, {len(kept)} kept "
          f"iterator-consumer sites", file=sys.stderr)


def export_relocations(data, ptrs):
    """The .rela.dyn entries backing the 21 real vtables."""
    rel = {}
    n = RELA_SIZE // 24
    for i in range(n):
        off, info, add = struct.unpack_from("<QQq", data, RELA_OFF + i * 24)
        if (info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
            rel[off] = add
    lines = ["offset\ttype\taddend\tslot\n"]
    count = 0
    for ptr in sorted(ptrs):
        for slot in range(-1, 24):
            off = ptr + slot * 8
            if off in rel:
                lines.append(f"0x{off:x}\tR_X86_64_RELATIVE\t"
                             f"0x{rel[off]:x}\t"
                             f"{'typeinfo' if slot == -1 else slot}\n")
                count += 1
    (HERE / "relocations.txt").write_text("".join(lines))
    print(f"relocations: {count} entries for {len(ptrs)} vtables",
          file=sys.stderr)


def main():
    data = open(BIN, "rb").read()
    windows = enumerate_vtables(data)
    # stored_ptrs of the 21 real vtables, for the relocation export
    ptrs = set()
    for line in open(HERE / "vtables_all.txt"):
        m = re.match(r"=== vtable stored_ptr (0x[0-9a-f]+) typeinfo=(\S+)",
                     line)
        if m and int(m.group(1), 16) not in FALSE_POSITIVES:
            ptrs.add(int(m.group(1), 16))
    export_relocations(data, ptrs)
    dispatch_census(data, windows)


if __name__ == "__main__":
    main()
