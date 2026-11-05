"""Reproduce the reference census for the
RE-001-skiplist-rep-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-rep-factory-115/census.py

Method (same as the RE-001-skiplist-rep-factory-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and relocations.txt (the RELATIVE records installing the three
vtable groups, the four typeinfo objects, their base-class
pointers, the GOT canonical slot-20 entry and the neighbouring
base-class typeinfo name pointers) into this packet directory.

Routines already mapped by merged PRs are census targets only
(slot-2 allocate 0x5f11c40 in #2170, slot-3 AllocateAligned
0x5f117a0 in #2160, slow-path 0x605d7b0 in #2150, destructor pair
0x5f10180/0x5f10d00 and member destructor 0x605cc30 in #2133);
this packet cites them, it does not re-ship their excerpts.
"""

import bisect
import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    0x6063640: (0x6063640, 0x6063752),  # SkipListFactory slot-19 factory
    0x6064440: (0x6064440, 0x6064551),  # SkipListFactory ctor (holder)
    0x605E010: (0x605E010, 0x605E163),  # ConcurrentArena init
    0x605DD90: (0x605DD90, 0x605DFCD),  # ConcurrentArena +0x60 sub-init
    0x605E810: (0x605E810, 0x605E826),  # small +0x80 init
    0x605CFA0: (0x605CFA0, 0x605CFD6),  # huge-page align helper
    0x5F04DA0: (0x5F04DA0, 0x5F04DAC),  # ConcurrentArena slot-4 stat
    0x5F04D90: (0x5F04D90, 0x5F04D9D),  # canonical slot-20 forwarder
    0x5F04D80: (0x5F04D80, 0x5F04D8D),  # SkipListRep slot-20 forwarder
    0x5F04D50: (0x5F04D50, 0x5F04D55),  # SkipListRep slot-10 no-op
    0x5F04D60: (0x5F04D60, 0x5F04D65),  # SkipListRep slot-11 no-op
    0x5F103F0: (0x5F103F0, 0x5F10CF8),  # owner function (dispatch site)
    # Merged ground, census only (see docstring).
    0x5F117A0: (0x5F117A0, 0x5F11C38),  # ConcurrentArena slot-3 (#2160)
    0x5F11C40: (0x5F11C40, 0x5F12162),  # ConcurrentArena slot-2 (#2170)
    0x605D7B0: (0x605D7B0, 0x605D926),  # slow-path block alloc (#2150)
    0x605E170: (0x605E170, 0x605E20D),  # shard refill (referenced)
    0x605CC30: (0x605CC30, 0x605CF73),  # +0x60 member dtor (#2133)
    0x5F10180: (0x5F10180, 0x5F101B2),  # ConcurrentArena dtor (#2133)
    0x5F10D00: (0x5F10D00, 0x5F10D3C),  # ConcurrentArena sized dtor (#2133)
    # Direct callees of the pinned routines (PLT stubs).
    0x63F0DD0: (0x63F0DD0, 0x63F0DE0),  # operator new
    0x63F0D80: (0x63F0D80, 0x63F0D90),  # operator delete
    0x63F0E10: (0x63F0E10, 0x63F0E20),  # basic_string::_M_create
    0x63F0E30: (0x63F0E30, 0x63F0E40),  # operator new[] (_Znam)
    0x63F0DC0: (0x63F0DC0, 0x63F0DD0),  # operator delete[] (_ZdaPv)
    0x63F13A0: (0x63F13A0, 0x63F13B0),  # hardware_concurrency
    0x63F13B0: (0x63F13B0, 0x63F13C0),  # ConcurrentArena tls_cpuid
    0x63F0B20: (0x63F0B20, 0x63F0B30),  # sched_yield
    0x63F0D70: (0x63F0D70, 0x63F0D80),  # __stack_chk_fail
    0x63F0A50: (0x63F0A50, 0x63F0A60),  # _Unwind_Resume
    0x63F0F90: (0x63F0F90, 0x63F0FA0),  # __throw_system_error
    0x63F0DE0: (0x63F0DE0, 0x63F0DF0),  # __throw_length_error
    0x63F0A60: (0x63F0A60, 0x63F0A70),  # memcpy
    0x63F1040: (0x63F1040, 0x63F1050),  # __throw_out_of_range_fmt
    0x63F0DB0: (0x63F0DB0, 0x63F0DC0),  # basic_string::_M_dispose
    0x63F0FA0: (0x63F0FA0, 0x63F0FB0),  # basic_string::find
    0x63F0A80: (0x63F0A80, 0x63F0A90),  # strlen
    0x63F0AA0: (0x63F0AA0, 0x63F0AB0),  # memcmp
    0x63F0F00: (0x63F0F00, 0x63F0F10),  # basic_string::_M_assign
}

# Pinned routines installed by RELATIVE records: the factory
# (SkipListFactory slot 19), the canonical slot-20 forwarder
# (SkipListFactory slot 20 and the GOT canonical entry), the
# SkipListRep slot-20 forwarder and no-op slots 10/11, the
# ConcurrentArena slots 0-4, the embedded Arena slots 0 and 3.
# The remaining pinned routines are reached only by direct calls.
RELOCATED = {0x6063640, 0x5F04D90, 0x5F04D80, 0x5F04D50, 0x5F04D60,
             0x5F04DA0, 0x5F117A0, 0x5F11C40, 0x5F10180, 0x5F10D00,
             0x605D7B0, 0x605CC30}


RELOCATION_RANGES = [
    (0x64D26D8, 0x64D27A0),  # SkipListRep vtable group (ti + 23 slots)
    (0x64D27A0, 0x64D2868),  # SkipListFactory vtable group (ti + 23 slots)
    (0x64CC5C8, 0x64CC600),  # ConcurrentArena vtable group (ti + 5 slots)
    (0x64D1FB0, 0x64D1FE0),  # embedded Arena vtable group (ti + 5 slots)
    (0x64D25F0, 0x64D2608),  # SkipListRep typeinfo (name + base)
    (0x64D25A8, 0x64D25C0),  # SkipListFactory typeinfo (name + base)
    (0x64CC550, 0x64CC568),  # ConcurrentArena typeinfo (name + base)
    (0x64D1F90, 0x64D1FA8),  # embedded Arena typeinfo (name + base)
    (0x64CC540, 0x64CC550),  # Allocator typeinfo (name)
    (0x64CC530, 0x64CC540),  # MemTableRep typeinfo (name)
    (0x64D1FE0, 0x64D2000),  # Iterator + MemTableRepFactory typeinfos
    (0x64ED780, 0x64ED788),  # GOT canonical slot-20 entry
    (0x64D3418, 0x64D34A0),  # Configurable vtable group (ti + 15 slots)
]


def exec_segments(data):
    """Return [(file offset, vaddr, file size)] of executable LOADs."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            out.append((p_offset, p_vaddr, p_filesz))
    if not out:
        raise SystemExit("no executable LOAD segment")
    return out


def disassembly_sites():
    """One objdump pass over every executable LOAD segment,
    streamed line by line, keeping direct call/jump lines and
    lea lines whose comment names a pinned routine. Returns
    {target: ([call sites], [jump sites], [lea sites])}."""
    sites = {}
    for _file_off, vaddr, filesz in exec_segments(BINARY.read_bytes()):
        proc = subprocess.Popen(
            ["objdump", "-d", "--no-show-raw-insn",
             "--start-address=%#x" % vaddr,
             "--stop-address=%#x" % (vaddr + filesz), str(BINARY)],
            stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if ("call" not in line and "jmp" not in line
                    and "lea" not in line):
                continue
            parts = line.split()
            if len(parts) < 3 or not parts[0].endswith(":"):
                continue
            try:
                site = int(parts[0][:-1], 16)
            except ValueError:
                continue
            mnemonic = parts[1]
            if mnemonic in ("call", "jmp"):
                target = parts[2]
                if not target or target[0] == "*":
                    continue
                try:
                    tgt = int(target, 16)
                except ValueError:
                    continue
                entry = sites.setdefault(tgt, ([], [], []))
                entry[0 if mnemonic == "call" else 1].append(site)
            elif mnemonic == "lea" and "#" in line:
                comment = line.split("#", 1)[1].strip()
                token = comment.split()[0]
                try:
                    tgt = int(token, 16)
                except ValueError:
                    continue
                entry = sites.setdefault(tgt, ([], [], []))
                entry[2].append(site)
        proc.wait()
        if proc.returncode != 0:
            raise SystemExit("objdump failed on segment %#x" % vaddr)
    for entry in sites.values():
        for lst in entry:
            lst.sort()
    return sites


def scan(sites, target):
    """(direct calls, tail jumps) for one target from a sites dict."""
    calls, jumps, _leas = sites.get(target, ([], [], []))
    return calls, jumps


def qwords(data, target):
    """File offsets holding target as an 8-byte-aligned qword."""
    needle = struct.pack("<Q", target)
    found = []
    pos = data.find(needle)
    while pos != -1:
        if pos % 8 == 0:
            found.append(pos)
        pos = data.find(needle, pos + 1)
    return found


def relative_records():
    """(offset -> addend) and raw lines for RELATIVE relocations."""
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    out = {}
    lines = []
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        typ = m.group(3)
        addend = m.group(4)
        if typ == "RELATIVE" and addend is not None:
            out[off] = int(addend, 16)
            lines.append(line)
    return out, lines


def frame_ranges():
    """All FDE pc ranges from a fresh frame dump."""
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def enclosing_fde(ordered, starts, value):
    """Smallest enclosing FDE for an address. `ordered` is the
    sorted FDE ranges and `starts` their starts, computed once by
    the caller (sorting per row would be O(rows x ranges))."""
    idx = bisect.bisect_right(starts, value) - 1
    cands = []
    for j in range(max(0, idx - 2), min(len(ordered), idx + 3)):
        a, b = ordered[j]
        if a <= value < b:
            cands.append((a, b))
    if not cands:
        cands = [(a, b) for a, b in ordered if a <= value < b]
    if not cands:
        raise SystemExit("no enclosing FDE for %#x" % value)
    a, b = min(cands, key=lambda ab: ab[1] - ab[0])
    return "%#x..%#x" % (a, b)


def main():
    data = BINARY.read_bytes()
    sites = disassembly_sites()
    relocs, reloc_lines = relative_records()
    ranges = frame_ranges()
    rows = []
    for target in sorted(TARGETS):
        calls, jumps, leas = sites.get(target, ([], [], []))
        qw = qwords(data, target)
        rel = sorted(o for o, a in relocs.items() if a == target)
        print("%#x calls=%d %s jumps=%d %s leas=%d %s qwords=%d %s relative=%d %s" % (
            target, len(calls),
            " ".join("%#x" % c for c in calls),
            len(jumps), " ".join("%#x" % j for j in jumps),
            len(leas), " ".join("%#x" % l for l in leas),
            len(qw), " ".join("%#x" % q for q in qw),
            len(rel), " ".join("%#x" % r for r in rel)))
        for site in calls:
            rows.append((site, target, "call"))
        for site in jumps:
            rows.append((site, target, "tail jump"))
        for site in leas:
            rows.append((site, target, "lea"))
    rows.sort()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    with open(PACKET / "callers.tsv", "w") as handle:
        handle.write("site\ttarget\tcaller\tkind\n")
        for site, target, kind in rows:
            handle.write("%#x\t%#x\t%s\t%s\n" % (
                site, target, enclosing_fde(ordered, starts, site), kind))
    kept = []
    for line in reloc_lines:
        parts = line.split()
        off = int(parts[0], 16)
        if any(lo <= off < hi for lo, hi in RELOCATION_RANGES):
            kept.append(line)
    with open(PACKET / "relocations.txt", "w") as handle:
        for line in kept:
            handle.write(line + "\n")
    print("relocations kept: %d" % len(kept))


if __name__ == "__main__":
    main()
