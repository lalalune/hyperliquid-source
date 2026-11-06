"""Reproduce the reference census for the
RE-001-skiplist-holder-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-skiplist-holder-115/census.py

Method (same as the RE-001-table-factory-role9-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address: the two ":" setters are
    reached only through such lea references from the registry
    builder 0x6195290 (no direct call, no stored qword, no
    RELATIVE record installs them).
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and relocations.txt (the RELATIVE records installing the two
factory vtable groups, the two control-block vtable groups and
the four typeinfo objects) into this packet directory.
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
    0x6064440: (0x6064440, 0x6064551),  # SkipListFactory ctor (holder)
    0x6099CE0: (0x6099CE0, 0x6099E34),  # record-vector push-back
    0x60B3C30: (0x60B3C30, 0x60B3EEB),  # options base init
    0x5D946B0: (0x5D946B0, 0x5D9518D),  # options validation / factory replace
    0x61935B0: (0x61935B0, 0x6193791),  # ":" setter, SkipListFactory arm
    0x6193390: (0x6193390, 0x6193559),  # ":" setter, HashLinkListRepFactory arm
    0x605F150: (0x605F150, 0x605F28E),  # HashLinkListRepFactory ctor
    0x5D350C0: (0x5D350C0, 0x5D35145),  # shared release helper
    0x6195290: (0x6195290, 0x619686D),  # factory registry builder
    0x6192860: (0x6192860, 0x619288D),  # skip_list registry accessor
    0x6192890: (0x6192890, 0x61928BD),  # hash_linkedlist registry accessor
    0x61D1EF0: (0x61D1EF0, 0x61D1EF9),  # decimal-parse stub -> 0x61D1540
    0x61D1540: (0x61D1540, 0x61D174B),  # decimal parser (K/M/G/T suffixes)
    # Direct callees of the pinned routines (PLT stubs).
    0x63F0DD0: (0x63F0DD0, 0x63F0DE0),  # operator new
    0x63F0D80: (0x63F0D80, 0x63F0D90),  # operator delete
    0x63F0E10: (0x63F0E10, 0x63F0E20),  # basic_string::_M_create
    0x63F0A80: (0x63F0A80, 0x63F0A90),  # strlen
    0x63F0AA0: (0x63F0AA0, 0x63F0AB0),  # memcmp
    0x63F0D70: (0x63F0D70, 0x63F0D80),  # __stack_chk_fail
    0x63F0FA0: (0x63F0FA0, 0x63F0FB0),  # basic_string::find
    0x63F0A60: (0x63F0A60, 0x63F0A70),  # memcpy
    0x63F0DB0: (0x63F0DB0, 0x63F0DC0),  # basic_string::_M_dispose
    0x63F1040: (0x63F1040, 0x63F1050),  # __throw_out_of_range_fmt
    0x63F0A50: (0x63F0A50, 0x63F0A60),  # _Unwind_Resume
    0x63F0F00: (0x63F0F00, 0x63F0F10),  # basic_string::_M_assign
}

# No pinned routine is installed by a RELATIVE record: the
# holder ctor, the setters, the registry builder and the
# accessors are reached only by direct calls or lea references,
# and the PLT stubs only by direct calls. (Verified by the
# census run: every target below reports relative=0, except
# 0x6063640 which is NOT a census target here.)
RELOCATED = set()

# RELATIVE records kept in relocations.txt: every record whose
# r_offset lies in one of these ranges (the two factory vtable
# groups, the two shared_ptr control-block vtable groups, and
# the three typeinfo objects). Each vtable range covers the
# offset-to-top/typeinfo slots (vptr-0x10/-0x08) and the
# installed function slots; the typeinfo ranges cover the
# name-pointer slot (ti+0x08).
RELOCATION_RANGES = [
    (0x64D27A0, 0x64D2868),  # SkipListFactory vtable group (ti + 23 slots)
    (0x64D2220, 0x64D22E8),  # HashLinkListRepFactory vtable group (ti + 23)
    (0x64D3770, 0x64D37A8),  # _Sp_counted_ptr<SkipListFactory*> vtable group
    (0x64C9BF0, 0x64C9C30),  # _Sp_counted_ptr_inplace control vtable group
    (0x64D25A8, 0x64D25B8),  # SkipListFactory typeinfo
    (0x64D2068, 0x64D2078),  # HashLinkListRepFactory typeinfo
    (0x64D3728, 0x64D3738),  # _Sp_counted_ptr<SkipListFactory*> typeinfo
    (0x64C99C0, 0x64C99D0),  # _Sp_counted_ptr_inplace typeinfo
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
