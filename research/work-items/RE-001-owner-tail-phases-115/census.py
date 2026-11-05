"""Reproduce the reference census for the
RE-001-owner-tail-phases-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-owner-tail-phases-115/census.py

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
and relocations.txt (the RELATIVE records installing the two
FragmentedRangeTombstoneListCache control vtables, their
typeinfo objects and name pointers, the SkipListRep vtable
group for the slot-15 stub, and the GOT entries for the big
caller's canonical check and the owner dispatch) into this
packet directory.

Routines already mapped by merged PRs are census targets only
(the +0xd10 table init 0x5f0b420 in RE-001-shared-table-resize-115,
the arena slot-3 AllocateAligned 0x5f117a0 in #2160, the arena
init 0x605e010 / huge-align 0x605cfa0 / small init 0x605e810 in
#3286, the factory 0x6063640 in #3286 and the holder ctor
0x6064440 in #3272); this packet cites them, it does not
re-ship their excerpts. The release helper 0x5d350c0, the
destroy dispatch 0x5d35070 and the release-loop helper
0x5f0a1dc are cited from RE-001-shared-table-resize-115 and
earlier packets.
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
    0x5F103F0: (0x5F103F0, 0x5F10CF8),  # owner function (whole)
    0x60D5880: (0x60D5880, 0x60D5917),  # rwlock element ctor
    0x5F07490: (0x5F07490, 0x5F074D3),  # once-flag helper
    0x5F07300: (0x5F07300, 0x5F07481),  # once predicate
    0x5F07230: (0x5F07230, 0x5F072F6),  # prologue helper
    0x61C26F0: (0x61C26F0, 0x61C27A8),  # small-install descriptor
    0x5F0A290: (0x5F0A290, 0x5F0A319),  # small-control _M_dispose
    0x5D8CA00: (0x5D8CA00, 0x5D8CA6A),  # small owner caller
    0x5ED01F0: (0x5ED01F0, 0x5ED2238),  # big owner caller (window only)
    0x6062FB0: (0x6062FB0, 0x6062FB7),  # SkipListRep slot-15 zero stub
    # Control-vtable slot functions (census only except 0x5f0a290).
    0x5F04E20: (0x5F04E20, 0x5F04E25),  # small slot 0 (trivial dtor)
    0x5F04E30: (0x5F04E30, 0x5F04E35),  # big slot 0 (trivial dtor)
    0x5F04E50: (0x5F04E50, 0x5F04E5E),  # big slot 1 (deleting dtor)
    0x5F04E60: (0x5F04E60, 0x5F04E6E),  # small slot 1 (deleting dtor)
    0x5F04F60: (0x5F04F60, 0x5F04F6E),  # small slot 3 (_M_destroy)
    0x5F04F70: (0x5F04F70, 0x5F04F7E),  # big slot 3 (_M_destroy)
    0x5F05380: (0x5F05380, 0x5F053C7),  # small slot 4 (_M_get_deleter)
    0x5F057C0: (0x5F057C0, 0x5F05807),  # big slot 4 (_M_get_deleter)
    0x5F061B0: (0x5F061B0, 0x5F06548),  # big slot 2 (_M_dispose)
    # Merged / cited ground, census only (see docstring).
    0x5F0B420: (0x5F0B420, 0x5F0B5D2),  # +0xd10 table init
    0x6063640: (0x6063640, 0x6063752),  # SkipListFactory slot-19 (#3286)
    0x6064440: (0x6064440, 0x6064551),  # holder ctor (#3272)
    0x605E010: (0x605E010, 0x605E163),  # ConcurrentArena init (#3286)
    0x605CFA0: (0x605CFA0, 0x605CFD6),  # huge-page align (#3286)
    0x605E810: (0x605E810, 0x605E826),  # small +0x80 init (#3286)
    0x5F117A0: (0x5F117A0, 0x5F11C38),  # arena slot-3 AllocateAligned (#2160)
    0x5D35070: (0x5D35070, 0x5D350BC),  # destroy dispatch (cited)
    0x5D350C0: (0x5D350C0, 0x5D35145),  # release helper (cited)
    0x5F0A1DC: (0x5F0A1DC, 0x5F0A287),  # release-loop helper (cited)
    0x61D1F30: (0x61D1F30, 0x61D2215),  # strerror-string builder
    # Direct callees of the pinned routines (PLT stubs).
    0x63F0DD0: (0x63F0DD0, 0x63F0DE0),  # operator new
    0x63F0D80: (0x63F0D80, 0x63F0D90),  # operator delete
    0x63F0D70: (0x63F0D70, 0x63F0D80),  # __stack_chk_fail
    0x63F0A50: (0x63F0A50, 0x63F0A60),  # _Unwind_Resume
    0x63F0DE0: (0x63F0DE0, 0x63F0DF0),  # __throw_length_error
    0x63F0A90: (0x63F0A90, 0x63F0AA0),  # memset
    0x63F1820: (0x63F1820, 0x63F1830),  # pthread_rwlock_init
    0x63F1400: (0x63F1400, 0x63F1410),  # __fprintf_chk
    0x63F0DB0: (0x63F0DB0, 0x63F0DC0),  # basic_string::_M_dispose
    0x63F0BF0: (0x63F0BF0, 0x63F0C00),  # abort
    0x63F1380: (0x63F1380, 0x63F1390),  # _Sp_locker C1
    0x63F1390: (0x63F1390, 0x63F13A0),  # _Sp_locker D1
}

# Pinned routines installed by RELATIVE records: the two
# FragmentedRangeTombstoneListCache control vtables' slot
# functions, the SkipListRep slot-15 stub, the arena slot-3
# AllocateAligned and the +0xd10 table init.
RELOCATED = {0x5F04E20, 0x5F04E30, 0x5F04E50, 0x5F04E60,
             0x5F04F60, 0x5F04F70, 0x5F05380, 0x5F057C0,
             0x5F061B0, 0x5F0A290, 0x6062FB0, 0x5F117A0,
             0x5F0B420}


RELOCATION_RANGES = [
    (0x64CC708, 0x64CC778),  # big + small control vtable groups
    (0x64CC590, 0x64CC5C8),  # the two control typeinfo objects
    (0x64D26D8, 0x64D27A8),  # SkipListRep vtable group (slot 15)
    (0x64ECFD0, 0x64ECFD8),  # GOT canonical entry (big caller)
    (0x64ED780, 0x64ED788),  # GOT canonical slot-20 entry (owner)
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
