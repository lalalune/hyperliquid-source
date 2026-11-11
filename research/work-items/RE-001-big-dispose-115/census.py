"""Reproduce the reference census for the
RE-001-big-dispose-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-big-dispose-115/census.py

Method (same as the RE-001-owner-tail-phases-115 packet):
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
FragmentedRangeTombstoneListCache control vtables and their
typeinfo objects) into this packet directory.

Routines already mapped by merged PRs are census targets only
(the sorted-unique clear 0x5d50470 in
RE-001-sorted-unique-clear-50470-115, the small-control
_M_dispose 0x5f0a290 in #3304, the release helper 0x5d350c0
and destroy dispatch 0x5d35070 in #3263/#3304); this packet
cites them, it does not re-ship their excerpts. The sort
callees of the merged 0x5d50470 routine (0x5d4a3f0/0x5d497e0)
are census targets too, to record that the dispose's own
sort callees (0x5f053d0/0x5f05120) are a different
instantiation.
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
    0x5F061B0: (0x5F061B0, 0x5F06548),  # big-control _M_dispose
    0x5F053D0: (0x5F053D0, 0x5F05678),  # __introsort_loop
    0x5F05120: (0x5F05120, 0x5F051F5),  # __insertion_sort
    0x5F04F80: (0x5F04F80, 0x5F0511D),  # __adjust_heap
    0x5F059B0: (0x5F059B0, 0x5F05B79),  # tree destroy
    0x61BD0E0: (0x61BD0E0, 0x61BD131),  # Cleanable drain
    0x61BD0C0: (0x61BD0C0, 0x61BD0D4),  # Cleanable init
    # Cited / merged ground, census only (see docstring).
    0x5D50470: (0x5D50470, 0x5D506A8),  # sorted-unique clear
    0x5D4A3F0: (0x5D4A3F0, 0x5D4A698),  # 0x5d50470 introsort callee
    0x5D497E0: (0x5D497E0, 0x5D498B5),  # 0x5d50470 insertion callee
    0x5D35070: (0x5D35070, 0x5D350BC),  # destroy dispatch (cited)
    0x5D350C0: (0x5D350C0, 0x5D35145),  # release helper (cited)
    0x5F0A1DC: (0x5F0A1DC, 0x5F0A287),  # release-loop helper (cited)
    0x5F0A290: (0x5F0A290, 0x5F0A319),  # small-control _M_dispose
    # Control-vtable slot functions (census only except 0x5f061b0).
    0x5F04E20: (0x5F04E20, 0x5F04E25),  # small slot 0 (trivial dtor)
    0x5F04E30: (0x5F04E30, 0x5F04E35),  # big slot 0 (trivial dtor)
    0x5F04E50: (0x5F04E50, 0x5F04E5E),  # big slot 1 (deleting dtor)
    0x5F04E60: (0x5F04E60, 0x5F04E6E),  # small slot 1 (deleting dtor)
    0x5F04F60: (0x5F04F60, 0x5F04F6E),  # small slot 3 (_M_destroy)
    0x5F04F70: (0x5F04F70, 0x5F04F7E),  # big slot 3 (_M_destroy)
    0x5F05380: (0x5F05380, 0x5F053C7),  # small slot 4 (_M_get_deleter)
    0x5F057C0: (0x5F057C0, 0x5F05807),  # big slot 4 (_M_get_deleter)
    0x5F117A0: (0x5F117A0, 0x5F11C38),  # arena slot-3 AllocateAligned (#2160)
    # Direct callees of the pinned routines (PLT stubs).
    0x63F0D80: (0x63F0D80, 0x63F0D90),  # operator delete
}

# Pinned routines installed by RELATIVE records: the two
# FragmentedRangeTombstoneListCache control vtables' slot
# functions, the SkipListRep slot-15 stub, the arena slot-3
# AllocateAligned and the +0xd10 table init.
RELOCATED = {0x5F04E20, 0x5F04E30, 0x5F04E50, 0x5F04E60,
             0x5F04F60, 0x5F04F70, 0x5F05380, 0x5F057C0,
             0x5F061B0, 0x5F0A290}


RELOCATION_RANGES = [
    (0x64CC708, 0x64CC778),  # big + small control vtable groups
    (0x64CC590, 0x64CC5C8),  # the two control typeinfo objects
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
