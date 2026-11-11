"""Reproduce the reference census for the
RE-001-record-insert-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-insert-115/census.py

Method (same as the RE-001-lazy-resolver-115 packet):
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
and relocations.txt (the RELATIVE records installing the
canonical product-slot targets in their GOT slots, plus the
two GOT slots holding the canonical 0x5d4b100) into this
packet directory.

Routines already mapped by earlier packets are census targets
and their excerpts are re-shipped byte-identical: the value
resolve-and-store 0x5f09e90 and the ProtectionInfo validation
0x5f09b10 (both merged ground), the once helper 0x5f07490 and
its predicate 0x5f07300 (#3304), the lazy resolver 0x5f074e0
and its canonical 0x5d4b100 (#3322), the release helper
0x5d350c0 (#3263) and the Status builder 0x61cf670 (#3251).
The sibling caller functions 0x5f0f930 and 0x5f0f3d0 are
census targets only: they call the same two helpers right
after each other, like this packet's main function does.
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
    0x5F0E890: (0x5F0E890, 0x5F0F37E),  # record insert (this packet)
    0x5F09E90: (0x5F09E90, 0x5F09FAF),  # value resolve-and-store (merged)
    0x5F09B10: (0x5F09B10, 0x5F09E84),  # ProtectionInfo validation (merged)
    0x5F0E660: (0x5F0E660, 0x5F0E85F),  # map find-or-insert (this packet)
    0x61C34A0: (0x61C34A0, 0x61C3525),  # 32-bit hash (this packet)
    0x61BD410: (0x61BD410, 0x61BD4E9),  # varint32 encoder (this packet)
    0x5F05310: (0x5F05310, 0x5F05379),  # record move-assign (this packet)
    0x5F07490: (0x5F07490, 0x5F074D3),  # once helper (re-shipped, #3304)
    0x5F07300: (0x5F07300, 0x5F07481),  # once predicate (re-shipped, #3304)
    0x5F074E0: (0x5F074E0, 0x5F07603),  # lazy resolver (re-shipped, #3322)
    0x5D4B100: (0x5D4B100, 0x5D4B20C),  # canonical chain-walk (re-shipped, #3322)
    0x5D350C0: (0x5D350C0, 0x5D35145),  # release helper (re-shipped, #3263)
    0x61CF670: (0x61CF670, 0x61CF767),  # Status builder (re-shipped, #3251)
    # Cited ground, census only (see docstring).
    0x5F0F930: (0x5F0F930, 0x5F10134),  # sibling caller function (cited)
    0x5F0F3D0: (0x5F0F3D0, 0x5F0F8C1),  # sibling caller function (cited)
}

# Routines installed by RELATIVE records: the canonical
# 0x5d4b100 in its two GOT slots, and the six product-slot
# canonical targets (forwarders) in their GOT slots.
RELOCATED = {
    0x5D4B100,
    0x5F04CF0,
    0x5F04D10,
    0x5F04D20,
    0x5F04D30,
    0x5F05740,
    0x5F05780,
}


RELOCATION_RANGES = [
    (0x64ED3E8, 0x64ED3F0),  # GOT slot for the canonical 0x5d4b100
    (0x64CDE48, 0x64CDE50),  # second GOT slot for the canonical
    (0x64ED748, 0x64ED750),  # GOT slot for product slot 0x10 target
    (0x64ED750, 0x64ED758),  # GOT slot for product slot 0x18 target
    (0x64ED758, 0x64ED760),  # GOT slot for product slot 0x28 target
    (0x64ED760, 0x64ED768),  # GOT slot for product slot 0x40 target
    (0x64ED798, 0x64ED7A0),  # GOT slot for product slot 0x20 target
    (0x64ED7A0, 0x64ED7A8),  # GOT slot for product slot 0x30 target
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
