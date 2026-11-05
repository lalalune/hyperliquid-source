"""Reproduce the reference census for the RE-001-stats-version-fetch-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-version-fetch-115/census.py

Method (same as the RE-001-stats-snapshot-insert-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site. The .text section is ~84 MB, so
    the full output (~21M lines) is never loaded whole.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the default produce 0x5d33a90 is
    installed at slot 0xe8 of six vtables plus the GOT entry
    0x64ed288 the fetch compares against; the forward produce
    0x5d2d0e0 is installed at slot 0xf0 of the first of those
    vtables plus the GOT entry 0x64ed070 the default produce
    compares against; the version-key initializer is reached
    through .init_array).

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> qwords=<n> relative=<n>
then the slot-0xe8 / slot-0xf0 registration tables and the GOT
canonical entries. Also writes callers.tsv (one row per direct
call / tail jump with the smallest enclosing FDE as the caller)
and relocations.txt (the RELATIVE records installing a pinned
routine) into this packet directory. callers.tsv in this packet
is the record of the calls column.
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
    0x606E3A0: (0x606E3A0, 0x606EA29),
    0x5D33A90: (0x5D33A90, 0x5D33C67),
    0x5D2D0E0: (0x5D2D0E0, 0x5D2D127),
    0x60B21F0: (0x60B21F0, 0x60B2262),
    0x5D532D0: (0x5D532D0, 0x5D532DC),
    0x61BD0C0: (0x61BD0C0, 0x61BD0D4),
    0x61BD0E0: (0x61BD0E0, 0x61BD131),
    0x61CF670: (0x61CF670, 0x61CF767),
    0x61D1540: (0x61D1540, 0x61D178B),
    0x606F950: (0x606F950, 0x606FA16),
    0x5F204E0: (0x5F204E0, 0x5F205C3),
    0x606E2EB: (0x606E2EB, 0x606E39B),
}

# Routines installed by RELATIVE relocations (the rest have none).
RELOCATED = {0x5D33A90, 0x5D2D0E0, 0x606F950}


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
    streamed line by line and keeping only direct call/jump
    lines. Returns {target: ([call sites], [jump sites])}."""
    sites = {}
    for _file_off, vaddr, filesz in exec_segments(BINARY.read_bytes()):
        proc = subprocess.Popen(
            ["objdump", "-d", "--no-show-raw-insn",
             "--start-address=%#x" % vaddr,
             "--stop-address=%#x" % (vaddr + filesz), str(BINARY)],
            stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if "call" not in line and "jmp" not in line:
                continue
            parts = line.split()
            if len(parts) < 3 or not parts[0].endswith(":"):
                continue
            mnemonic = parts[1]
            if mnemonic not in ("call", "jmp"):
                continue
            target = parts[2]
            if not target or target[0] == "*":
                continue
            try:
                tgt = int(target, 16)
                site = int(parts[0][:-1], 16)
            except ValueError:
                continue
            entry = sites.setdefault(tgt, ([], []))
            entry[0 if mnemonic == "call" else 1].append(site)
        proc.wait()
        if proc.returncode != 0:
            raise SystemExit("objdump failed on segment %#x" % vaddr)
    for _calls, jumps in sites.values():
        jumps.sort()
    for calls, _jumps in sites.values():
        calls.sort()
    return sites


def scan(sites, target):
    """Direct calls and tail jumps to target from the streamed
    disassembly (true instruction starts only)."""
    calls, jumps = sites.get(target, ([], []))
    return list(calls), list(jumps)


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
        m = re.match(r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+R_X86_64_(\w+)"
                     r"(?:\s+([0-9a-f]+))?", line)
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
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def enclosing_fde(ranges, value):
    """Smallest enclosing FDE for an address (same rule as
    verify.py: bisect + bounded neighbourhood + full scan)."""
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    idx = bisect.bisect_right(starts, value) - 1
    cands = []
    for j in range(max(0, idx - 2), min(len(ordered), idx + 3)):
        a, b = ordered[j]
        if a <= value < b:
            cands.append((a, b))
    if not cands:
        cands = [(a, b) for a, b in ranges if a <= value < b]
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
        calls, jumps = scan(sites, target)
        qw = qwords(data, target)
        rel = sorted(o for o, a in relocs.items() if a == target)
        print("%#x calls=%d %s jumps=%d %s qwords=%d %s relative=%d %s" % (
            target, len(calls),
            " ".join("%#x" % c for c in calls),
            len(jumps), " ".join("%#x" % j for j in jumps),
            len(qw), " ".join("%#x" % q for q in qw),
            len(rel), " ".join("%#x" % r for r in rel)))
        for site in calls:
            rows.append((site, target, "call"))
        for site in jumps:
            rows.append((site, target, "tail jump"))
    rows.sort()
    with open(PACKET / "callers.tsv", "w") as handle:
        handle.write("site\ttarget\tcaller\tkind\n")
        for site, target, kind in rows:
            handle.write("%#x\t%#x\t%s\t%s\n" % (
                site, target, enclosing_fde(ranges, site), kind))
    with open(PACKET / "relocations.txt", "w") as handle:
        for line in reloc_lines:
            parts = line.split()
            if len(parts) >= 4 and int(parts[3], 16) in RELOCATED:
                handle.write(line + "\n")
    print("--- default produce 0x5d33a90 slot-0xe8 registrations ---")
    for off in sorted(relocs):
        if relocs[off] == 0x5D33A90 and off != 0x64ED288:
            print("%#x vtable %#x slot 0xe8" % (off, off - 0xE8))
    print("--- forward produce 0x5d2d0e0 slot-0xf0 registrations ---")
    for off in sorted(relocs):
        if relocs[off] == 0x5D2D0E0 and off != 0x64ED070:
            print("%#x vtable %#x slot 0xf0" % (off, off - 0xF0))
    print("--- GOT canonical entries ---")
    print("0x64ed288 -> %#x" % relocs[0x64ED288])
    print("0x64ed070 -> %#x" % relocs[0x64ED070])


if __name__ == "__main__":
    main()
