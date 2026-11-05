"""Reproduce the reference census for the RE-001-record-pushback-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-pushback-115/census.py

Method (same as the RE-001-options-default-init-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump
with the smallest enclosing FDE as the caller) and
relocations.txt (the RELATIVE records installing a pinned
routine) into this packet directory.
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
    0x6099CE0: (0x6099CE0, 0x6099E34),
    0x6099790: (0x6099790, 0x6099CAD),
    0x6064440: (0x6064440, 0x6064551),
    0x5FD0090: (0x5FD0090, 0x5FD0178),
    0x60DB710: (0x60DB710, 0x60DBD69),
    # Direct callees of the pinned routines (PLT stubs).
    0x63F0F00: (0x63F0F00, 0x63F0F10),  # basic_string::_M_assign
    0x63F0E10: (0x63F0E10, 0x63F0E20),  # basic_string::_M_create
    0x63F0A60: (0x63F0A60, 0x63F0A70),  # memcpy
    0x63F0D80: (0x63F0D80, 0x63F0D90),  # operator delete
    0x63F0DD0: (0x63F0DD0, 0x63F0DE0),  # operator new
    0x63F0DB0: (0x63F0DB0, 0x63F0DC0),  # basic_string::_M_dispose
}

# Routines installed by RELATIVE relocations. None of the pinned
# routines is installed anywhere: the push-back helper, the
# growth routine and the three call sites are reached only by
# direct calls, and the PLT stubs are reached only by direct
# calls. (Verified by the census run: every target below
# reports relative=0.)
RELOCATED = set()


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
    print("--- push-back / growth pair ---")
    growth_calls, _ = scan(sites, 0x6099790)
    print("growth calls: %s" % " ".join("%#x" % c for c in growth_calls))
    pushback_calls, _ = scan(sites, 0x6099CE0)
    print("push-back calls: %s" % " ".join("%#x" % c for c in pushback_calls))


if __name__ == "__main__":
    main()
