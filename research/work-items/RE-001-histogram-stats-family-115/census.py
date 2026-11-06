"""Reproduce the reference census for the
RE-001-histogram-stats-family-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-histogram-stats-family-115/census.py

Method (same as the RE-001-stats-produce-115 packet, whose
census.py this adapts):
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
lea reference with the smallest enclosing FDE as the caller).

Routines already mapped by the RE-001-stats-produce-115 packet
(#3362) are census targets and their excerpts are re-shipped
byte-identical: the bucket-count init 0x606b080, the locked
init 0x606b0c0, the merge wrapper 0x606bdf0, the percentile
struct 0x606bce0 and its thunk 0x606bdd0. The vector-grow
helper 0x5dde8e0, the histogram builder 0x6070500 and
StatisticsImpl::ToString 0x6070810 are census targets only:
their bodies are cited by contract, not excerpted.
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
    0x606AF40: (0x606AF40, 0x606AF4C),  # name accessor (slot 0x38)
    0x606AF50: (0x606AF50, 0x606AF59),  # min accessor (slot 0x40)
    0x606AF60: (0x606AF60, 0x606AF69),  # max accessor (slot 0x48)
    0x606AF70: (0x606AF70, 0x606AF91),  # boundaries vector dtor
    0x606AFA0: (0x606AFA0, 0x606B013),  # bucket index (lower_bound)
    0x606B020: (0x606B020, 0x606B07C),  # shared init
    0x606B080: (0x606B080, 0x606B0A2),  # bucket-count init (re-shipped)
    0x606B0C0: (0x606B0C0, 0x606B10A),  # locked init (re-shipped)
    0x606B110: (0x606B110, 0x606B11F),  # empty check
    0x606B120: (0x606B120, 0x606B12D),  # empty thunk (slot 0x18)
    0x606B130: (0x606B130, 0x606B1B3),  # Add(value)
    0x606B1C0: (0x606B1C0, 0x606B1CD),  # record thunk (slot 0x20)
    0x606B1D0: (0x606B1D0, 0x606B253),  # lock merge inner
    0x606B260: (0x606B260, 0x606B4FE),  # percentile(p) core
    0x606B500: (0x606B500, 0x606B511),  # P50
    0x606B520: (0x606B520, 0x606B52D),  # median thunk (slot 0x58)
    0x606B530: (0x606B530, 0x606B53D),  # percentile thunk (slot 0x60)
    0x606B540: (0x606B540, 0x606B5B9),  # average
    0x606B5C0: (0x606B5C0, 0x606B5CD),  # average thunk (slot 0x68)
    0x606B5D0: (0x606B5D0, 0x606B6AE),  # stddev
    0x606B6B0: (0x606B6B0, 0x606B6BD),  # stddev thunk (slot 0x70)
    0x606B6BE: (0x606B6BE, 0x606B6E6),  # renderer string-dispose pad
    0x606B6F0: (0x606B6F0, 0x606BC8D),  # full text renderer
    0x606BC90: (0x606BC90, 0x606BCD3),  # ToString entry (slot 0x30)
    0x606BCE0: (0x606BCE0, 0x606BDCD),  # percentile struct (re-shipped)
    0x606BDD0: (0x606BDD0, 0x606BDDD),  # struct thunk (slot 0x78, re-shipped)
    0x606BDF0: (0x606BDF0, 0x606BE3D),  # merge wrapper (re-shipped)
    0x606BE40: (0x606BE40, 0x606BED5),  # merge entry (slot 0x28)
    0x606BF10: (0x606BF10, 0x606C134),  # boundary generator
    0x606C140: (0x606C140, 0x606C16B),  # boundaries static init
    # Cited ground, census only (see docstring).
    0x5DDE8E0: (0x5DDE8E0, 0x5DDEA65),  # vector grow helper
    0x6070500: (0x6070500, 0x60705D8),  # histogram builder (#3362)
    0x6070810: (0x6070810, 0x6070AB5),  # StatisticsImpl::ToString (#3362)
}


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
    """(offset -> addend) for RELATIVE relocations."""
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    out = {}
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
    return out


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
    """Smallest enclosing FDE for an address."""
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
    relocs = relative_records()
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
    print("wrote callers.tsv (%d rows)" % len(rows))


if __name__ == "__main__":
    main()
