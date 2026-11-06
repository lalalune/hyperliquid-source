"""Reproduce the reference census for the
RE-001-stats-produce-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-produce-115/census.py

Method (same as the RE-001-record-write-caller-115 packet):
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

Routines already mapped by earlier packets are census targets
and their excerpts are re-shipped byte-identical: the stats
emit 0x5d52020 (#3037's source packet RE-001-stats-emit-52020-115),
the log dispatch 0x5fcf060 (#3037), the mutex lock 0x60d5230 and
unlock 0x60d52f0 (RE-001-mutex-wrappers-115), and the
instrumented acquire 0x606ca40 (RE-001-instrumented-acquire-6ca40-115).
The percentile/average/stddev helpers, the shared init, the
merge inner helper, the temp builder, the rebuild caller's
opaque callees and the TableFactory installer lookalike are
census targets only: their bodies are cited by contract, not
excerpted.
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
    0x6070810: (0x6070810, 0x6070AB5),  # StatisticsImpl::ToString (this packet)
    0x6070430: (0x6070430, 0x607047D),  # sharded ticker sum (this packet)
    0x6070500: (0x6070500, 0x60705D8),  # HistogramData build (this packet)
    0x606B080: (0x606B080, 0x606B0A2),  # histogram bucket-count init
    0x606B0C0: (0x606B0C0, 0x606B10A),  # histogram locked shared init
    0x606BDF0: (0x606BDF0, 0x606BE3D),  # histogram shard merge
    0x606BCE0: (0x606BCE0, 0x606BDCD),  # histogram percentile struct
    0x606BDD0: (0x606BDD0, 0x606BDDD),  # slot-0x78 thunk
    0x5D8B3B0: (0x5D8B3B0, 0x5D8B3BE),  # histogram sized delete
    0x5D35C00: (0x5D35C00, 0x5D35C26),  # shared_ptr control copy + bump
    0x5D58720: (0x5D58720, 0x5D58809),  # mutex-guarded rebuild caller
    0x5D57770: (0x5D57770, 0x5D586E3),  # struct-copy routine (site only)
    0x5D52020: (0x5D52020, 0x5D520C1),  # stats emit (re-shipped)
    0x5FCF060: (0x5FCF060, 0x5FCF153),  # log dispatch (re-shipped)
    0x60D5230: (0x60D5230, 0x60D52C5),  # mutex lock (re-shipped)
    0x60D52F0: (0x60D52F0, 0x60D5385),  # mutex unlock (re-shipped)
    0x606CA40: (0x606CA40, 0x606CC6A),  # instrumented acquire (re-shipped)
    # Cited ground, census only (see docstring).
    0x606B500: (0x606B500, 0x606B511),  # percentile-50 helper stub
    0x606B260: (0x606B260, 0x606B4FE),  # percentile(p) helper
    0x606B540: (0x606B540, 0x606B5B9),  # average helper
    0x606B5D0: (0x606B5D0, 0x606B6AE),  # stddev helper
    0x606B1D0: (0x606B1D0, 0x606B253),  # bucket merge inner
    0x606B020: (0x606B020, 0x606B07C),  # histogram shared init
    0x60C2E20: (0x60C2E20, 0x60C3477),  # rebuild temp builder
    0x5D8BCE0: (0x5D8BCE0, 0x5D8BD2A),  # rebuild stack fill
    0x5D354B0: (0x5D354B0, 0x5D35635),  # rebuild temp cleanup
    0x5D35770: (0x5D35770, 0x5D35925),  # rebuild source cleanup
    0x60DBD80: (0x60DBD80, 0x60DBDBB),  # lookalike factory
    0x5D356E0: (0x5D356E0, 0x5D3576D),  # TableFactory installer lookalike
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
