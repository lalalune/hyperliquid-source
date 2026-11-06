"""Reproduce the reference census for the
RE-001-basic-stats-factory-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-basic-stats-factory-115/census.py

Method (same as the RE-001-stats-ticker-map-115 packet):
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
(#3362) are census targets only: StatisticsImpl::ToString
0x6070810, the histogram builder 0x6070500, the ticker getter
0x6070430, and the mutex lock/unlock 0x60d5230/0x60d52f0. The
registry lookup 0x609e510 and its callee 0x609a410, the host's
result translator 0x6076b20, the shared_ptr release dispatcher
0x5d35070, the shard allocator/free 0x60d5d50/0x60d5db0, the
mutex destroy 0x60d5170, the options-system manager 0x606fa80
and the registry-list helper 0x61f81d0 are census targets only:
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
    0x6077820: (0x6077820, 0x60780A0),  # create-by-name host
    0x6075BC0: (0x6075BC0, 0x6075FF5),  # RegisterBuiltinStatistics lambda
    0x6071A00: (0x6071A00, 0x6071B60),  # StatisticsImpl ctor
    0x6071BA0: (0x6071BA0, 0x6071CCB),  # factory create callback (invoker)
    0x606FA50: (0x606FA50, 0x606FA7D),  # std::function manager (lambda)
    0x61F8B60: (0x61F8B60, 0x61F8D12),  # ObjectLibrary singleton accessor
    0x5FD1DA0: (0x5FD1DA0, 0x5FD1FFA),  # unordered_map operator[]
    0x5FD17C0: (0x5FD17C0, 0x5FD1962),  # vector _M_realloc_insert
    0x60D50C0: (0x60D50C0, 0x60D5157),  # pthread_mutex_init wrapper
    0x60716D0: (0x60716D0, 0x6071952),  # ticker shard-store construction
    0x6099CE0: (0x6099CE0, 0x6099E34),  # "StatisticsOptions" record append
    0x6070EA0: (0x6070EA0, 0x607103C),  # StatisticsImpl destructor
    0x6071040: (0x6071040, 0x607105B),  # StatisticsImpl deleting destructor
    0x606FAD0: (0x606FAD0, 0x606FB12),  # FactoryEntry dtor
    0x606FDA0: (0x606FDA0, 0x606FDEA),  # FactoryEntry deleting dtor
    0x606FB40: (0x606FB40, 0x606FB4E),  # FactoryEntry Matches forward
    0x606FB50: (0x606FB50, 0x606FB5E),  # FactoryEntry Name forward
    0x5FF2030: (0x5FF2030, 0x5FF2145),  # PatternEntry dtor
    0x5FF2150: (0x5FF2150, 0x5FF225F),  # PatternEntry deleting dtor
    0x61F8670: (0x61F8670, 0x61F86F2),  # PatternEntry Matches
    0x61F8120: (0x61F8120, 0x61F8129),  # PatternEntry Name
    0x61F8430: (0x61F8430, 0x61F8670),  # match helper
    0x61F8280: (0x61F8280, 0x61F842B),  # sub-pattern matcher
    0x606FAC0: (0x606FAC0, 0x606FAC5),  # counted_ptr<StatisticsImpl> dtor
    0x606FB80: (0x606FB80, 0x606FB8E),  # counted_ptr<StatisticsImpl> deleting dtor
    0x60710B0: (0x60710B0, 0x60710FB),  # counted_ptr<StatisticsImpl> _M_dispose
    0x606FB90: (0x606FB90, 0x606FB9E),  # counted_ptr<StatisticsImpl> _M_destroy
    0x606FB30: (0x606FB30, 0x606FB37),  # counted_ptr<StatisticsImpl> _M_get_deleter
    0x606FAB0: (0x606FAB0, 0x606FAB5),  # counted_ptr<Statistics> dtor
    0x606FB60: (0x606FB60, 0x606FB6E),  # counted_ptr<Statistics> deleting dtor
    0x6071060: (0x6071060, 0x60710AB),  # counted_ptr<Statistics> _M_dispose
    0x606FB70: (0x606FB70, 0x606FB7E),  # counted_ptr<Statistics> _M_destroy
    0x606FB20: (0x606FB20, 0x606FB27),  # counted_ptr<Statistics> _M_get_deleter
    0x61F8130: (0x61F8130, 0x61F8135),  # inplace<ObjectRegistry> dtor
    0x61F8140: (0x61F8140, 0x61F814E),  # inplace<ObjectRegistry> deleting dtor
    0x61F8760: (0x61F8760, 0x61F89DB),  # inplace<ObjectRegistry> _M_dispose
    0x61F8170: (0x61F8170, 0x61F817E),  # inplace<ObjectRegistry> _M_destroy
    0x61F8180: (0x61F8180, 0x61F81C7),  # inplace<ObjectRegistry> _M_get_deleter
    0x5FEFC70: (0x5FEFC70, 0x5FEFC75),  # inplace<ObjectLibrary> dtor
    0x5FEFD00: (0x5FEFD00, 0x5FEFD0E),  # inplace<ObjectLibrary> deleting dtor
    0x5FF7900: (0x5FF7900, 0x5FF7952),  # inplace<ObjectLibrary> _M_dispose
    0x5FEFD50: (0x5FEFD50, 0x5FEFD5E),  # inplace<ObjectLibrary> _M_destroy
    0x5FEFF70: (0x5FEFF70, 0x5FEFFB7),  # inplace<ObjectLibrary> _M_get_deleter
    # Cited ground, census only (see docstring).
    0x609E510: (0x609E510, 0x609F073),  # registry lookup (host's non-BasicStatistics path)
    0x609A410: (0x609A410, 0x609A67C),  # registry lookup callee
    0x6076B20: (0x6076B20, 0x6077712),  # host's non-OK result translator
    0x6070810: (0x6070810, 0x6070AB5),  # StatisticsImpl::ToString (#3362)
    0x6070500: (0x6070500, 0x60705D8),  # histogram builder (#3362)
    0x6070430: (0x6070430, 0x607047D),  # ticker shard-sum getter (#3362)
    0x60D5230: (0x60D5230, 0x60D52C5),  # mutex lock (#3362)
    0x60D52F0: (0x60D52F0, 0x60D5385),  # mutex unlock (#3362)
    0x5D35070: (0x5D35070, 0x5D350BC),  # shared_ptr release dispatcher
    0x60D5D50: (0x60D5D50, 0x60D5DB0),  # shard-store allocator
    0x60D5DB0: (0x60D5DB0, 0x60D5DB9),  # shard-store free
    0x60D5170: (0x60D5170, 0x60D5200),  # pthread_mutex_destroy wrapper
    0x606FA80: (0x606FA80, 0x606FAAD),  # options-system manager (sibling functor)
    0x61F81D0: (0x61F81D0, 0x61F8271),  # registry-list helper (inplace dispose callee)
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
