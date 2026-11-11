"""Reproduce the reference census for the
RE-001-stats-write-side-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-write-side-115/census.py

Method (same as the RE-001-locked-ticker-read-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address, and indirect virtual-dispatch
    lines `call *0xb0(%r..)` / `*0xb8` / `*0xc0` / `*0xd0` /
    `*0xd8` / `*0xe0` for the six write-side vtable slots.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and dispatch.tsv (one row per indirect call through vtable
slots 0xb0/0xb8/0xc0/0xd0/0xd8/0xe0 with the smallest enclosing
FDE).

Routines already mapped by earlier packets are census targets
and their excerpts are re-shipped byte-identical: the mutex
lock/unlock 0x60d5230/0x60d52f0 from
RE-001-locked-ticker-read-115 (#3392).
StatisticsImpl::ToString 0x6070810, the slot-0xf0 fill 0x6076030,
the locked reads 0x6070490/0x6070610/0x6070700, the histogram
builder 0x6070500, the ticker getter 0x6070430, the HistogramImpl
percentile struct 0x606bce0 / renderer 0x606b6f0, the creator
0x6071ba0, the shard-store builder 0x60716d0, the once-init
0x6075bc0, the host 0x6077820 and the registry lookup 0x609e510
are census targets only: their bodies are cited by contract,
not excerpted.
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
    0x606FBA0: (0x606FBA0, 0x606FC59),  # slot 0xb0 record tick
    0x60D5CD0: (0x60D5CD0, 0x60D5CF0),  # CPUID APIC-id picker
    0x61C4080: (0x61C4080, 0x61C4117),  # thread-local LCG seed
    0x6070DC0: (0x6070DC0, 0x6070E9A),  # slot 0xb8 locked set
    0x6070D92: (0x6070D92, 0x6070DB2),  # 0xb8 unlock + resume fragment
    0x6070AC0: (0x6070AC0, 0x6070B1B),  # unlocked set core
    0x6070C50: (0x6070C50, 0x6070D92),  # slot 0xc0 get-and-reset
    0x606FEF0: (0x606FEF0, 0x606FFCE),  # slot 0xd8 record histogram
    0x606FFD0: (0x606FFD0, 0x60700C4),  # slot 0xd0 devirtualized twin
    0x6070B30: (0x6070B30, 0x6070C2A),  # slot 0xe0 reset
    0x6070B1C: (0x6070B1C, 0x6070B2E),  # reset unlock + resume fragment
    0x6070C2A: (0x6070C2A, 0x6070C4A),  # reset unlock + resume fragment 2
    0x606FA20: (0x606FA20, 0x606FA2C),  # slot 0x70 name
    0x606FA30: (0x606FA30, 0x606FA39),  # slot 0x88 delegate getter
    0x606FA40: (0x606FA40, 0x606FA4B),  # slot 0xf8 histogram-id check
    0x6071A00: (0x6071A00, 0x6071B60),  # StatisticsImpl ctor
    0x6070EA0: (0x6070EA0, 0x607103C),  # slot 0x0 dtor
    0x6071040: (0x6071040, 0x607105B),  # slot 0x8 deleting dtor
    0x606B130: (0x606B130, 0x606B1B3),  # HistogramImpl slot 0x20 record
    0x606AFA0: (0x606AFA0, 0x606B013),  # bucket lower_bound
    0x606B0C0: (0x606B0C0, 0x606B10A),  # HistogramImpl slot 0x10 locked init
    0x606B020: (0x606B020, 0x606B07C),  # shared record init
    0x606BF10: (0x606BF10, 0x606C134),  # boundary generator
    0x60D5230: (0x60D5230, 0x60D52C5),  # mutex lock (re-shipped)
    0x60D52F0: (0x60D52F0, 0x60D5385),  # mutex unlock (re-shipped)
    # Cited ground, census only (see docstring).
    0x6070810: (0x6070810, 0x6070AB5),  # StatisticsImpl::ToString (#3362)
    0x6076030: (0x6076030, 0x6076615),  # slot-0xf0 ticker-map fill (#3378)
    0x6070490: (0x6070490, 0x60704D2),  # locked ticker read (#3392)
    0x6070610: (0x6070610, 0x60706C9),  # locked percentiles (#3392)
    0x6070700: (0x6070700, 0x60707C1),  # locked histogram text (#3392)
    0x6070500: (0x6070500, 0x60705D8),  # histogram builder (#3362)
    0x6070430: (0x6070430, 0x607047D),  # ticker shard-sum getter (#3378)
    0x606BCE0: (0x606BCE0, 0x606BD00),  # HistogramImpl percentile struct (#3371)
    0x606B6F0: (0x606B6F0, 0x606BCE0),  # HistogramImpl text renderer (#3371)
    0x6071BA0: (0x6071BA0, 0x6071C00),  # creator (installs fresh object)
    0x60716D0: (0x60716D0, 0x6071A00),  # shard-store builder
    0x60D50C0: (0x60D50C0, 0x60D5170),  # mutex init
    0x60D5170: (0x60D5170, 0x60D51A0),  # mutex destroy
    0x6099CE0: (0x6099CE0, 0x6099D00),  # StatisticsOptions record append
    0x6075BC0: (0x6075BC0, 0x6075FF5),  # once-init (RegisterBuiltinStatistics)
    0x6077820: (0x6077820, 0x60780A0),  # create-by-name host
    0x609E510: (0x609E510, 0x609E600),  # registry lookup
    0x606B1C0: (0x606B1C0, 0x606B1CD),  # outer record entry (+8 thunk)
    0x606AF70: (0x606AF70, 0x606AFA0),  # boundaries dtor
    0x606C140: (0x606C140, 0x606C16B),  # boundaries static init
    0x5D8B3B0: (0x5D8B3B0, 0x5D8B3C0),  # sized delete (GOT 0x64ed2f0)
    0x60D5DB0: (0x60D5DB0, 0x60D5DC0),  # free (dtor shard-store free)
    0x606BDF0: (0x606BDF0, 0x606BE40),  # histogram merge wrapper
    0x606B080: (0x606B080, 0x606B0C0),  # bucket-count init
    0x606B260: (0x606B260, 0x606B500),  # percentile core
}

# Indirect virtual-dispatch displacements for the six write slots.
DISPATCH_SLOTS = {0xB0: 0x606FBA0, 0xB8: 0x6070DC0, 0xC0: 0x6070C50,
                  0xD0: 0x606FFD0, 0xD8: 0x606FEF0, 0xE0: 0x6070B30}


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
    lea lines whose comment names a pinned routine, plus
    indirect calls through the three locked-read vtable slots.
    Returns ({target: ([calls], [jumps], [leas])},
             {slot: [dispatch sites]})."""
    sites = {}
    dispatch = {slot: [] for slot in DISPATCH_SLOTS}
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
                if target.startswith("*0x"):
                    m = re.match(r"\*0x([0-9a-f]+)\(%", target)
                    if m and mnemonic == "call":
                        disp = int(m.group(1), 16)
                        if disp in DISPATCH_SLOTS:
                            dispatch[disp].append(site)
                    continue
                if target.startswith("*"):
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
    for lst in dispatch.values():
        lst.sort()
    return sites, dispatch


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
    sites, dispatch = disassembly_sites()
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
    drows = []
    for slot in sorted(dispatch):
        tgt = DISPATCH_SLOTS[slot]
        print("dispatch slot %#x -> %#x sites=%d %s" % (
            slot, tgt, len(dispatch[slot]),
            " ".join("%#x" % s for s in dispatch[slot])))
        for site in dispatch[slot]:
            drows.append((site, tgt, slot))
    drows.sort()
    with open(PACKET / "dispatch.tsv", "w") as handle:
        handle.write("site\ttarget\tslot\tcaller\n")
        for site, tgt, slot in drows:
            handle.write("%#x\t%#x\t%#x\t%s\n" % (
                site, tgt, slot, enclosing_fde(ordered, starts, site)))
    print("wrote dispatch.tsv (%d rows)" % len(drows))


if __name__ == "__main__":
    main()
