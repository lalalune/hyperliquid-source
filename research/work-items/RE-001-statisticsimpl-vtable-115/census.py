"""Reproduce the reference census for the
RE-001-statisticsimpl-vtable-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-statisticsimpl-vtable-115/census.py

Method (same as the RE-001-stats-write-side-115 packet, #3396):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address, and indirect virtual-dispatch
    lines `call *0xNN(%r..)` for all 32 StatisticsImpl vtable
    displacements (0x00..0xf8).
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and dispatch.tsv (one row per indirect call through the 32
vtable slots with the smallest enclosing FDE).

Routines already mapped by earlier packets are census targets
and their excerpts are re-shipped byte-identical: the 13 shared
Configurable/Customizable base slots from
RE-001-systemclock-wrapper-vtable-115 (#3902); the locked reads
0x6070490/0x6070610/0x6070700, the ticker getter and the
histogram builder from RE-001-locked-ticker-read-115 (#3392);
ToString 0x6070810 from RE-001-stats-produce-115 (#3362); the
slot-0xf0 fill 0x6076030 from RE-001-stats-ticker-map-115
(#3378); the write side (record tick, locked set, get-and-reset,
record histogram + devirtualized twin, reset, the dtors, the
name/delegate/hist-id stubs and the helpers) from
RE-001-stats-write-side-115 (#3396). New in this packet: the
deleting dtor 0x6071040, the slot-0xc8 forwarder 0x5d48960, the
base PrepareOptions 0x6095e70 and SerializeOptions 0x609de80,
IsInstanceOf 0x5d2e770 and the empty-string slot 0x5d2ca10, and
the complete 32-slot dispatch census.
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
    0x6070EA0: (0x6070EA0, 0x607103C),  # slot 0x00 D1 dtor
    0x6071040: (0x6071040, 0x607105B),  # slot 0x08 D0 deleting dtor (new)
    0x609D760: (0x609D760, 0x609D954),  # slot 0x10 Customizable::GetOption
    0x609DC40: (0x609DC40, 0x609DE39),  # slot 0x18 Customizable::AreEquivalent
    0x5D32560: (0x5D32560, 0x5D3257B),  # slot 0x20 empty-string (name open)
    0x6095E70: (0x6095E70, 0x609661C),  # slot 0x28 base Configurable::PrepareOptions (new)
    0x6096790: (0x6096790, 0x6096F0C),  # slot 0x30 Configurable::ValidateOptions
    0x5D2E090: (0x5D2E090, 0x5D2E0DE),  # slot 0x38 Customizable::GetOptionsPtr
    0x60956F0: (0x60956F0, 0x609570C),  # slot 0x40 empty-Status (name open)
    0x609D0E0: (0x609D0E0, 0x609D75E),  # slot 0x48 Configurable::ConfigureOptions
    0x60986B0: (0x60986B0, 0x6098A9C),  # slot 0x50 Configurable::ParseOption
    0x6095710: (0x6095710, 0x609579A),  # slot 0x58 Configurable::OptionsAreEqual
    0x609DE80: (0x609DE80, 0x609E29E),  # slot 0x60 base Customizable::SerializeOptions (new)
    0x609D980: (0x609D980, 0x609DC18),  # slot 0x68 Customizable::GetOptionName
    0x606FA20: (0x606FA20, 0x606FA2C),  # slot 0x70 Name -> "BasicStatistics"
    0x5D32A30: (0x5D32A30, 0x5D32A51),  # slot 0x78 GetId
    0x5D2E770: (0x5D2E770, 0x5D2E832),  # slot 0x80 IsInstanceOf (new)
    0x606FA30: (0x606FA30, 0x606FA39),  # slot 0x88 delegate getter
    0x5D2CA10: (0x5D2CA10, 0x5D2CA1C),  # slot 0x90 empty-string (new)
    0x6070490: (0x6070490, 0x60704D2),  # slot 0x98 locked ticker read
    0x6070610: (0x6070610, 0x60706C9),  # slot 0xa0 locked percentiles
    0x6070700: (0x6070700, 0x60707C1),  # slot 0xa8 locked histogram text
    0x606FBA0: (0x606FBA0, 0x606FC59),  # slot 0xb0 record tick
    0x6070DC0: (0x6070DC0, 0x6070E9A),  # slot 0xb8 locked set ticker
    0x6070C50: (0x6070C50, 0x6070D92),  # slot 0xc0 get-and-reset ticker
    0x5D48960: (0x5D48960, 0x5D48979),  # slot 0xc8 level-3-only forwarder (new)
    0x606FFD0: (0x606FFD0, 0x60700C4),  # slot 0xd0 record histogram devirt twin
    0x606FEF0: (0x606FEF0, 0x606FFCE),  # slot 0xd8 record histogram
    0x6070B30: (0x6070B30, 0x6070C2A),  # slot 0xe0 reset
    0x6070810: (0x6070810, 0x6070AB5),  # slot 0xe8 StatisticsImpl::ToString
    0x6076030: (0x6076030, 0x6076615),  # slot 0xf0 ticker-map fill
    0x606FA40: (0x606FA40, 0x606FA4B),  # slot 0xf8 histogram-id check
    # Helpers (excerpted, re-shipped from #3396/#3392/#3362).
    0x6070AC0: (0x6070AC0, 0x6070B1B),  # unlocked set core
    0x60D5CD0: (0x60D5CD0, 0x60D5CF0),  # CPUID APIC-id picker
    0x61C4080: (0x61C4080, 0x61C4117),  # thread-local LCG seed
    0x60D5230: (0x60D5230, 0x60D52C5),  # mutex lock
    0x60D52F0: (0x60D52F0, 0x60D5385),  # mutex unlock
    0x6070430: (0x6070430, 0x607047D),  # ticker shard-sum getter
    0x6070500: (0x6070500, 0x60705D8),  # histogram builder
    0x606B130: (0x606B130, 0x606B1B3),  # HistogramImpl slot 0x20 record
    0x606B1C0: (0x606B1C0, 0x606B1CD),  # outer record entry (+8 thunk)
    0x606B0C0: (0x606B0C0, 0x606B10A),  # HistogramImpl slot 0x10 locked init
    0x606AFA0: (0x606AFA0, 0x606B013),  # bucket lower_bound
    0x606B020: (0x606B020, 0x606B07C),  # shared record init
    0x606BF10: (0x606BF10, 0x606C134),  # boundary generator
    0x6071A00: (0x6071A00, 0x6071B60),  # StatisticsImpl ctor (installs vtable)
    # Census-only neighbours.
    0x6071060: (0x6071060, 0x60710AB),  # _Sp_counted_ptr<StatisticsImpl> deleter
    0x6070D92: (0x6070D92, 0x6070DB2),  # 0xb8 unlock + resume fragment
    0x6070B1C: (0x6070B1C, 0x6070B2E),  # reset unlock + resume fragment
    0x6070C2A: (0x6070C2A, 0x6070C4A),  # reset unlock + resume fragment 2
    0x607047E: (0x607047E, 0x607048E),  # locked-read landing pad
    0x60705D8: (0x60705D8, 0x607060C),  # cleanup a0
    0x60706CA: (0x60706CA, 0x60706FE),  # cleanup a8
}

# Indirect virtual-dispatch displacements for all 32 vtable slots.
DISPATCH_SLOTS = {
    0x00: 0x6070EA0, 0x08: 0x6071040, 0x10: 0x609D760, 0x18: 0x609DC40,
    0x20: 0x5D32560, 0x28: 0x6095E70, 0x30: 0x6096790, 0x38: 0x5D2E090,
    0x40: 0x60956F0, 0x48: 0x609D0E0, 0x50: 0x60986B0, 0x58: 0x6095710,
    0x60: 0x609DE80, 0x68: 0x609D980, 0x70: 0x606FA20, 0x78: 0x5D32A30,
    0x80: 0x5D2E770, 0x88: 0x606FA30, 0x90: 0x5D2CA10, 0x98: 0x6070490,
    0xA0: 0x6070610, 0xA8: 0x6070700, 0xB0: 0x606FBA0, 0xB8: 0x6070DC0,
    0xC0: 0x6070C50, 0xC8: 0x5D48960, 0xD0: 0x606FFD0, 0xD8: 0x606FEF0,
    0xE0: 0x6070B30, 0xE8: 0x6070810, 0xF0: 0x6076030, 0xF8: 0x606FA40,
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
    lea lines whose comment names a pinned routine, plus
    indirect calls through the 32 vtable slots.
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
        print("dispatch slot %#x -> %#x sites=%d" % (
            slot, tgt, len(dispatch[slot])))
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
