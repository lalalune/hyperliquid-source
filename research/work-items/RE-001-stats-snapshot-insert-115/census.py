"""Reproduce the reference census for the RE-001-stats-snapshot-insert-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-snapshot-insert-115/census.py

Method (same as the RE-001-ts-gate-ops-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site. The .text section is ~84 MB, so
    the full output (~21M lines) is never loaded whole.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the two node vtables at 0x64d2c28
    and 0x64d2c90 hold the slot functions as RELATIVE
    addends; the caller reaches the binary through four
    {slot address, 8, function} registration triples, and
    the wrapper and the count getter through one triple
    each).

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> qwords=<n> relative=<n>
and the two vtable slot tables. callers.tsv in this packet is
the record of the calls column.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    0x5D4CC80: (0x5D4CC80, 0x5D4CE6A),
    0x606EF50: (0x606EF50, 0x606F91F),
    0x606F920: (0x606F920, 0x606F94B),
    0x60B21F0: (0x60B21F0, 0x60B2262),
    0x5D532D0: (0x5D532D0, 0x5D532DC),
    0x606DE00: (0x606DE00, 0x606DE09),
    0x606C680: (0x606C680, 0x606C6A5),
    0x5D52660: (0x5D52660, 0x5D52765),
    0x5D4E140: (0x5D4E140, 0x5D4E257),
    0x5D6C600: (0x5D6C600, 0x5D6C79B),
    0x5D498C0: (0x5D498C0, 0x5D4990E),
    0x606C5E0: (0x606C5E0, 0x606C657),
    0x606E250: (0x606E250, 0x606E2C7),
    0x606C280: (0x606C280, 0x606C5DD),
    0x606DEF0: (0x606DEF0, 0x606E24D),
    0x606C660: (0x606C660, 0x606C67B),
    0x606E2D0: (0x606E2D0, 0x606E2EB),
    0x606C180: (0x606C180, 0x606C189),
    0x606DDF0: (0x606DDF0, 0x606DDF9),
    0x606C6B0: (0x606C6B0, 0x606C6DB),
    0x606C190: (0x606C190, 0x606C199),
    0x606C170: (0x606C170, 0x606C17A),
    0x606C1A0: (0x606C1A0, 0x606C1A9),
    0x606DE10: (0x606DE10, 0x606DE19),
    0x606C1E0: (0x606C1E0, 0x606C278),
    0x606DE50: (0x606DE50, 0x606DEE8),
    0x606F950: (0x606F950, 0x606FA16),
    0x5F204E0: (0x5F204E0, 0x5F205C3),
    0x606EB60: (0x606EB60, 0x606EEAC),
    0x61D1540: (0x61D1540, 0x61D178B),
    0x61C7E30: (0x61C7E30, 0x61C7FB6),
    0x61CF670: (0x61CF670, 0x61CF767),
    0x61CF610: (0x61CF610, 0x61CF64F),
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


def relative_addends():
    """Map RELATIVE relocation offset -> addend, from readelf -r."""
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    out = {}
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
    return out


def main():
    data = BINARY.read_bytes()
    sites = disassembly_sites()
    relocs = relative_addends()
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
    print("--- node vtable A 0x64d2c28 ---")
    for off in sorted(relocs):
        if 0x64D2C28 <= off < 0x64D2C90:
            print("%#x -> %#x" % (off, relocs[off]))
    print("--- node vtable B 0x64d2c90 ---")
    for off in sorted(relocs):
        if 0x64D2C90 <= off < 0x64D2D20:
            print("%#x -> %#x" % (off, relocs[off]))


if __name__ == "__main__":
    main()
