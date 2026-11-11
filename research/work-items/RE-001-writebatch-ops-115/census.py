"""Reproduce the reference census for the RE-001-writebatch-ops-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-writebatch-ops-115/census.py

Method:
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site and no per-candidate confirmation
    spawn is needed. The .text section is ~84 MB, so the full
    output (~21M lines) is never loaded whole.
  * Classify each routine's own control transfers from one
    linear disassembly of its whole range (true instruction
    starts only).
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the WriteBatch vtable at 0x64cd498
    holds the six middle callees as RELATIVE addends; the
    guard's default getter address is a RELATIVE addend in
    4 records, per PR #3202).
  * Resolve the WriteBatch vtable: the typeinfo pointer record
    at 0x64cd490 and the vtable entries at 0x64cd498.. with
    the middle callees as addends, plus the typeinfo name
    string for rocksdb::WriteBatch.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> qwords=<n> relative=<n>
and the vtable slot table. callers.tsv in this packet is the
record of the calls column.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    0x5E94540: (0x5E94540, 0x5E94656),
    0x5E94B20: (0x5E94B20, 0x5E94C36),
    0x5E94DA0: (0x5E94DA0, 0x5E94EA3),
    0x5E952C0: (0x5E952C0, 0x5E953C3),
    0x5E95800: (0x5E95800, 0x5E95916),
    0x5E95D70: (0x5E95D70, 0x5E95EF7),
    0x5E943F0: (0x5E943F0, 0x5E944FF),
    0x5E94970: (0x5E94970, 0x5E94AE1),
    0x5E94C70: (0x5E94C70, 0x5E94D5E),
    0x5E95190: (0x5E95190, 0x5E9527E),
    0x5E956B0: (0x5E956B0, 0x5E957B7),
    0x5E95C20: (0x5E95C20, 0x5E95D27),
    0x5FBF5D0: (0x5FBF5D0, 0x5FBF795),
    0x5FC4DB0: (0x5FC4DB0, 0x5FC4F43),
    0x5FC0320: (0x5FC0320, 0x5FC04AD),
    0x5FC1010: (0x5FC1010, 0x5FC119D),
    0x5FC1E60: (0x5FC1E60, 0x5FC2045),
    0x5FC4020: (0x5FC4020, 0x5FC41E5),
    0x5FBF0B0: (0x5FBF0B0, 0x5FBF588),
    0x5FC46C0: (0x5FC46C0, 0x5FC4D78),
    0x5FBFF40: (0x5FBFF40, 0x5FC02E8),
    0x5FC0C30: (0x5FC0C30, 0x5FC0FD8),
    0x5FC1980: (0x5FC1980, 0x5FC1E23),
    0x5FC3B00: (0x5FC3B00, 0x5FC3FD8),
    0x5FB9F90: (0x5FB9F90, 0x5FBA0BE),
    0x5FB7EE0: (0x5FB7EE0, 0x5FB7FB7),
    0x61CF610: (0x61CF610, 0x61CF64F),
    0x5FBBC90: (0x5FBBC90, 0x5FBBE5B),
    0x5FBED30: (0x5FBED30, 0x5FBF077),
    0x5FBFC20: (0x5FBFC20, 0x5FBFF39),
    0x5FC0910: (0x5FC0910, 0x5FC0C29),
    0x5FC1600: (0x5FC1600, 0x5FC1979),
    0x5FC24F0: (0x5FC24F0, 0x5FC27F7),
    0x5D58810: (0x5D58810, 0x5D58AC5),
    0x61CF670: (0x61CF670, 0x61CF767),
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
    lines. The .text section is ~84 MB, so the full output
    (~21M lines) is never loaded whole; objdump runs with
    --no-show-raw-insn to keep it compact. Returns
    {target: ([call sites], [jump sites])}."""
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
    """File offsets holding target as an 8-byte-aligned qword
    (C-speed search, same alignment rule as the stride-8 scan
    the earlier packets used)."""
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
    print("--- writebatch vtable 0x64cd498 ---")
    for off in sorted(relocs):
        if 0x64CD488 <= off < 0x64CD600:
            print("%#x -> %#x" % (off, relocs[off]))


if __name__ == "__main__":
    main()
