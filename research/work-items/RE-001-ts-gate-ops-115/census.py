"""Reproduce the reference census for the RE-001-ts-gate-ops-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ts-gate-ops-115/census.py

Method (same as the RE-001-writebatch-ops-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site. The .text section is ~84 MB, so
    the full output (~21M lines) is never loaded whole.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the WriteBatch vtable at 0x64cd498
    holds the middle callees as RELATIVE addends; the wrappers
    reach the binary through RELATIVE function-pointer
    registrations, as in PR #3209).
  * Resolve the WriteBatch vtable and the GOT slot at
    0x64ecfa8 (RELATIVE addend 0x5d48400, the always-OK stub
    the gate compares slot 0xc8 against).

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
    0x5E882B0: (0x5E882B0, 0x5E8901D),
    0x5E94800: (0x5E94800, 0x5E9491C),
    0x5E95040: (0x5E95040, 0x5E95156),
    0x5E95560: (0x5E95560, 0x5E95676),
    0x5E95AC0: (0x5E95AC0, 0x5E95BE0),
    0x5E960A0: (0x5E960A0, 0x5E961BC),
    0x5E94690: (0x5E94690, 0x5E947B8),
    0x5E94EE0: (0x5E94EE0, 0x5E94FF8),
    0x5E95400: (0x5E95400, 0x5E95518),
    0x5E95950: (0x5E95950, 0x5E95A78),
    0x5E95F30: (0x5E95F30, 0x5E96058),
    0x5FBF7D0: (0x5FBF7D0, 0x5FBF92F),
    0x5FC04F0: (0x5FC04F0, 0x5FC062F),
    0x5FC11E0: (0x5FC11E0, 0x5FC131F),
    0x5FC2080: (0x5FC2080, 0x5FC21F7),
    0x5FC4220: (0x5FC4220, 0x5FC437F),
    0x5FBF0B0: (0x5FBF0B0, 0x5FBF588),
    0x5FBFF40: (0x5FBFF40, 0x5FC02E8),
    0x5FC0C30: (0x5FC0C30, 0x5FC0FD8),
    0x5FC1980: (0x5FC1980, 0x5FC1E23),
    0x5FC3B00: (0x5FC3B00, 0x5FC3FD8),
    0x5FB6910: (0x5FB6910, 0x5FB6A30),
    0x61C7E30: (0x61C7E30, 0x61C7FB6),
    0x61C7DA0: (0x61C7DA0, 0x61C7DB2),
    0x5D48400: (0x5D48400, 0x5D48407),
    0x5FB9F90: (0x5FB9F90, 0x5FBA0BE),
    0x5FB7EE0: (0x5FB7EE0, 0x5FB7FB7),
    0x61CF610: (0x61CF610, 0x61CF64F),
    0x61CF670: (0x61CF670, 0x61CF767),
    0x5D48510: (0x5D48510, 0x5D4851C),
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
    print("--- writebatch vtable 0x64cd498 ---")
    for off in sorted(relocs):
        if 0x64CD488 <= off < 0x64CD600:
            print("%#x -> %#x" % (off, relocs[off]))
    print("--- got slot 0x64ecfa8 ---")
    print("%#x -> %#x" % (0x64ECFA8, relocs.get(0x64ECFA8, -1)))


if __name__ == "__main__":
    main()
