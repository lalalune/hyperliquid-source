"""Reproduce the reference census for the
RE-001-stats-emit-caller-7dfc0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-emit-caller-7dfc0-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it exhaustively for E8 (direct call)
    and E9 (tail jump) opcodes whose rel32 target is one of the
    pinned routines. Every candidate is confirmed as a real
    instruction by decoding from the candidate address with
    objdump; a candidate that does not decode to a call/jump to
    the target there is rejected, not counted.
  * Classify the main routine's and the cleanup fragment's own
    control transfers from one linear disassembly of each range
    (true instruction starts only).
  * Scan the raw binary at 8-byte strides for qwords equal to
    each pinned routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each pinned routine address.

Expected result for the digest-verified node #115 work binary:
main 0x5d7dfc0: 0 direct calls, 1 tail jump (the thunk at
0x5d7e63a, FDE 0x5d7e630..0x5d7e63f); stats-emit 0x5d52020: 1
direct call (0x5d7e339); noop hook 0x5f04ce0: 1 direct call
(0x5d7e456); registry lookup 0x5eee790: 6 direct calls; trim
invoke 0x5eee9f0: 3 direct calls, 1 tail jump; refresh 0x5eef8a0:
3 direct calls; acquire 0x606ca40: 244 direct calls, 8 tail
jumps; log dispatch 0x5fcf060: 252 direct calls, 1 tail jump;
version release 0x5d911e0: 53 direct calls, 1 tail jump; string
assign 0x5d4ab80: 35 direct calls; mutex unlock 0x60d52f0: 669
direct calls, 5 tail jumps; identity 0x5d3a940: 0 calls, 0 jumps (installed by 8
RELATIVE records; the slot +0xd0 guard reads 0x64ecd10); rehash
0x5d7dda0: 1 direct call (0x5d7e582). Main internal transfers:
28 direct calls, 7 direct tail jumps (all into the cleanup
fragment), 2 indirect calls, 0 indirect tail jumps. Cleanup
fragment internal transfers: 12 direct calls, 0 tail jumps,
0 indirect calls, 0 indirect tail jumps.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D7DFC0, 0x5D4AB80, 0x5D911E0, 0x60D52F0, 0x5F04CE0,
           0x5D3A940, 0x5FCF060, 0x5EEE790, 0x5EEE9F0, 0x5EEF8A0,
           0x606CA40, 0x5D52020, 0x5D7DDA0)
ROUTINE_START, ROUTINE_STOP = 0x5D7DFC0, 0x5D7E627
CLEANUP_START, CLEANUP_STOP = 0x5D7DEDE, 0x5D7DFBA

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def exec_segment(data):
    """Return (file offset, vaddr, file size) of the R E LOAD segment."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            return p_offset, p_vaddr, p_filesz
    raise SystemExit("no executable LOAD segment")


def confirmed(site, kind, target):
    """True when objdump, decoding from the site itself, shows a
    real call/jump to target there."""
    text = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % site,
         "--stop-address=%#x" % (site + 0x10), str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    want_op = "call" if kind == "call" else "jmp"
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        if int(match.group(1), 16) != site:
            continue
        mnemonic = (match.group(3) or "").strip()
        return (mnemonic.startswith(want_op)
                and ("%x" % target) in mnemonic)
    return False


def internal_transfers(start, stop):
    """Classify one range's own control transfers (true starts)."""
    dump = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    instructions = []
    for line in dump.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if (not mnemonic and instructions
                and address == instructions[-1][0]
                + len(instructions[-1][1])):
            instructions[-1] = (instructions[-1][0],
                                instructions[-1][1] + raw,
                                instructions[-1][2])
        else:
            instructions.append((address, raw, mnemonic))
    internal = {"call": set(), "jmp": set(),
                "icall": set(), "ijmp": set()}
    for address, _raw, mnemonic in instructions:
        parts = mnemonic.split(None, 1)
        if not parts:
            continue
        opcode = parts[0]
        operand = parts[1] if len(parts) > 1 else ""
        if opcode == "call" and operand.startswith("*"):
            internal["icall"].add(address)
        elif opcode == "jmp" and operand.startswith("*"):
            internal["ijmp"].add(address)
        elif opcode == "call":
            internal["call"].add(address)
        elif opcode == "jmp":
            dest = operand.split()[0] if operand.split() else ""
            try:
                dest_value = int(dest, 16)
            except ValueError:
                dest_value = None
            if (dest_value is None
                    or not (start <= dest_value < stop)):
                internal["jmp"].add(address)
    return internal


def _fmt(addresses):
    return sorted("%#x" % a for a in addresses)


def main():
    data = BINARY.read_bytes()
    seg_offset, seg_vaddr, seg_filesz = exec_segment(data)
    reloc_text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in TARGETS:
        found = {"call": set(), "jmp": set()}
        rejected = []
        for off in range(seg_offset, seg_offset + seg_filesz - 5):
            op = data[off]
            if op not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from("<i", data, off + 1)[0]
            site = off - seg_offset + seg_vaddr
            if site + 5 + rel != target:
                continue
            kind = "call" if op == 0xE8 else "jmp"
            if confirmed(site, kind, target):
                found[kind].add(site)
            else:
                rejected.append(site)
        print("routine %#x: direct calls: %s" % (target, _fmt(found["call"])))
        print("routine %#x: tail jumps: %s" % (target, _fmt(found["jmp"])))
        if rejected:
            print("routine %#x: rejected candidates: %s"
                  % (target, _fmt(rejected)))
        qwords = []
        for off in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, off)[0] == target:
                qwords.append(off)
        print("routine %#x: stored qwords: %s"
              % (target, ["%#x" % q for q in qwords]))
        count = 0
        for line in reloc_text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                count += 1
        print("routine %#x: RELATIVE addends: %d" % (target, count))
    for label, start, stop in (
            ("routine", ROUTINE_START, ROUTINE_STOP),
            ("cleanup", CLEANUP_START, CLEANUP_STOP)):
        internal = internal_transfers(start, stop)
        print("%s %#x: internal calls: %s"
              % (label, start, _fmt(internal["call"])))
        print("%s %#x: internal tail jumps: %s"
              % (label, start, _fmt(internal["jmp"])))
        print("%s %#x: internal indirect calls: %s"
              % (label, start, _fmt(internal["icall"])))
        print("%s %#x: internal indirect tail jumps: %s"
              % (label, start, _fmt(internal["ijmp"])))


if __name__ == "__main__":
    main()
