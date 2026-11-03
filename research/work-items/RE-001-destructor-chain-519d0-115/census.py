"""Reproduce the reference census for the RE-001-destructor-chain-519d0-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-destructor-chain-519d0-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it exhaustively for E8 (direct call)
    and E9 (tail jump) opcodes whose rel32 target is the
    destructor chain routine (0x5d519d0). Every candidate is
    confirmed as a real instruction by decoding from the candidate
    address with objdump; a candidate that does not decode to a
    call/jump to the target there is rejected, not counted.
  * Classify the routine's own control transfers from one linear
    disassembly of the whole routine range (true instruction
    starts only): the routine makes exactly four direct calls
    (the destructor at 0x5d50de0, the destroy at 0x5f10d40,
    and two operator deletes) and one direct tail jump (to the
    teardown at 0x5d51010), and no indirect transfer of any
    kind. A jump whose target lies inside the routine range is
    an internal jump, not a tail jump.
  * Scan the raw binary at 8-byte strides for qwords equal to the
    routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning the
    routine address (there are none; the routine is reached only
    by direct calls).
  * For every confirmed call site, find the smallest enclosing
    FDE from a fresh frame dump and print it, so callers.tsv can
    be checked against the dump rather than asserted.

Expected result for the digest-verified node #115 work binary:
12 direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends for the routine address, 4 internal calls, 1 internal
tail jump, 0 internal indirect calls, 0 internal indirect tail
jumps.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5D519D0,)
ROUTINE_START, ROUTINE_STOP = 0x5D519D0, 0x5D51AAF

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
        if match and int(match.group(1), 16) == site:
            mnemonic = (match.group(3) or "").strip()
            return (mnemonic.startswith(want_op)
                    and ("%x" % target) in mnemonic)
    return False


def enclosing_fdes():
    """Return [(start, stop, line)] from a fresh frame dump."""
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for line in text.splitlines():
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if match:
            fdes.append((int(match.group(1), 16),
                         int(match.group(2), 16), line.strip()))
    return fdes


def main():
    data = BINARY.read_bytes()
    seg_offset, seg_vaddr, seg_filesz = exec_segment(data)
    fdes = enclosing_fdes()
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
        print("routine %#x: direct calls: %s"
              % (target, sorted("%#x" % c for c in found["call"])))
        print("routine %#x: tail jumps: %s"
              % (target, sorted("%#x" % j for j in found["jmp"])))
        if rejected:
            print("routine %#x: rejected candidates: %s"
                  % (target, sorted("%#x" % r for r in rejected)))
        for site in sorted(found["call"]):
            enclosing = [f for f in fdes if f[0] <= site < f[1]]
            enclosing.sort(key=lambda f: f[1] - f[0])
            if enclosing:
                print("site %#x caller %#x..%#x"
                      % (site, enclosing[0][0], enclosing[0][1]))
            else:
                print("site %#x caller NONE" % site)
        qwords = []
        for off in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, off)[0] == target:
                qwords.append(off + 0x1000)
        print("routine %#x: stored qwords: %s"
              % (target, ["%#x" % q for q in qwords]))
        dump = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % ROUTINE_START,
             "--stop-address=%#x" % ROUTINE_STOP, str(BINARY)],
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
                        or not (ROUTINE_START <= dest_value < ROUTINE_STOP)):
                    internal["jmp"].add(address)
        print("routine %#x: internal calls: %s"
              % (target, sorted("%#x" % c for c in internal["call"])))
        print("routine %#x: internal tail jumps: %s"
              % (target, sorted("%#x" % j for j in internal["jmp"])))
        print("routine %#x: internal indirect calls: %s"
              % (target, sorted("%#x" % c for c in internal["icall"])))
        print("routine %#x: internal indirect tail jumps: %s"
              % (target, sorted("%#x" % j for j in internal["ijmp"])))
    text = subprocess.run(["readelf", "-r", str(BINARY)],
                          capture_output=True, text=True,
                          check=True).stdout
    for target in TARGETS:
        count = 0
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                count += 1
        print("routine %#x: RELATIVE addends: %d" % (target, count))


if __name__ == "__main__":
    main()
