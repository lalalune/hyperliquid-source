"""Reproduce the reference census for the RE-001-alloc-boundary-63650-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-alloc-boundary-63650-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it exhaustively for E8 (direct call)
    and E9 (tail jump) opcodes whose rel32 target is the allocation
    boundary (0x5963650). Every candidate is confirmed as a real
    instruction by one streaming objdump disassembly pass over the
    whole binary: a candidate counts only when objdump decodes a
    call/jump to the target at exactly that address.
  * Classify the routine's own control transfers from one linear
    disassembly of the whole routine range (true instruction
    starts only).
  * Scan the raw binary at 8-byte strides for qwords equal to the
    routine address.
  * Parse `readelf -r` output for RELATIVE records whose addend is
    the routine address.

Expected result for the digest-verified node #115 work binary:
732 direct calls, 0 tail jumps, no stored qwords, no RELATIVE
addends, 0 internal calls, 0 internal tail jumps, 4 internal
indirect calls (the four allocator slot calls), 0 internal
indirect tail jumps. A capstone cross-check decoding linearly
from each candidate's enclosing FDE start gives the same 732
sites in 580 distinct caller FDEs with zero rejections.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x5963650,)
ROUTINE_START, ROUTINE_STOP = 0x5963650, 0x5963739

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


def objdump_confirmed():
    """One streaming objdump pass; return {site: 'call'|'jmp'} for
    real instructions whose target is the boundary."""
    found = {}
    targets = {"%x" % t for t in TARGETS}
    proc = subprocess.Popen(
        ["objdump", "-d", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        match = LINE_RE.match(line)
        if not match:
            continue
        mnemonic = (match.group(3) or "").strip()
        if not mnemonic:
            continue
        parts = mnemonic.split(None, 1)
        if parts[0] not in ("call", "jmp") or len(parts) < 2:
            continue
        dest = parts[1].split()[0] if parts[1].split() else ""
        if dest in targets:
            found[int(match.group(1), 16)] = parts[0]
    if proc.wait() != 0:
        raise SystemExit("objdump pass failed")
    return found


def main():
    data = BINARY.read_bytes()
    seg_offset, seg_vaddr, seg_filesz = exec_segment(data)
    confirmed = objdump_confirmed()
    for target in TARGETS:
        raw = {"call": set(), "jmp": set()}
        for off in range(seg_offset, seg_offset + seg_filesz - 5):
            op = data[off]
            if op not in (0xE8, 0xE9):
                continue
            rel = struct.unpack_from("<i", data, off + 1)[0]
            site = off - seg_offset + seg_vaddr
            if site + 5 + rel != target:
                continue
            raw["call" if op == 0xE8 else "jmp"].add(site)
        calls = sorted(s for s in raw["call"]
                       if confirmed.get(s) == "call")
        jumps = sorted(s for s in raw["jmp"]
                       if confirmed.get(s) == "jmp")
        rejected = sorted((raw["call"] | raw["jmp"]) - set(calls) - set(jumps))
        print("routine %#x: direct calls: %s"
              % (target, ["%#x" % c for c in calls]))
        print("routine %#x: tail jumps: %s"
              % (target, ["%#x" % j for j in jumps]))
        if rejected:
            print("routine %#x: rejected candidates: %s"
                  % (target, ["%#x" % r for r in rejected]))
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
            raw_bytes = bytes.fromhex(match.group(2).strip())
            mnemonic = (match.group(3) or "").strip()
            if (not mnemonic and instructions
                    and address == instructions[-1][0]
                    + len(instructions[-1][1])):
                instructions[-1] = (instructions[-1][0],
                                    instructions[-1][1] + raw_bytes,
                                    instructions[-1][2])
            else:
                instructions.append((address, raw_bytes, mnemonic))
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
            fields = line.split()
            if (len(fields) >= 4 and fields[2] == "R_X86_64_RELATIVE"
                    and fields[-1] == "%x" % target):
                count += 1
        print("routine %#x: RELATIVE addends: %d" % (target, count))


if __name__ == "__main__":
    main()
