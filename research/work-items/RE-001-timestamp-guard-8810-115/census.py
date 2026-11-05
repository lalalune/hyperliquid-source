"""Reproduce the reference census for the RE-001-timestamp-guard-8810-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-timestamp-guard-8810-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it exhaustively for E8 (direct call)
    and E9 (tail jump) opcodes whose rel32 target is one of the
    three pinned routines (guard 0x5d58810, status builder
    0x61cf670, default getter 0x5d48510). Every candidate is
    confirmed as a real instruction by decoding from the candidate
    address with objdump; a candidate that does not decode to a
    call/jump to the target there is rejected, not counted.
  * Classify each routine's own control transfers from one linear
    disassembly of its whole range (true instruction starts
    only): the guard makes 15 direct calls, 0 direct tail jumps
    out, 3 indirect calls and 0 indirect tail jumps; the builder
    makes 4 direct calls, 2 direct tail jumps out (the delete[]
    tail call and the landing-pad jump to its pre-FDE cleanup
    block), 0 indirect calls and 0 indirect tail jumps; the
    getter makes no calls and no jumps.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the getter address is a RELATIVE
    addend in 4 records; the guard and builder addresses in 0).

Expected result for the digest-verified node #115 work binary:
guard 15 direct calls, 0 tail jumps, no stored qwords,
0 RELATIVE addends; builder 847 direct calls, 0 tail jumps,
no stored qwords, 0 RELATIVE addends; getter 0 direct calls,
0 tail jumps, 4 stored qwords (the .rela.dyn addends),
4 RELATIVE addends.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = {
    0x5D58810: (0x5D58810, 0x5D58AC5),
    0x61CF670: (0x61CF670, 0x61CF767),
    0x5D48510: (0x5D48510, 0x5D4851C),
}

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


def main():
    data = BINARY.read_bytes()
    seg_offset, seg_vaddr, seg_filesz = exec_segment(data)
    for target, (routine_start, routine_stop) in TARGETS.items():
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
        qwords = []
        for off in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, off)[0] == target:
                qwords.append(off + 0x1000)
        print("routine %#x: stored qwords: %s"
              % (target, ["%#x" % q for q in qwords]))
        # True instruction starts from one linear disassembly of
        # the routine range; split lines (long instructions) are
        # accumulated the same way verify.py does.
        dump = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % routine_start,
             "--stop-address=%#x" % routine_stop, str(BINARY)],
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
            # objdump pads the opcode, so split opcode/operands
            # on whitespace instead of matching "call *" literally.
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
                # Only jumps leaving the routine count as tail
                # jumps; jumps back inside are control flow. The
                # operand's first token is the destination address
                # (a label suffix may follow it).
                dest = operand.split()[0] if operand.split() else ""
                try:
                    dest_value = int(dest, 16)
                except ValueError:
                    dest_value = None
                if (dest_value is None
                        or not (routine_start <= dest_value < routine_stop)):
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
