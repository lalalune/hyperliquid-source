"""Reproduce the reference census for the
RE-001-node115-gated-base-accessor-636c880 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node115-gated-base-accessor-636c880/census.py

Method:
  * Parse the ELF program headers to find the single executable LOAD
    segment, then scan it exhaustively for E8 (direct call) and E9
    (tail jump) opcodes whose rel32 target is the routine
    (0x636c880). Each candidate is confirmed as a real instruction by
    decoding from the candidate address with objdump. There are no
    direct calls and no tail jumps to this routine: it is reached
    only indirectly, through the function pointer the dynamic loader
    installs (see below).
  * Classify the routine's own control transfers from one linear
    disassembly of the whole routine range (true instruction starts
    only): the routine makes no calls at all, and all three of its
    direct jumps land inside itself (je 0x636c88e -> 0x636c8b0,
    jne 0x636c89a -> 0x636c8b0, ja 0x636c8a0 -> 0x636c8b0), so it has
    no direct tail jump out and no indirect transfer of any kind.
  * Scan the raw binary at 8-byte strides for qwords equal to the
    routine address. Exactly one occurs: it is the addend of an
    R_X86_64_RELATIVE record, i.e. a pointer to this routine stored
    into .data.rel.ro at relocation time.
  * Parse `readelf -r` output for RELATIVE records mentioning the
    routine address, and report the slot (r_offset) each installs.

Expected result for the digest-verified node #115 work binary:
0 direct calls, 0 tail jumps, exactly 1 stored qword (file offset
0x132eb0, inside .rela.dyn), exactly 1 RELATIVE addend installing the
routine pointer at .data.rel.ro slot 0x64ddc18, 0 internal calls,
0 internal direct tail jumps, 0 internal indirect calls, 0 internal
indirect tail jumps. The returned constant 0x64ddc20 is the adjacent
qword, 8 bytes after that slot.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGETS = (0x636C880,)
ROUTINE_START, ROUTINE_STOP = 0x636C880, 0x636C8B3

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
        # Stored qwords: report the raw file offset of every 8-byte
        # window equal to the routine address.
        qwords = []
        for off in range(0, len(data) - 8, 8):
            if struct.unpack_from("<Q", data, off)[0] == target:
                qwords.append(off)
        print("routine %#x: stored qwords (file offsets): %s"
              % (target, ["%#x" % q for q in qwords]))
        # True instruction starts from one linear disassembly of the
        # routine range; split lines are accumulated as verify.py does.
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
        slots = []
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                slots.append(line.split()[0])
        print("routine %#x: RELATIVE addends: %d, slots: %s"
              % (target, len(slots), ["0x%s" % s.lstrip("0") for s in slots]))


if __name__ == "__main__":
    main()
