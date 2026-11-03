"""Reproduce the reference census for the RE-001-chain-reset-dispatch-4dc00-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-chain-reset-dispatch-4dc00-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it for E8 (direct call) and E9
    (tail jump) opcodes whose rel32 target is the chain reset
    routine (0x5d4dc00). Candidates are found with a
    C-accelerated byte search and every candidate is confirmed
    as a real instruction by decoding from the candidate address
    with objdump; a candidate that does not decode to a
    call/jump to the target there is rejected, not counted.
  * Classify the routine's own control transfers from one linear
    disassembly of the whole routine range (true instruction
    starts only). A jump whose target lies inside the routine
    range is an internal jump, not a tail jump. The landing-pad
    stub at the end of the range jumps to a shared cleanup block
    outside the range; the census counts it separately and the
    README explains it, since it is not a normal-flow exit.
  * Scan the raw binary for qwords equal to the routine address.
    In this RELA binary the hits are the .rela.dyn addend fields,
    not runtime pointers; the runtime slots themselves are
    recorded from the RELATIVE relocation entries.
  * Parse the .rela.dyn section (located via readelf -S) for
    RELATIVE records mentioning the routine address, and read
    each slot's neighbouring slots' addends the same way, so
    pointer_slots.tsv can be checked against the dump rather
    than asserted.

Expected result: 0 direct calls, 0 tail jumps, 4 stored-qword
addend file offsets, 4 RELATIVE slots, 8 internal direct calls,
1 internal indirect call, 1 internal direct tail jump, 1
landing-pad-stub tail jump.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x5D4DC00
ROUTINE_START, ROUTINE_STOP = 0x5D4DC00, 0x5D4DD50

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def executable_segment(data):
    phoff = struct.unpack("<Q", data[32:40])[0]
    phentsize, phnum = struct.unpack("<HH", data[54:58])
    for i in range(phnum):
        entry = data[phoff + i * phentsize: phoff + (i + 1) * phentsize]
        p_type, p_flags, p_offset, p_vaddr, _p, p_filesz, _m, _a = struct.unpack(
            "<IIQQQQQQ", entry[:56])
        if p_type == 1 and p_flags & 1:  # PT_LOAD, executable
            return p_offset, p_vaddr, p_filesz
    raise AssertionError("no executable LOAD segment")


def objdump(start, stop):
    text = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    instructions = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if not mnemonic and instructions and address == instructions[-1][0] + len(instructions[-1][1]):
            instructions[-1] = (instructions[-1][0], instructions[-1][1] + raw,
                                instructions[-1][2])
        else:
            instructions.append((address, raw, mnemonic))
    return instructions


def rela_relative(data):
    text = subprocess.run(["readelf", "-S", str(BINARY)],
                          capture_output=True, text=True, check=True).stdout
    offset = size = None
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if ".rela.dyn" in line:
            parts = line.split()
            # [ 9] .rela.dyn RELA addr offset; size is on the next line.
            offset = int(parts[5], 16)
            size = int(lines[index + 1].split()[0], 16)
            break
    if offset is None or size is None:
        raise AssertionError("could not locate .rela.dyn")
    relative = {}
    for i in range(0, size, 24):
        entry_off, info, addend = struct.unpack(
            "<QQq", data[offset + i: offset + i + 24])
        if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
            relative[entry_off] = (addend, offset + i)
    return relative


def main():
    data = BINARY.read_bytes()
    seg_off, seg_vaddr, seg_size = executable_segment(data)
    segment = data[seg_off: seg_off + seg_size]
    calls, jumps = [], []
    for match in re.finditer(rb"[\xe8\xe9]", segment):
        i = match.start()
        if i + 5 > seg_size:
            continue
        rel = struct.unpack("<i", segment[i + 1: i + 5])[0]
        if seg_vaddr + i + 5 + rel == TARGET:
            site = seg_vaddr + i
            decoded = objdump(site, site + 0x10)
            if not decoded or decoded[0][0] != site:
                continue
            mnemonic = decoded[0][2]
            if segment[i] == 0xE8 and mnemonic.startswith("call"):
                calls.append(site)
            elif segment[i] == 0xE9 and mnemonic.startswith("jmp"):
                jumps.append(site)
    print("routine 0x5d4dc00: direct calls: %s"
          % [hex(c) for c in calls])
    print("routine 0x5d4dc00: tail jumps: %s"
          % [hex(j) for j in jumps])

    pattern = TARGET.to_bytes(8, "little")
    qwords = []
    index = 0
    while True:
        found = data.find(pattern, index)
        if found < 0:
            break
        qwords.append(found)
        index = found + 1
    print("routine 0x5d4dc00: stored qwords (file offsets): %s"
          % [hex(q) for q in qwords])

    relative = rela_relative(data)
    slots = sorted(v for v, (add, _e) in relative.items() if add == TARGET)
    print("routine 0x5d4dc00: RELATIVE slots: %s" % [hex(s) for s in slots])
    for slot in slots:
        neighbours = []
        for delta in (-2, -1, 0, 1, 2):
            neighbours.append(hex(relative[slot + delta * 8][0])
                              if slot + delta * 8 in relative else None)
        print("slot %#x neighbours: %s" % (slot, neighbours))
        print("slot %#x rela entry file offset: %#x"
              % (slot, relative[slot][1]))

    own = objdump(ROUTINE_START, ROUTINE_STOP)
    internal_calls, internal_indirect, internal_jumps, stubs = [], [], [], []
    direct_re = re.compile(r"^(call|jmp)\s+([0-9a-f]+)\b")
    for address, _raw, mnemonic in own:
        match = direct_re.match(mnemonic)
        if match:
            kind, target_text = match.group(1), match.group(2)
            target = int(target_text, 16)
            if kind == "call":
                internal_calls.append(address)
            elif ROUTINE_START <= target < ROUTINE_STOP:
                continue  # internal jump, not a tail jump
            elif address >= 0x5D4DD44:
                stubs.append(address)
            else:
                internal_jumps.append(address)
        elif mnemonic.startswith("call") or mnemonic.startswith("jmp"):
            # Indirect transfer (register or memory operand).
            if mnemonic.startswith("call"):
                internal_indirect.append(address)
    print("routine 0x5d4dc00: internal direct calls: %s"
          % [hex(c) for c in internal_calls])
    print("routine 0x5d4dc00: internal indirect calls: %s"
          % [hex(c) for c in internal_indirect])
    print("routine 0x5d4dc00: internal direct tail jumps: %s"
          % [hex(c) for c in internal_jumps])
    print("routine 0x5d4dc00: landing-pad-stub tail jumps: %s"
          % [hex(c) for c in stubs])


if __name__ == "__main__":
    main()
