"""Reproduce the reference census for the RE-001-mutex-wrappers-115
packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-mutex-wrappers-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it for E8 (direct call) and E9
    (tail jump) opcodes whose rel32 target is the lock wrapper
    (0x60d5230), the unlock wrapper (0x60d52f0), or the lock stub
    (0x606ca00). Every candidate is confirmed as a real
    instruction by decoding from the candidate address with
    objdump; a candidate that does not decode to a call/jump to
    the target there is rejected, not counted.
  * Classify each wrapper's own control transfers from one
    linear disassembly of the whole window (true instruction
    starts only). A jump whose target lies inside the window is
    an internal jump, not a tail jump. Each wrapper's
    landing-pad stub at the end of its window jumps to a shared
    cleanup block outside the window; the census counts it
    separately and the README explains it, since it is not a
    normal-flow exit. The lock stub's jump is its whole body,
    so it counts as a direct tail jump of the stub window.
  * Scan the raw binary for qwords equal to each target
    address, and parse .rela.dyn for RELATIVE records
    mentioning them. In this RELA binary code addresses are
    not stored as qwords and draw no RELATIVE entries; both
    scans are expected empty, and the wrappers are reached
    only by direct calls, tail jumps, and the lock stub.

Expected result: lock 157 direct calls, 1 tail jump (the
stub); unlock 669 direct calls, 5 tail jumps; stub 2 direct
calls, 0 tail jumps; no stored qwords and no RELATIVE slots
for any of the three addresses.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    "lock": 0x60D5230,
    "unlock": 0x60D52F0,
    "stub": 0x606CA00,
}

WINDOWS = {
    "lock": (0x60D5230, 0x60D52C5, 0x60D52B9),
    "lock_cleanup": (0x60D5200, 0x60D5225, None),
    "unlock": (0x60D52F0, 0x60D5385, 0x60D5379),
    "unlock_cleanup": (0x60D52C6, 0x60D52EB, None),
    "stub": (0x606CA00, 0x606CA09, None),
}

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
    relative = rela_relative(data)
    for name, target in TARGETS.items():
        calls, jumps = [], []
        for match in re.finditer(rb"[\xe8\xe9]", segment):
            i = match.start()
            if i + 5 > seg_size:
                continue
            rel = struct.unpack("<i", segment[i + 1: i + 5])[0]
            if seg_vaddr + i + 5 + rel == target:
                site = seg_vaddr + i
                decoded = objdump(site, site + 0x10)
                if not decoded or decoded[0][0] != site:
                    continue
                mnemonic = decoded[0][2]
                if segment[i] == 0xE8 and mnemonic.startswith("call"):
                    calls.append(site)
                elif segment[i] == 0xE9 and mnemonic.startswith("jmp"):
                    jumps.append(site)
        print("%s %#x: direct calls: %s" % (name, target, [hex(c) for c in calls]))
        print("%s %#x: tail jumps: %s" % (name, target, [hex(j) for j in jumps]))
        pattern = target.to_bytes(8, "little")
        qwords = []
        index = 0
        while True:
            found = data.find(pattern, index)
            if found < 0:
                break
            qwords.append(found)
            index = found + 1
        print("%s %#x: stored qwords (file offsets): %s"
              % (name, target, [hex(q) for q in qwords]))
        slots = sorted(v for v, (add, _e) in relative.items() if add == target)
        print("%s %#x: RELATIVE slots: %s" % (name, target, [hex(s) for s in slots]))

    direct_re = re.compile(r"^(call|jmp)\s+([0-9a-f]+)\b")
    for name, (start, stop, stub_start) in WINDOWS.items():
        own = objdump(start, stop)
        internal_calls, internal_jumps, stubs = [], [], []
        for address, _raw, mnemonic in own:
            match = direct_re.match(mnemonic)
            if match:
                kind, target_text = match.group(1), match.group(2)
                target = int(target_text, 16)
                if kind == "call":
                    internal_calls.append(address)
                elif start <= target < stop:
                    continue  # internal jump, not a tail jump
                elif stub_start is not None and address >= stub_start:
                    stubs.append(address)
                else:
                    internal_jumps.append(address)
        print("%s window %#x: internal direct calls: %s"
              % (name, start, [hex(c) for c in internal_calls]))
        print("%s window %#x: internal direct tail jumps: %s"
              % (name, start, [hex(j) for j in internal_jumps]))
        print("%s window %#x: landing-pad-stub tail jumps: %s"
              % (name, start, [hex(s) for s in stubs]))


if __name__ == "__main__":
    main()
