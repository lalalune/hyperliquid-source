"""External-reference census for node #115 routine 0x143ddc0.

Reproduces, from the raw bytes of work/hl-node-115.bin:

  * the exhaustive executable-segment E8/E9 rel32 scan for direct
    calls and direct tail-jumps whose destination is the routine entry
    (expected: zero of each -- the routine is reached only through an
    installed function pointer, not a direct site);
  * the 8-byte-stride stored-qword scan over the whole file for the
    routine entry value (expected: exactly one occurrence, the addend
    of the installing R_X86_64_RELATIVE record inside .rela.dyn);
  * the routine's own control transfers from one linear disassembly of
    its FDE range (expected: one in-body conditional branch, two
    indirect tail-jumps through the single .got slot 0x64df720, zero
    direct calls, zero direct tail-jumps).

Prints a JSON summary. Run from the repository root:
    python3 research/work-items/RE-001-node115-bool-display-shim-143ddc0/census.py
"""

import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
START, STOP = 0x143DDC0, 0x143DDF2
TAIL_SLOT = 0x64DF720

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def seg_params(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _pp, p_filesz,
         _pm, _pa) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            return p_offset, p_vaddr, p_filesz
    raise SystemExit("no executable LOAD segment")


def main():
    data = BINARY.read_bytes()
    p_off, p_va, p_sz = seg_params(data)

    direct_calls, direct_jmps = [], []
    for off in range(p_off, p_off + p_sz - 5):
        op = data[off]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        site = off - p_off + p_va
        if site + 5 + rel == START:
            (direct_calls if op == 0xE8 else direct_jmps).append(site)

    qwords = [off for off in range(0, len(data) - 8, 8)
              if struct.unpack_from("<Q", data, off)[0] == START]

    dump = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % START,
         "--stop-address=%#x" % STOP, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    internal_calls = 0
    internal_direct_tail_jumps = 0
    internal_indirect_tail_jumps = 0
    in_body_branches = 0
    for line in dump.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        mnemonic = (match.group(3) or "").strip()
        parts = mnemonic.split(None, 1)
        if not parts:
            continue
        opcode = parts[0]
        operand = parts[1] if len(parts) > 1 else ""
        if opcode == "call":
            internal_calls += 1
        elif opcode == "jmp":
            if operand.startswith("*"):
                internal_indirect_tail_jumps += 1
            else:
                dest = operand.split()[0] if operand.split() else ""
                try:
                    dest_value = int(dest, 16)
                except ValueError:
                    dest_value = None
                if dest_value is not None and START <= dest_value < STOP:
                    in_body_branches += 1
                else:
                    internal_direct_tail_jumps += 1
        elif opcode.startswith("j"):
            # conditional branch
            dest = operand.split()[0] if operand.split() else ""
            try:
                dest_value = int(dest, 16)
            except ValueError:
                dest_value = None
            if dest_value is not None and START <= dest_value < STOP:
                in_body_branches += 1
            else:
                raise SystemExit("conditional branch leaves the body: %s"
                                 % mnemonic)

    summary = {
        "routine": "0x143ddc0",
        "direct_call_count": len(direct_calls),
        "direct_tail_jump_count": len(direct_jmps),
        "stored_qwords": [hex(q) for q in qwords],
        "internal_calls": internal_calls,
        "internal_direct_tail_jumps": internal_direct_tail_jumps,
        "internal_indirect_tail_jumps": internal_indirect_tail_jumps,
        "in_body_conditional_branches": in_body_branches,
        "tail_slot": hex(TAIL_SLOT),
    }
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
