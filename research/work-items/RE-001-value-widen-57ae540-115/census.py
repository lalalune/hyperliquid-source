"""Reproduce the reference census for the RE-001-value-widen-
57ae540-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-value-widen-57ae540-115/census.py

Method:
  * Parse the ELF program headers to find the single executable
    LOAD segment, then scan it exhaustively for E8 (direct call)
    and E9 (tail jump) opcodes whose rel32 target is the pinned
    body at 0x57ae540.  Every candidate is confirmed as a real
    instruction by decoding from the candidate address with
    objdump; a candidate that does not decode to a call/jump to
    the target there is rejected, not counted.
  * Classify the body's own control transfers from one linear
    disassembly of the whole FDE range (true instruction starts
    only), and read the 22-entry jump table at 0x931abc from
    the segment bytes.
  * Scan the raw binary at 8-byte strides for qwords equal to
    the target address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    the target address.

Expected result for the digest-verified node #115 work binary:
see records.json (census block) and callers.tsv.
"""

import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
TARGET = 0x57AE540
BODY = (0x57AE540, 0x57AE642)
TABLE = 0x931ABC
TABLE_ENTRIES = 22

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def exec_segment(data):
    """Return (file offset, vaddr, file size) of the R E LOAD segment."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _ = \
            struct.unpack_from("<IIQQQQI", data,
                               e_phoff + i * e_phentsize)
        if p_type == 1 and p_flags & 0x1:
            return p_offset, p_vaddr, p_filesz
    raise ValueError("no executable LOAD segment")


def any_segment_voff(data, vaddr):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _ = \
            struct.unpack_from("<IIQQQQI", data,
                               e_phoff + i * e_phentsize)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return vaddr - p_vaddr + p_offset
    raise ValueError("vaddr %#x not in any LOAD" % vaddr)


def disasm_window(start, stop):
    """objdump disassembly of [start, stop) as {addr: (mnemonic, rest)}."""
    text = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    insns = {}
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            rest = (m.group(3) or "").strip()
            if rest:
                parts = rest.split(None, 1)
                insns[addr] = (parts[0], parts[1] if len(parts) > 1 else "")
    return insns


def collect():
    data = BINARY.read_bytes()
    off, vaddr, size = exec_segment(data)
    seg = data[off:off + size]

    raw_sites = []
    for i in range(len(seg) - 5):
        if seg[i] in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", seg, i + 1)[0]
            if vaddr + i + 5 + rel == TARGET:
                raw_sites.append((vaddr + i, seg[i] == 0xE8))

    calls, jumps, rejected = [], [], []
    for site, is_call in raw_sites:
        insns = disasm_window(site, site + 5)
        ins = insns.get(site)
        if ins and ins[0] == ("call" if is_call else "jmp") \
                and ins[1].split()[0] == "%x" % TARGET:
            (calls if is_call else jumps).append(site)
        else:
            rejected.append(site)

    body_insns = disasm_window(*BODY)
    internal = sorted(a for a in body_insns if a != BODY[0])
    table_off = any_segment_voff(data, TABLE)
    entries = []
    for i in range(TABLE_ENTRIES):
        delta = struct.unpack_from("<i", data, table_off + 4 * i)[0]
        entries.append(TABLE + delta)

    qwords = sum(
        1 for i in range(0, len(data) - 8, 8)
        if data[i:i + 8] == struct.pack("<Q", TARGET))

    reloc_text = subprocess.run(
        ["readelf", "-r", "-W", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    reladdends = sum(
        1 for line in reloc_text.splitlines()
        if "%x" % TARGET in line.lower())

    return {
        "direct_calls": ["%#x" % s for s in sorted(calls)],
        "tail_jumps": ["%#x" % s for s in sorted(jumps)],
        "rejected_candidates": ["%#x" % s for s in sorted(rejected)],
        "body_instruction_starts": len(body_insns),
        "body_internal_starts": len(internal),
        "jump_table_entries": ["%#x" % e for e in entries],
        "stored_qwords": qwords,
        "relative_addends": reladdends,
    }


def main():
    result = collect()
    print("direct call sites: %d" % len(result["direct_calls"]))
    print("tail jump sites: %d" % len(result["tail_jumps"]))
    print("rejected byte-scan candidates: %d"
          % len(result["rejected_candidates"]))
    print("jump table entries: %d" % len(result["jump_table_entries"]))
    print("stored qwords: %d" % result["stored_qwords"])
    print("RELATIVE addends: %d" % result["relative_addends"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
