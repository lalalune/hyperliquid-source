#!/usr/bin/env python3
"""Census for this work item: exhaustive direct call / tail-jump scan.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-consumer-a010-115/census.py

Method: scan every executable PT_LOAD segment byte-by-byte for E8 (call)
and E9 (jmp) rel32 forms, compute each candidate target, and keep only
the sites whose target is one of the pinned addresses.  Every kept site
is then confirmed by disassembling its containing FDE (from readelf) and
checking that an instruction really starts at the site and calls/jumps
to the target.  Stored qwords are 8-byte little-endian occurrences of a
pinned address anywhere in the file, mapped to virtual addresses through
the PT_LOAD headers; occurrences inside .rela.dyn are relocation addends,
reported separately.  RELATIVE relocations with a pinned address as the
addend are listed from readelf -r.

The output files callers.tsv and relocations.txt in this directory are
the committed census; verify.py re-runs this logic and compares.
"""

import json
import re
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    "main": 0x5EFA010,
    "filler": 0x5EF1FA0,
    "final": 0x5EF5D40,
    "outer_insert": 0x5EF1630,
    "inner_insert": 0x5EF1480,
    "move_assign": 0x5EECDB0,
    "node_create": 0x5EED170,
    "tree_free": 0x5EEBCC0,
    "tree_erase": 0x5EEC510,
    "fmt_pct": 0x5EEC680,
    "map_node_create": 0x5EF3ED0,
    "map_find_insert": 0x5EF40A0,
    "string_move_assign": 0x5EEBB20,
    "name_getter": 0x5EEB7F0,
    "scalar_sum": 0x5F6C300,
    "scalar_sum2": 0x5DA4DE0,
    "tag_index": 0x5FC9E20,
    "name_join": 0x5FCA2D0,
    "name_lookup1": 0x5FC9960,
    "name_lookup2": 0x5FC9CE0,
    "key_a": 0x5FCA050,
    "key_b": 0x5FCA190,
    "key_c": 0x5FC9ED0,
    "key_d": 0x5FC9F80,
    "u64str": 0x5D4F970,
    "global_pair_map": 0x6503A00,
    "fmt_global": 0x64ED730,
    "allocator_global": 0x64ED5D8,
}

FDE_RE = re.compile(r"pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)")
CALL_RE = re.compile(
    r"^\s+([0-9a-f]+):\t[0-9a-f ]+\t(call|jmp)\s+([0-9a-f]+)", re.M)


def load_segments():
    data = BIN.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    exec_segs, loads = [], []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _p, p_filesz, _m, _a = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type != 1:
            continue
        loads.append((p_offset, p_vaddr, p_filesz))
        if p_flags & 1:
            exec_segs.append((p_offset, p_vaddr, p_filesz))
    return data, exec_segs, loads


def file_offset_to_vaddr(loads, offset):
    for p_offset, p_vaddr, p_filesz in loads:
        if p_offset <= offset < p_offset + p_filesz:
            return p_vaddr + (offset - p_offset)
    return None


def fde_ranges():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        check=True, capture_output=True, text=True).stdout
    ranges = []
    for line in out.splitlines():
        m = FDE_RE.search(line)
        if m:
            ranges.append((int(m.group(1), 16), int(m.group(2), 16)))
    return sorted(ranges)


def containing_fde(ranges, addr):
    for start, stop in ranges:
        if start <= addr < stop:
            return (start, stop)
    return None


def disassemble(start, stop):
    out = subprocess.run(
        ["objdump", "-d",
         "--start-address=%#x" % start, "--stop-address=%#x" % stop,
         str(BIN)],
        check=True, capture_output=True, text=True).stdout
    found = {}
    for m in CALL_RE.finditer(out):
        found[int(m.group(1), 16)] = (m.group(2), int(m.group(3), 16))
    return found


def scan_calls(data, exec_segs, ranges):
    """Return {target: {'call': [sites], 'jmp': [sites]}} (confirmed)."""
    result = {t: {"call": [], "jmp": []} for t in TARGETS.values()}
    dis_cache = {}
    for p_offset, p_vaddr, p_filesz in exec_segs:
        seg = data[p_offset:p_offset + p_filesz]
        for opcode, kind in ((0xE8, "call"), (0xE9, "jmp")):
            idx = 0
            while True:
                j = seg.find(bytes([opcode]), idx)
                if j < 0:
                    break
                idx = j + 1
                if j + 5 > len(seg):
                    continue
                rel = struct.unpack_from("<i", seg, j + 1)[0]
                site = p_vaddr + j
                target = site + 5 + rel
                if target not in result:
                    continue
                fde = containing_fde(ranges, site)
                if fde is None:
                    continue
                if fde not in dis_cache:
                    dis_cache[fde] = disassemble(*fde)
                got = dis_cache[fde].get(site)
                if got == (kind, target):
                    result[target][kind].append(site)
    for target in result:
        result[target]["call"].sort()
        result[target]["jmp"].sort()
    return result


def scan_stored_qwords(data, loads):
    """Return {target: [vaddr, ...]} for 8-byte LE occurrences."""
    result = {}
    sections = subprocess.run(
        ["readelf", "-S", "-W", str(BIN)],
        check=True, capture_output=True, text=True).stdout
    rela = None
    for line in sections.splitlines():
        m = re.search(r"\.rela\.dyn\s+RELA\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                      line)
        if m:
            rela = (int(m.group(1), 16), int(m.group(2), 16),
                    int(m.group(3), 16))
    for target in TARGETS.values():
        pat = struct.pack("<Q", target)
        hits, idx = [], 0
        while True:
            j = data.find(pat, idx)
            if j < 0:
                break
            idx = j + 1
            vaddr = file_offset_to_vaddr(loads, j)
            if vaddr is None:
                continue
            in_rela = bool(rela and rela[0] <= vaddr < rela[0] + rela[2])
            hits.append((vaddr, in_rela))
        result[target] = hits
    return result


def scan_relative_relocations():
    out = subprocess.run(["readelf", "-r", str(BIN)],
                         check=True, capture_output=True, text=True).stdout
    found = {t: [] for t in TARGETS.values()}
    for line in out.splitlines():
        m = re.match(
            r"([0-9a-f]+)\s+000000000008\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
            line.strip())
        if not m:
            continue
        offset, addend = int(m.group(1), 16), int(m.group(2), 16)
        if addend in found:
            found[addend].append(offset)
    for target in found:
        found[target].sort()
    return found


def main():
    data, exec_segs, loads = load_segments()
    ranges = fde_ranges()
    calls = scan_calls(data, exec_segs, ranges)
    stored = scan_stored_qwords(data, loads)
    rels = scan_relative_relocations()
    tsv_lines = ["target\tkind\tsite"]
    for name, target in TARGETS.items():
        for kind in ("call", "jmp"):
            for site in calls[target][kind]:
                tsv_lines.append("0x%x\t%s\t0x%x" % (target, kind, site))
    (HERE / "callers.tsv").write_text("\n".join(tsv_lines) + "\n")
    rel_lines = []
    for name, target in TARGETS.items():
        rel_lines.append("0x%x relative_records:%s" % (
            target, (" " + " ".join("0x%x" % o for o in rels[target]))
            if rels[target] else " none"))
        rel_lines.append("0x%x stored_qwords:%s" % (
            target, (" " + " ".join(
                "0x%x%s" % (v, " (in .rela.dyn, addend field)" if r else "")
                for v, r in stored[target])) if stored[target] else " none"))
    (HERE / "relocations.txt").write_text("\n".join(rel_lines) + "\n")
    for name, target in TARGETS.items():
        print("%s 0x%x: calls=%s jmps=%s rel=%s stored=%s" % (
            name, target, [hex(s) for s in calls[target]["call"]],
            [hex(s) for s in calls[target]["jmp"]],
            [hex(o) for o in rels[target]],
            [(hex(v), r) for v, r in stored[target]]))


if __name__ == "__main__":
    main()
