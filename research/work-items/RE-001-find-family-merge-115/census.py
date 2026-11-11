#!/usr/bin/env python3
"""Reproducible caller census for RE-001-find-family-merge-115 (node #115).

One objdump pass over the whole binary counts every direct call/jump
and every lea that references one of the packet's routines, and records
the enclosing FDE for each site. Run from the repository root:

    python3 research/work-items/RE-001-find-family-merge-115/census.py

Writes callers.tsv next to this script (sorted by site address) and
prints the per-target counts to stdout. verify.py re-runs this script
and requires callers.tsv to come out byte-identical.
"""

import bisect
import collections
import re
import subprocess
import sys
from pathlib import Path

BINARY = Path(__file__).resolve().parents[3] / "work" / "hl-node-115.bin"

TARGETS = {
    0x609D0E0: "host_a",
    0x609D08E: "host_a_cleanup",
    0x60BEDC0: "host_b",
    0x60BEA8C: "host_b_catch",
    0x609C8C0: "merge_driver",
    0x6098510: "worker_wrapper",
    0x60B7CD0: "range_ctor",
    0x6095B80: "node_clone",
    0x5D38260: "rehash",
    0x61D10A0: "escape_assign",
    0x61D0EE0: "escape_decoder",
    0x61D1480: "bool_parser",
    0x61D1540: "stoull_parser",
    0x61D18A0: "stoll_parser",
    0x61D1B90: "stoi_parser",
    0x61D1840: "u32_parser",
    0x61D17D0: "u8_parser",
    0x61D1B30: "i32_parser",
    0x61D1EF0: "stoull_alias",
    0x61D1E30: "stod_parser",
    0x61C7FC0: "hex_decode",
    0x61C7DC0: "hexval",
    0x60BE160: "enum_60be160",
    0x60BE2B0: "enum_60be2b0",
    0x60BE400: "enum_60be400",
    0x60BE550: "enum_60be550",
    0x60BE6A0: "enum_60be6a0",
    0x60BE7F0: "enum_60be7f0",
    0x60BE940: "enum_60be940",
    0x6080B10: "plain_table",
    0x6080A71: "plain_table_cleanup",
    0x60818F0: "block_table",
    0x608183A: "block_table_cleanup",
    0x6098AD0: "element_scan_host",
    0x6098A9C: "element_scan_host_cleanup",
    0x609BCB0: "walker",
    0x607D9F0: "cstr_ctor_607d9f0",
    0x6193B40: "plain_creator",
    0x6193A00: "plain_ctor",
    0x60DBD80: "block_creator",
    0x60DB710: "block_ctor",
    0x607E020: "options_list_destroy",
    0x609A1B0: "map_find_name",
    0x609A2F0: "map_erase_next",
    0x609BAD0: "map_insert",
    0x61CF610: "cstr_dup",
    0x5D350C0: "counted_release",
    0x6099CE0: "options_record_append",
    0x60B79B0: "clear_string",
    0x609A740: "entry",
    0x6099E70: "find_e70",
    0x609BA30: "no_equals",
    0x609B8A0: "resolve_no_equals",
    0x609B700: "kind_dispatch",
    0x6096F40: "element_scan",
    0x60BA0B0: "name_lookup",
    0x60B84B0: "hash_name_find",
    0x60B79E0: "move_assign",
    0x61D1390: "ends_with",
    0x61D13E0: "str_compare",
    0x6097150: "fallback_delegate",
    0x6097110: "delegate_impl",
    0x60956F0: "zero_stub",
    0x609A410: "find_norm",
    0x60C1190: "parser",
    0x5D5B300: "map_clear",
    0x61CF670: "status_builder",
    0x5D35070: "shared_release",
    0x60BB9A0: "matcher",
    0x60971C0: "resolver",
    0x60B9D70: "value_copy",
    0x5E33FB0: "value_dtor",
    0x60B7D80: "cstr_ctor_60b7d80",
}


def load_fdes(binary):
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(binary)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def main():
    fdes = load_fdes(BINARY)
    starts = [s for s, _ in fdes]

    def enclosing(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e = fdes[i]
        return (s, e) if s <= addr < e else None

    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    rows = []
    counts = collections.Counter()
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t(.*)", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        insn = m.group(2).strip()
        mm = re.search(r"\b(call|jmp)\s+([0-9a-f]+)\s", insn)
        if mm:
            t = int(mm.group(2), 16)
            if t in TARGETS:
                enc = enclosing(addr)
                rows.append((addr, t, TARGETS[t],
                             "%#x..%#x" % enc if enc else "?",
                             mm.group(1)))
                counts[(TARGETS[t], mm.group(1))] += 1
        lm = re.search(r"\blea\b.*#\s+([0-9a-f]+)", insn)
        if lm:
            t = int(lm.group(1), 16)
            if t in TARGETS:
                enc = enclosing(addr)
                rows.append((addr, t, TARGETS[t],
                             "%#x..%#x" % enc if enc else "?",
                             "lea"))
                counts[(TARGETS[t], "lea")] += 1
    rows.sort()
    out_path = Path(__file__).resolve().parent / "callers.tsv"
    with open(out_path, "w") as f:
        f.write("site\ttarget\tcaller\tkind\n")
        for addr, t, name, enc, kind in rows:
            f.write("%#x\t%#x\t%s\t%s\n" % (addr, t, enc, kind))
    for (name, kind), n in sorted(counts.items()):
        print("%-24s %-4s %d" % (name, kind, n))
    print("rows: %d" % len(rows))


if __name__ == "__main__":
    main()
