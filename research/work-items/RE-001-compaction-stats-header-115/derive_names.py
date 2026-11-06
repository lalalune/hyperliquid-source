#!/usr/bin/env python3
"""Derive the global int->pair registry contents from the committed
initializer disassembly (initializer.txt) plus the raw binary.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-stats-header-115/derive_names.py

The static initializer 0x5efbd80 builds a 21-entry {int, string, string}
table on the stack (stride 0x48, keys 1..21) and pair_range-inserts it
into the global pair map at 0x6503a00 via 0x5ef0ea0.  This script pins
the table: the construction region is straight-line code, so the string
literals assigned (in address order) pair with the integer keys stored
(in address order) one-to-one.  The script asserts the key slots follow
the exact array stride before zipping, so a reordered or miscounted
table fails loudly instead of silently mis-pairing.

(Adapted from the derive_names.py of PR #3164, which first pinned this
table from the same initializer; the pair derivation and its assertions
are unchanged.  The 9-entry int registry that #3164 also derived is not
needed here and is not re-derived.)
"""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

INIT = (HERE / "initializer.txt").read_text().splitlines()

ADDR_RE = re.compile(r"^\s+([0-9a-f]+):")
LEA_LIT_RE = re.compile(
    r"lea\s+[^,]+,%rsi\s+# ([0-9a-f]+)")
CALL_ASSIGN_RE = re.compile(r"call\s+5eebd00\b")
MOVL_KEY_RE = re.compile(
    r"movl\s+\$0x([0-9a-f]+),(-0x[0-9a-f]+)\(%rbp\)")


def addr_of(line):
    m = ADDR_RE.match(line)
    return int(m.group(1), 16) if m else None


def cstr(addr, limit=120):
    data = BIN.read_bytes()
    end = data.find(b"\x00", addr)
    return data[addr:end][:limit].decode("utf-8")


def collect_assigns(start, stop):
    """(call-site addr, literal addr) for string_assign in [start, stop)."""
    out, last_lit = [], None
    for line in INIT:
        a = addr_of(line)
        if a is None:
            continue
        m = LEA_LIT_RE.search(line)
        if m:
            last_lit = int(m.group(1), 16)
        if CALL_ASSIGN_RE.search(line) and start <= a < stop:
            assert last_lit is not None, "assign without literal at %#x" % a
            out.append((a, last_lit))
            last_lit = None
    return out


def collect_keys(start, stop):
    """(key, slot offset) for movl $key, disp(%rbp) in [start, stop)."""
    out = []
    for line in INIT:
        a = addr_of(line)
        if a is None or not (start <= a < stop):
            continue
        m = MOVL_KEY_RE.search(line)
        if m:
            out.append((int(m.group(1), 16), -int(m.group(2)[3:], 16)))
    return out


def derive_pairs():
    keys = collect_keys(0x5EFBE42, 0x5EFC660)
    assert [k for k, _ in keys] == list(range(1, 22)), keys
    assert [s for _, s in keys] == [-0x1900 + k * 0x48 for k in range(21)], keys
    lits = collect_assigns(0x5EFBE12, 0x5EFC640)
    assert len(lits) == 42, len(lits)
    names = [cstr(lit) for _, lit in lits]
    return [{"key": k, "first": names[2 * i], "second": names[2 * i + 1]}
            for i, k in enumerate(range(1, 22))]


def main():
    out = {"pair_table": derive_pairs()}
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
