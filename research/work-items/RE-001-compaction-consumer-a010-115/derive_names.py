#!/usr/bin/env python3
"""Derive the global int->name registry and pair-table contents from the
committed initializer disassembly (initializer.txt) plus the raw binary.

Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-consumer-a010-115/derive_names.py

The static initializer 0x5efbd80 builds two tables on the stack and range-
inserts them into two globals:
  * 21 {int, string, string} entries (keys 1..21) into the pair map at
    0x6503a00 via pair_range_insert 0x5ef0ea0 (stride 0x48);
  * 9 {int, string} entries (keys 0..8) into the int map at 0x65039c8 via
    range_insert 0x5ef11e0 (stride 0x28).
The 21-entry pair table is the one this work item's main routine reads
through map::at(i) (the FIRST string of each pair becomes the
"compaction.L<n>.<name>" key); the 9-entry registry is recorded for
context (it is the table #3145's consumer reads).  The 9th registry name
(key 8) is not a literal but the join lookup1(4) + "-" + lookup2(1),
resolved here from name_lookup1.txt and name_lookup2.txt plus the raw
binary.

Method: the construction region is straight-line code, so the string
literals assigned (in address order) pair with the integer keys stored
(in address order) one-to-one.  The script asserts the key slots follow
the exact array stride before zipping, so a reordered or miscounted
table fails loudly instead of silently mis-pairing.

(Adapted from the derive_names.py of PR #3145, which first pinned both
tables from the same initializer; the derivation and its assertions are
unchanged.)
"""

import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

INIT = (HERE / "initializer.txt").read_text().splitlines()
LOOKUP1 = (HERE / "name_lookup1.txt").read_text().splitlines()
LOOKUP2 = (HERE / "name_lookup2.txt").read_text().splitlines()
JOIN = (HERE / "name_join.txt").read_text().splitlines()

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


def derive_registry():
    # Second array: keys 0..8, slots -0x1900 + k*0x28, strings at slot+8.
    keys = collect_keys(0x5EFC922, 0x5EFCAB0)
    assert [k for k, _ in keys] == list(range(9)), keys
    assert [s for _, s in keys] == [-0x1900 + k * 0x28 for k in range(9)], keys
    lits = collect_assigns(0x5EFC905, 0x5EFCAB0)
    assert len(lits) == 8, lits
    names = [cstr(lit) for _, lit in lits]
    # Key 8: name_join(out, esi=4, edx=1) -> lookup1(4) + "-" + lookup2(1).
    s1 = derive_lookup1()
    s2 = derive_lookup2()
    names.append(s1 + "-" + s2)
    return [{"key": k, "name": n} for k, n in zip(range(9), names)]


def derive_lookup1():
    # name_lookup1.txt: for input 4 the function returns the static string
    # at 0x65049c0, built as 26 bytes: 16 from .rodata 0x453980, then 16
    # from .rodata 0x455900 stored at +0xa (so bytes 10..25 come from it).
    data = BIN.read_bytes()
    assert "65049c0" in "\n".join(LOOKUP1)
    assert any("cmp    $0x4,%ebx" in ln for ln in LOOKUP1)
    chunk1 = data[0x453980:0x453990]
    chunk2 = data[0x455900:0x455910]
    return (chunk1[:10] + chunk2[:16]).decode("utf-8")


def derive_lookup2():
    # name_lookup2.txt: for input 1 the function returns the static string
    # at 0x6504940, built inline: movl $0x706f7473 ("stop") at 0x6504950,
    # movb $0x73 ('s') at 0x6504954, length 5.
    text = "\n".join(LOOKUP2)
    assert "6504940" in text
    assert "movl   $0x706f7473" in text
    assert "movb   $0x73" in text
    return "stops"


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
    out = {"registry": derive_registry(), "pair_table": derive_pairs()}
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
