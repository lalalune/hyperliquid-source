#!/usr/bin/env python3
"""Re-derive the binary-grounded claims of RE-001-optiontypeinfo-type2122-arm-115
from artifacts/node/115/hl-node and check them against records.json / the TSVs.

Checks (all read from the binary, never from memory):
  1. artifact digest == provenance/artifacts.json node #115 sha256
  2. apply jump table at 0x9786b4: 25 int32 relative offsets; entries 17-22
     resolve to 0x60bf07e; entry 14 resolves to 0x60bf05a
  3. comparator build (temp -0x3550): +0x18 manager = 0 at 0x60900c9,
     +0x20 invoker = 0 at 0x60900d4; type/verification pack qword at 0x458f68
  4. table_factory build (temp -0x3550): +0x18 = 0 at 0x60903ad,
     +0x20 = 0 at 0x60903b8, flags 0xc402 at 0x609041b
  5. type-22 helper forces flags 0x400: `or $0x4,%ch` at 0x6083a99
  6. CF factory builder zeroes the function slots: `pxor %xmm0,%xmm0` at 0x607ea16
  7. every literal in records.json reads back byte-identical from .rodata
  8. type22-entries.tsv rows == records.json entries (15 type-22, 0 type-21)
  9. reachability.tsv rows == records.json reachability (10 reach the arm, 5 custom)

Usage: python3 census.py  (run from the repository root)
Exit 0 when every check passes; prints FAIL lines otherwise.
"""
import csv
import hashlib
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BIN = os.path.join(REPO, "artifacts", "node", "115", "hl-node")
HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

failures = []
checks = [0]


def check(cond, label, detail=""):
    checks[0] += 1
    print(("PASS " if cond else "FAIL ") + label + ((" -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        failures.append(label)


def main():
    data = open(BIN, "rb").read()
    records = json.load(open(os.path.join(HERE, "records.json")))

    # 1. artifact digest
    check(hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256, "artifact digest",
          hashlib.sha256(data).hexdigest())

    # 2. jump table: int32 relative offsets at 0x9786b4 (.rodata vaddr == offset)
    base = 0x9786B4
    targets = []
    for t in range(25):
        off = struct.unpack_from("<i", data, base + 4 * t)[0]
        targets.append(base + off)
    check(all(targets[i] == 0x60BF07E for i in range(17, 23)),
          "jump table entries 17-22 -> 0x60bf07e", [hex(x) for x in targets[17:23]])
    check(targets[14] == 0x60BF05A, "jump table entry 14 -> 0x60bf05a", hex(targets[14]))

    # raw .text byte check helper: file offset == vaddr - 0x1000
    def text_bytes(vaddr, n):
        return data[vaddr - 0x1000: vaddr - 0x1000 + n]

    # 3. comparator build
    check(text_bytes(0x60900C9, 11) == bytes.fromhex("48c785c8caffff00000000"),
          "comparator +0x18 manager = 0 (0x60900c9)", text_bytes(0x60900C9, 11).hex())
    check(text_bytes(0x60900D4, 11) == bytes.fromhex("48c785d0caffff00000000"),
          "comparator +0x20 invoker = 0 (0x60900d4)", text_bytes(0x60900D4, 11).hex())
    check(struct.unpack_from("<Q", data, 0x458F68)[0] == 0x100000016,
          "type/verification pack qword 0x458f68 == 0x100000016",
          hex(struct.unpack_from("<Q", data, 0x458F68)[0]))

    # 4. table_factory build
    check(text_bytes(0x60903AD, 11) == bytes.fromhex("48c785c8caffff00000000"),
          "table_factory +0x18 manager = 0 (0x60903ad)", text_bytes(0x60903AD, 11).hex())
    check(text_bytes(0x60903B8, 11) == bytes.fromhex("48c785d0caffff00000000"),
          "table_factory +0x20 invoker = 0 (0x60903b8)", text_bytes(0x60903B8, 11).hex())
    check(text_bytes(0x609041B, 10) == bytes.fromhex("c78560cbffff02c40000"),
          "table_factory flags 0xc402 (0x609041b)", text_bytes(0x609041B, 10).hex())

    # 5. type-22 helper forces 0x400
    check(text_bytes(0x6083A99, 3) == bytes.fromhex("80cd04"),
          "helper or $0x4,%ch at 0x6083a99", text_bytes(0x6083A99, 3).hex())

    # 6. factory builder zeroes with pxor
    check(text_bytes(0x607EA16, 4) == bytes.fromhex("660fefc0"),
          "factory builder pxor %xmm0,%xmm0 at 0x607ea16", text_bytes(0x607EA16, 4).hex())

    # 7. literals read back byte-identical
    for lit in records["literals"]:
        va = int(lit["address"], 16)
        want = lit["text"].encode()
        got = data[va:va + len(want)]
        check(got == want, "literal %s %r" % (lit["address"], lit["text"]), got)

    # 8. entries TSV == records.json
    with open(os.path.join(HERE, "type22-entries.tsv")) as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    rec_entries = records["entries"]
    check(len(rows) == 15 and len(rec_entries) == 15, "15 type-22 entries", (len(rows), len(rec_entries)))
    check(all(r["type"] == "22" for r in rows), "0 type-21 entries in the census")
    tsv_names = sorted(r["name"] for r in rows)
    rec_names = sorted(e["name"] for e in rec_entries)
    check(tsv_names == rec_names, "TSV names == records.json names")
    for row in rows:
        match = [e for e in rec_entries if e["name"] == row["name"]]
        check(len(match) == 1 and match[0]["map"] == row["map"]
              and match[0]["verification"] == int(row["verification"])
              and match[0]["offset"] == "0x%x" % int(row["offset"], 16)
              and match[0]["flags"] == "0x%x" % int(row["flags"], 16),
              "entry fields match for %s" % row["name"])

    # 9. reachability TSV == records.json
    with open(os.path.join(HERE, "reachability.tsv")) as f:
        rrows = list(csv.DictReader(f, delimiter="\t"))
    check(len(rrows) == 15, "15 reachability rows", len(rrows))
    reach = [r["name"] for r in rrows if r["reaches_arm"] == "YES"]
    custom = [r["name"] for r in rrows if r["reaches_arm"] == "NO"]
    check(sorted(reach) == sorted(records["reachable_entries"]),
          "10 entries reach the arm", reach)
    check(sorted(custom) == sorted(records["custom_parse_path_entries"]),
          "5 entries take a custom parse path", custom)

    if failures:
        print("census: %d checks, %d failures" % (checks[0], len(failures)))
    else:
        print("census: ALL CHECKS PASSED (%d checks)" % checks[0])
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
