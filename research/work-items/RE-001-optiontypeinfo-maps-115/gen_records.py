#!/usr/bin/env python3
"""Generate records.json for RE-001-optiontypeinfo-maps-115 (node #115).

Inputs (all produced by the packet's own census scripts from the real
binary work/hl-node-115.bin, SHA-256 a6e2897c...):
  blocks.tsv        92 pair-ctor blocks (census.py)
  ranges.tsv        6 range-ctor calls (census.py)
  midhelpers.tsv    4 mid-helper calls (census.py)
  atexit.tsv        7 __cxa_atexit calls (census.py)
  enum_maps.tsv     16 enum-name pairs (special_pairs.py)
  special_pairs.tsv 8 special pairs (special_pairs.py)
  consumers.tsv     24 RIP-relative reference sites (census_consumers.py)
The two type-dispatch jump tables (parse 0x9786b4, serialize 0x978650)
are read from .rodata here.

The JSON holds semantic records only.  Instruction-level detail lives in
the raw disassembly excerpts (*.objdump.txt), kept verbatim and
whole-function; the objdump command is recorded in README.md.

Usage: python3 gen_records.py  (run from the repo root)
Writes records.json next to this file.
"""

import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work/hl-node-115.bin"
DIGEST = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# Type classification, derived from the parse jump table (0x9786b4) case
# blocks in fn-60bedc0.objdump.txt: store width + parse helper + the
# entries' field widths.  Names for the named-enum types (11-16, 24) are
# the .bss registry each case loads; type 13 is the wal_compression enum
# (registry 0x6507120) and type 18 is the mid-helper enum type.
TYPE_INFO = {
    0: ("bool", "1-byte; parse 0x61d1480, serialize case 0x60bab78"),
    1: ("int32", "4-byte store; parse 0x61d1b90"),
    2: ("uint32", "4-byte store; parse 0x61d1b30"),
    3: ("uint64", "8-byte store; parse 0x61d18a0"),
    4: ("uint32", "4-byte store; parse 0x61d1840 (same helper as type 6)"),
    5: ("1-byte", "1-byte store; parse 0x61d17d0; no DBOptions entry"),
    6: ("uint32", "4-byte store; parse 0x61d1840 (same helper as type 4)"),
    7: ("uint64", "8-byte store; parse 0x61d1540"),
    8: ("size_t", "8-byte store; parse 0x61d1ef0"),
    9: ("string", "std::string assign (0x60bf403)"),
    10: ("double", "movsd store; parse 0x61d1e30"),
    11: ("named-enum", "registry 0x65070a0 (parse 0x60be160)"),
    12: ("named-enum", "registry 0x6507060 (parse 0x60be2b0)"),
    13: ("named-enum", "registry 0x6507120 (parse 0x60be400); "
        "wal_compression, the CompressionType enum"),
    14: ("named-enum", "registry 0x6507020 (parse 0x60be7f0)"),
    15: ("named-enum", "registry 0x6507160 (parse 0x60be550)"),
    16: ("named-enum", "registry 0x65070e0 (parse 0x60be6a0)"),
    17: ("struct", "no built-in parse; apply falls through to the "
        "verification check"),
    18: ("enum", "mid-helper enum type; parse/serialize std::functions "
        "capture the enum-name map"),
    19: ("struct", "no built-in parse; apply falls through to the "
        "verification check"),
    20: ("vector", "no built-in parse; listeners carries a custom "
        "parse std::function"),
    21: ("struct", "nested-struct parse at 0x60bf1e0"),
    22: ("struct", "nested-struct parse at 0x60bf1e0"),
    23: ("string-like", "parse builds a string via 0x61c7fc0"),
    24: ("named-enum", "registry 0x6506fe0 (parse 0x60be940)"),
    26: ("shared-ptr/struct", "no built-in parse; custom parse "
        "std::function (rate_limiter, env)"),
}


def read_tsv(name):
    rows = []
    with open(HERE / name) as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            rows.append(dict(zip(header, line.split("\t"))))
    return rows


def jump_table(base, count=25):
    with open(BIN, "rb") as f:
        f.seek(base)
        raw = f.read(count * 4)
    return [base + off for off in struct.unpack(f"<{count}i", raw)]


def main():
    blocks = read_tsv("blocks.tsv")
    ranges = read_tsv("ranges.tsv")
    mids = read_tsv("midhelpers.tsv")
    atexit = read_tsv("atexit.tsv")
    enum_maps = read_tsv("enum_maps.tsv")
    specials = read_tsv("special_pairs.tsv")
    consumers = read_tsv("consumers.tsv")

    def tv_split(tv):
        if tv.startswith("qword@"):
            v = int(tv.split("=")[1], 16)
        elif tv.startswith("0x"):
            v = int(tv, 16)
        else:
            v = int(tv)
        return v & 0xFFFFFFFF, v >> 32

    entries = []
    for b in blocks:
        typ, ver = tv_split(b["typeverif"])
        off = b["offset"]
        off = f"0x{int(off, 0):x}" if off not in ("?", "") else off
        entries.append({
            "name": b["name"],
            "map": "mutable" if int(b["block"]) < 19 else "dboptions",
            "block": int(b["block"]),
            "offset": off,
            "type": typ,
            "type_name": TYPE_INFO.get(typ, ("?", ""))[0],
            "verification": ver,
            "flags": f"0x{int(b['flags'], 0):x}",
            "source": "pair-ctor block",
        })
    for s in specials:
        entries.append({
            "name": s["key"],
            "map": "dboptions",
            "block": None,
            "offset": s["offset"],
            "type": int(s["type"]),
            "type_name": TYPE_INFO.get(int(s["type"]), ("?", ""))[0],
            "verification": int(s["verification"]),
            "flags": s["flags"],
            "source": "special pair: " + s["value_source"],
            "enum_map": (s["enum_map"].removeprefix("enum-map ")
                         if s["enum_map"] else None),
        })
    entries.sort(key=lambda e: (e["map"], e["block"] is None,
                                e["block"] or 0))

    offset_zero = [e for e in entries if e["offset"] in ("0", "0x0")]
    real_zero = [e for e in offset_zero if e["verification"] == 0]
    ignored_zero = [e for e in offset_zero if e["verification"] == 4]

    records = {
        "task": "RE-001",
        "work_item": "RE-001-optiontypeinfo-maps-115",
        "artifact": {
            "file": "work/hl-node-115.bin",
            "sha256": DIGEST,
            "node": 115,
        },
        "question": "Which entry range goes to which OptionTypeInfo map, "
            "and how are the 15 offset-0 entries served?",
        "maps": [
            {
                "name": "mutable",
                "address": "0x6506dc0",
                "entries": 19,
                "range_ctor_call": "0x60aba7e",
                "range_ctor": "0x5d405b0",
                "first_pair": "-0x4490(%rbp)",
                "last_pair": "-0x3488(%rbp)",
                "pair_stride": "0xd8",
                "fields": "MutableDBOptions (blocks 0-18)",
                "dtor": "0x5d3f820 via __cxa_atexit",
            },
            {
                "name": "dboptions",
                "address": "0x6506d80",
                "entries": 81,
                "range_ctor_call": "0x60b096c",
                "range_ctor": "0x5d405b0",
                "first_pair": "-0x4490(%rbp)",
                "last_pair": "-0x38(%rbp)",
                "pair_stride": "0xd8",
                "fields": "DBOptions (blocks 19-91, 73 pair-ctor pairs) "
                    "plus 8 special pairs",
                "dtor": "0x5d3f820 via __cxa_atexit",
            },
        ],
        "enum_maps": [
            {
                "address": f"0x6506{tag}",
                "pairs": [
                    {"name": p["name"], "value": int(p["value"])}
                    for p in enum_maps if p["map"] == f"0x6506{tag}"
                ],
            }
            for tag in ["ec0", "e80", "e40", "e00"]
        ],
        "section_strings": [
            {"address": "0x6506f00", "value": "Version"},
            {"address": "0x6506f20", "value": "DBOptions"},
            {"address": "0x6506f40", "value": "CFOptions"},
            {"address": "0x6506f60", "value": "TableOptions/"},
            {"address": "0x6506f80", "value": "Unknown"},
        ],
        "entries": entries,
        "entry_count": {
            "total": len(entries),
            "mutable_map": sum(1 for e in entries if e["map"] == "mutable"),
            "dboptions_map": sum(1 for e in entries
                                 if e["map"] == "dboptions"),
            "pair_ctor_blocks": len(blocks),
            "special_pairs": len(specials),
        },
        "offset_zero_resolution": {
            "count": len(offset_zero),
            "real_first_fields": [
                {"name": e["name"], "map": e["map"], "type": e["type"]}
                for e in real_zero
            ],
            "ignored_deprecated": [
                {"name": e["name"], "map": e["map"], "type": e["type"]}
                for e in ignored_zero
            ],
            "gate": {
                "function": "0x60bedc0 (per-entry apply)",
                "check": "cmpl $0x4,0xac(%rsi) at 0x60bedeb; "
                    "je 0x60bf000 on verification == 4",
                "effect": "verification 4 returns Status OK immediately; "
                    "the options struct is not touched and the offset "
                    "is never dereferenced",
            },
            "apply": {
                "function": "0x60bedc0",
                "field_address": "options_base + record->offset "
                    "(movslq 0x0(%rbp),%rax; add %r13,%rax at 0x60beeda)",
                "parse_call": "call *0x20(%rbp) at 0x60bef16 when the "
                    "record's first std::function is present; otherwise "
                    "the type jump table at 0x9786b4",
            },
        },
        "type_dispatch": {
            "parse_jump_table": "0x9786b4",
            "parse_cases": {
                str(t): f"0x{addr:x}"
                for t, addr in enumerate(jump_table(0x9786B4))
            },
            "serialize_jump_table": "0x978650",
            "serialize_cases": {
                str(t): f"0x{addr:x}"
                for t, addr in enumerate(jump_table(0x978650))
            },
            "types": {
                str(t): {"name": v[0], "behavior": v[1]}
                for t, v in TYPE_INFO.items()
            },
        },
        "consumers": {
            "map_reference_sites": [
                {
                    "address": c["address"],
                    "target": c["target_name"],
                    "instruction": c["instruction"],
                    "enclosing_fde": c["enclosing_fde"],
                }
                for c in consumers
            ],
            "functions": [
                {
                    "address": "0x60a1d60",
                    "role": "applies a parsed name/value map onto a "
                        "MutableDBOptions copy via the apply loop "
                        "0x60c18b0",
                    "map": "mutable",
                },
                {
                    "address": "0x60a2080",
                    "role": "reads one MutableDBOptions option by name "
                        "('MutableDBOptions' literal at 0x4541e0) via the "
                        "single-option getter 0x60bfda0",
                    "map": "mutable",
                },
                {
                    "address": "0x60a47f0",
                    "role": "dumps every entry of both maps to strings "
                        "(OPTIONS-file writer path) via 0x6099ce0 after "
                        "building default DBOptions/ImmutableDBOptions",
                    "map": "both",
                },
                {
                    "address": "0x60ba0b0",
                    "role": "map lookup: linear bucket walk while the map "
                        "has at most 20 entries, hash path above; "
                        "unknown keys split on '.' (0x43821e) for nested "
                        "lookup",
                    "map": "both",
                },
                {
                    "address": "0x60bedc0",
                    "role": "per-entry apply (see offset_zero_resolution)",
                    "map": "both",
                },
                {
                    "address": "0x60ba600",
                    "role": "serialize dispatch by type (jump table "
                        "0x978650); enum types walk the .bss name "
                        "registries 0x6506fe0..0x6507160",
                    "map": "both",
                },
            ],
        },
        "ranges": [
            {
                "call": r["call"],
                "ctor": r["helper"],
                "map": r["map"],
                "first": r["first"],
                "last": r["last"],
            }
            for r in ranges
        ],
        "mid_helpers": [
            {
                "address": m["helper"],
                "call": m["call"],
                "dest": m["dest"],
                "offset": m["offset"],
                "flags": m["flags"],
                "enum_map": m["arg_rdx"],
            }
            for m in mids
        ],
        "atexit": [
            {
                "call": a["call"],
                "function": a["func"],
                "object": a["obj"],
                "dso_handle": a["dso"],
            }
            for a in atexit
        ],
        "corrections_to_prior_packet": [
            "#4233 claimed one 92-entry DBOptions map; the initializer "
            "actually builds two maps (19 + 81 = 100 pairs) plus four "
            "enum-name maps",
            "#4233 left wal_filter unattributed; it is the special pair "
            "at -0x3dd0 (offset 0x188, type 22, verification 1, "
            "flags 0x1201)",
            "#4233 guessed the move helpers 0x5e32b10/0x5e332c0 were "
            "std::function move ctors; they are OptionTypeInfo move "
            "constructors",
            "#4233 listed 92 entries plus a 'DBOptions' no-temp row; the "
            "93rd row was a mis-parse of the 'DBOptions' section string",
        ],
        "open_unknowns": [
            "The full name lists of the seven .bss enum registries "
            "(0x6506fe0..0x6507160) used by types 11-16 and 24: the "
            "registries are runtime-built linked lists, so their contents "
            "are not recoverable from the static file; only wal_compression "
            "(type 13) is pinned to its registry address",
            "The exact C++ OptionType enum names for types 4 vs 6 (both "
            "parse as uint32 via 0x61d1840) and 3 vs 7 vs 8 (all 8-byte "
            "unsigned stores with different parse helpers); the packet "
            "records the behavior, not the header names",
            "Type 5 (1-byte parse 0x61d17d0) and type 23 (string build via "
            "0x61c7fc0) have no DBOptions entries; their names are unknown",
            "Block 26 allow_2pc (offset 0x173, type 0, verification 0) "
            "does not sit in the EnvOptions bool cluster; its field is "
            "not yet tied to a struct member by a ctor pack",
        ],
    }
    with open(HERE / "records.json", "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    print(f"wrote records.json: {len(entries)} entries "
          f"({len(offset_zero)} offset-0: {len(real_zero)} real, "
          f"{len(ignored_zero)} ignored)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
