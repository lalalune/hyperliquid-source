#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ttl-option-maps-115/gen_records.py

Writes records.json. The JSON holds semantic records only -- branch
site->target pairs, record sets, caller/key domains -- never a
per-instruction mnemonic list. Instruction-level detail lives only in the
raw disassembly excerpt text files.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

DIGEST = hashlib.sha256(BIN.read_bytes()).hexdigest()
assert DIGEST == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RECORDS = {
    "task": "RE-001",
    "work_item": "RE-001-ttl-option-maps-115",
    "question": (
        "What do the four static OptionTypeInfo maps used by the TTL "
        "family hold -- the maps whose addresses merged PR #4065 records "
        "only as globals (0x6509440, 0x65093c0, 0x6509400, 0x6509480) "
        "without pinning their entries?"
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4065,
        "open_unknowns": [
            "the contents of the four TTL OptionTypeInfo maps",
        ],
        "answer": (
            "The static initializer 0x6206ef0 inserts exactly one entry "
            "into each of the four maps: 'user_operator' into 0x6509480, "
            "'ttl' into 0x6509440, 'user_filter_factory' into 0x6509400 "
            "and 'user_filter' into 0x65093c0. Three entries carry type "
            "22 (verification 1, except 'user_filter_factory' with "
            "verification 3) and flags 0x400 (except 'user_filter' with "
            "flags 0x1200). The 'ttl' entry is the odd one: its block "
            "builds the record directly at -0x1d0(%rbp) and writes its "
            "OWN pack/flags into the record's +0xa8/+0xb0 slots (movq "
            "$0x2 at 0x62071a8, movl $0x0 at 0x62071b3), so under the "
            "calibrated layout it carries pack 0x2 (type 2, verification "
            "0) and flags 0x0 -- not the 0x100000016/0x400 of the other "
            "entries. It calls no record init (0x5e32b10) and loads no "
            "GOT pack. A fifth map, 0x65094c0, is zeroed and "
            "atexit-registered by the initializer but receives no insert "
            "there."
        ),
    },
    "initializer": {
        "function": "0x6206ef0",
        "fde": "0x6206ef0..0x620769f",
        "blocks": [
            {"key": "user_operator", "map": "0x6509480",
             "insert_site": "0x62070c2", "atexit_site": "0x62070f4",
             "pack_source": "GOT slot 0x458f68"},
            {"key": "ttl", "map": "0x6509440",
             "insert_site": "0x620726b", "atexit_site": "0x62072d4",
             "pack_source": "immediate: the ttl block builds its record "
                           "directly at -0x1d0(%rbp) and writes movq $0x2 "
                           "into +0xa8 (0x62071a8) and movl $0x0 into +0xb0 "
                           "(0x62071b3); it calls no record init and loads "
                           "no GOT pack"},
            {"key": "user_filter_factory", "map": "0x6509400",
             "insert_site": "0x620740b", "atexit_site": "0x620743b",
             "pack_source": "GOT slot 0x4594e8"},
            {"key": "user_filter", "map": "0x65093c0",
             "insert_site": "0x6207575", "atexit_site": "0x62075be",
             "pack_source": "GOT slot 0x458f68"},
        ],
    },
    "option_maps": {
        "0x6509480": {"entries": [{"key": "user_operator",
                                  "key_literal": "0x44c438",
                                  "pack": "0x100000016",
                                  "type": 22, "verification": 1,
                                  "flags": "0x400",
                                  "insert_site": "0x62070c2",
                                  "atexit_site": "0x62070f4"}]},
        "0x6509440": {"entries": [{"key": "ttl",
                                  "key_literal": "0x4322be",
                                  "pack": "0x2",
                                  "type": 2, "verification": 0,
                                  "flags": "0x0",
                                  "insert_site": "0x620726b",
                                  "atexit_site": "0x62072d4",
                                  "pack_source": "immediate"}]},
        "0x6509400": {"entries": [{"key": "user_filter_factory",
                                  "key_literal": "0x44ffe6",
                                  "pack": "0x300000016",
                                  "type": 22, "verification": 3,
                                  "flags": "0x400",
                                  "insert_site": "0x620740b",
                                  "atexit_site": "0x620743b"}]},
        "0x65093c0": {"entries": [{"key": "user_filter",
                                  "key_literal": "0x4385bb",
                                  "pack": "0x100000016",
                                  "type": 22, "verification": 1,
                                  "flags": "0x1200",
                                  "insert_site": "0x6207575",
                                  "atexit_site": "0x62075be"}]},
        "0x65094c0": {"entries": [],
                     "note": "zeroed at the initializer entry "
                     "(0x6206ef5) and atexit-registered; no insert into "
                     "this map in the initializer 0x6206ef0"},
    },
    "consumers": {
        "note": "The maps are the option maps of the TTL family, "
                "consumed by the ctors' RegisterOptions calls. The ctors, "
                "their groups and the maps' addresses are pinned by "
                "merged PR #4065; the runtime methods and vtables by "
                "merged PR #4087. This packet pins only the maps' "
                "contents, which neither packet records.",
        "groups": [
            {"name": "TTL", "map": "0x6509440",
             "used_by": "filter ctor 0x6202a10 (site 0x6202aa4) and "
                        "factory ctor 0x6205790 (site 0x6205895), per #4065"},
            {"name": "UserFilter", "map": "0x65093c0",
             "used_by": "filter ctor 0x6202a10 (site 0x6202afc), per #4065"},
            {"name": "UserOptions", "map": "0x6509400",
             "used_by": "factory ctor 0x6205790 (site 0x6205847), per #4065"},
            {"name": "TtlMergeOptions", "map": "0x6509480",
             "used_by": "merge-operator ctor 0x6205560 (site 0x620561a), "
                        "per #4065"},
        ],
    },
    "callers": {
        "0x5d405b0": ["0x62070c2", "0x620726b", "0x620740b", "0x6207575"],
    },
    "open_unknowns": [
        "the OptionType enum name for type 22, and the meaning of "
        "verification 1 vs 3 across the map entries -- and what type 2 "
        "(the ttl entry's pack) means against type 22",
        "the ttl record's name string at +0xc0/+0xc8 (ptr -0x100, size 3) "
        "and the xmm callback pairs the initializer loads from GOT slots "
        "0x64eda98/0x64edaa0/0x64edae8/0x64edb58",
        "which buffer the insert ultimately stores: the ttl record is "
        "built at -0x1d0 and copied by 0x5e332c0 to -0xf0, while the other "
        "three records are built at -0x110 and copied to -0x1d0",
        "the fifth map 0x65094c0: which code inserts entries into it, if any",
        "the 'ttl' literal's other lea sites 0x608a88c and 0x608da05 "
        "(both in 0x6089b50..0x6091e5c)",
    ],
    "assumptions": [
        "the record pack sits at record+0xa8 and the flags at record+0xb0, "
        "calibrated against merged PR #4389's 'block_size' record, which "
        "uses the same initializer pattern and the same GOT pack slot "
        "0x458f68",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2, sort_keys=False) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
