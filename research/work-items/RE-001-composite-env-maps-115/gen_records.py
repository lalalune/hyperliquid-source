#!/usr/bin/env python3
"""Generate the semantic records for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-composite-env-maps-115/gen_records.py

Writes records.json: semantic records only (no per-instruction mnemonic
lists; instruction detail lives in the verbatim objdump excerpts).
Resolves merged PR #3950's open unknown: the contents of the three .bss
OptionTypeInfo maps the CompositeEnvWrapper ctor registers. #3950 pinned
the three empty-named registrations and recorded the map contents as
"not recoverable statically"; the static initializer 0x5fe0760 shows
they are: one entry per map.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RECORDS = {
    "task": "RE-001",
    "work_item": "RE-001-composite-env-maps-115",
    "question": (
        "What are the contents of the three .bss OptionTypeInfo maps "
        "(0x6504c60, 0x6504c20, 0x6504be0) that the CompositeEnvWrapper "
        "ctor 0x5fd7360 registers with empty names? Merged PR #3950 pinned "
        "the three registrations and recorded the map contents as an open "
        "unknown ('not recoverable statically'); this packet resolves it "
        "from the static initializer 0x5fe0760."),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 3950,
        "open_unknown": (
            "Record third fields 0x6504c60/0x6504c20/0x6504be0 are in .bss "
            "(runtime-initialized); their contents are not recoverable "
            "statically."),
        "answer": (
            "Recoverable: the static initializer 0x5fe0760 inserts exactly "
            "one entry into each map before any ctor runs."),
    },
    "context_cited_not_repinned": {
        "host_ctor": {
            "address": "0x5fd7360",
            "fde": "0x5fd7360..0x5fd7466",
            "cpp_name": (
                "rocksdb::CompositeEnvWrapper::CompositeEnvWrapper(Env*, "
                "const std::shared_ptr<FileSystem>&, "
                "const std::shared_ptr<SystemClock>&)"),
            "cpp_name_source": (
                "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, "
                "200/262 bytes, 76.34%)"),
            "registrations_pinned_by_3950": [
                {"call_site": "0x5fd73cb", "name": "",
                 "base": "object+0x48 (Env*)", "map": "0x6504c60"},
                {"call_site": "0x5fd73f1", "name": "",
                 "base": "object+0x28 (FileSystem shared_ptr)",
                 "map": "0x6504c20"},
                {"call_site": "0x5fd7417", "name": "",
                 "base": "object+0x38 (SystemClock shared_ptr)",
                 "map": "0x6504be0"},
            ],
            "note": (
                "The ctor, its base ctor 0x5fceb20, destructor, vtable "
                "overrides and PrepareOptions are all pinned by merged "
                "#3950 and are cited here only; this packet adds the map "
                "contents."),
        },
    },
    "initializer": {
        "address": "0x5fe0760",
        "fde": "0x5fe0760..0x5fe0fbc",
        "cpp_name": "__static_initialization_and_destruction_0v",
        "cpp_name_source": (
            "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, "
            "1884/2140 bytes, 88.04%)"),
        "role": (
            "Builds the three static OptionTypeInfo maps at load time: one "
            "stack-built record and one insert call per map, then registers "
            "each map's destructor (0x5d3f820) with __cxa_atexit."),
        "insert_helper": {
            "address": "0x5d405b0",
            "fde": "0x5d405b0..0x5d40f32",
            "role": (
                "unordered_map lazy init + insert: bucket count 1, load "
                "factor 1.0f, bucket array via _M_next_bkt, then a bucket-"
                "chain walk comparing key length and memcmp (dedup: an "
                "equal key already present returns without inserting). "
                "45 direct call sites binary-wide; exactly one per map "
                "here."),
            "callers_binary_wide": 45,
        },
        "map_destructor": {
            "address": "0x5d3f820",
            "fde": "0x5d3f820..0x5d3f94d",
            "direct_e8_callers": 0,
            "note": (
                "Reached only via __cxa_atexit, as expected for static-"
                "duration maps."),
        },
        "record_swap_helper": {
            "address": "0x5fd5ff0",
            "fde": "0x5fd5ff0..0x5fd60a7",
            "direct_callers": 3,
            "caller_sites": ["0x5fe0916", "0x5fe0ccd", "0x5fe0e4d"],
            "role": (
                "Swaps two 32-byte blocks (std::function move/swap): used "
                "once per record build to place the callback pairs."),
        },
    },
    "maps": [
        {
            "address": "0x6504c60",
            "group_base": "object+0x48 (Env*)",
            "entries": 1,
            "entry": {
                "key": "target",
                "key_literal": "0x44a390",
                "key_bytes": "target + NUL (6 bytes + NUL)",
                "insert_site": "0x5fe0b4a",
                "atexit_site": "0x5fe0bee",
                "record_base": "-0x1c8(%rbp)",
                "pack_record_plus_0xa0": "0x10000001a",
                "pack_source": "qword at 0x4593c0",
                "type": 26,
                "verification": 1,
                "flags_record_plus_0xa8": "0x2000",
                "flags_site": "0x5fe08fe",
            },
            "lea_sites": ["0x5fd73b9", "0x5fe0b34", "0x5fe0be4"],
            "lea_meaning": (
                "host ctor (RegisterOptions arg), initializer (insert arg), "
                "initializer (__cxa_atexit arg); no other references "
                "binary-wide."),
        },
        {
            "address": "0x6504c20",
            "group_base": "object+0x28 (FileSystem shared_ptr)",
            "entries": 1,
            "entry": {
                "key": "file_system",
                "key_literal": "0x44b349",
                "key_bytes": "file_system + NUL (11 bytes + NUL)",
                "insert_site": "0x5fe0d4b",
                "atexit_site": "0x5fe0d7f",
                "record_base": "-0x108(%rbp)",
                "pack_record_plus_0xa0": "0x100000016",
                "pack_source": "qword at 0x458f68",
                "type": 22,
                "verification": 1,
                "flags_record_plus_0xa8": "0x400",
                "flags_site": "0x5fe0cb1",
            },
            "lea_sites": ["0x5fd73e7", "0x5fe0d36", "0x5fe0d75"],
            "lea_meaning": (
                "host ctor (RegisterOptions arg), initializer (insert arg), "
                "initializer (__cxa_atexit arg); no other references "
                "binary-wide."),
        },
        {
            "address": "0x6504be0",
            "group_base": "object+0x38 (SystemClock shared_ptr)",
            "entries": 1,
            "entry": {
                "key": "clock",
                "key_literal": "0x4496d9",
                "key_bytes": "clock + NUL (5 bytes + NUL)",
                "insert_site": "0x5fe0ed1",
                "atexit_site": "0x5fe0f1a (tail-call jmp __cxa_atexit)",
                "record_base": "-0x108(%rbp)",
                "pack_record_plus_0xa0": "0x100000016",
                "pack_source": "qword at 0x458f68",
                "type": 22,
                "verification": 1,
                "flags_record_plus_0xa8": "0x400",
                "flags_site": "0x5fe0e38",
            },
            "lea_sites": ["0x5fd740d", "0x5fe0e9b"],
            "lea_meaning": (
                "host ctor (RegisterOptions arg), initializer (insert arg); "
                "the __cxa_atexit registration reuses r12 (loaded at "
                "0x5fe0e9b), so there is no third lea; no other references "
                "binary-wide."),
        },
    ],
    "record_layout": {
        "pack_offset": "record+0xa0",
        "pack_decode": (
            "low dword = OptionType, high dword = OptionVerification "
            "(same packing as #4320's 0x100000016 for comparator entries)"),
        "flags_offset": "record+0xa8",
        "offset_field": (
            "Records are zero-initialized on the stack and no offset store "
            "appears in any of the three builds, so the field offset is 0: "
            "each entry addresses its group base itself."),
        "callbacks": {
            "note": (
                "All three records share the same two std::function "
                "callback pairs, loaded once from GOT slots at the "
                "initializer prologue and moved into each record by "
                "0x5fd5ff0."),
            "pairs": [
                {
                    "got_slots": ["0x64ed8d0", "0x64ed958"],
                    "resolved": ["0x5fcc660", "0x5fd4c30"],
                    "stack_slot": "-0x2b0(%rbp)",
                    "invoke_identity": (
                        "0x5fd4c30 is a vendor-census-named "
                        "_Function_handler<Status(const ConfigOptions&, "
                        "const std::string&, const std::string&, void*)>"
                        "::_M_invoke for "
                        "OptionTypeInfo::AsCustomSharedPtr "
                        "(librocksdb-sys, 134/145 bytes, 92.41%)"),
                },
                {
                    "got_slots": ["0x64ed8c8", "0x64ed960"],
                    "resolved": ["0x5fd5460", "0x5fd7470"],
                    "stack_slot": "-0x2c0(%rbp)",
                    "invoke_identity": (
                        "0x5fd7470 is a vendor-census-named "
                        "_Function_handler<...AsCustomSharedPtr...>"
                        "::_M_invoke copy (135/145 bytes, 93.10%)"),
                },
            ],
            "manager_functions": [
                "0x5fd53d0", "0x5fd5400", "0x5fd5430",
                "0x5fd5680", "0x5fd5710", "0x5fd53a0",
            ],
            "manager_shape": (
                "Tiny std::function managers: op 0 stores a vtable "
                "(0x64ce060/0x64ce070/0x64ce080 for the first three), op 1 "
                "stores the functor, op 2 returns 0."),
        },
    },
    "verification_notes": (
        "The 'target' literal at 0x44a390 is immediately followed by the "
        "'Environment' string at 0x44a397 that #3950 cites for the "
        "'Cannot make a shared Environment from a guarded one' error text; "
        "the two literals are adjacent in .rodata, not the same string."),
    "open_unknowns": [
        "The C++ OptionType enum names for types 22 and 26 (the enum-name "
        "question is already open from #4239 for types 5 and 23); only the "
        "numbers and their pack/flags are pinned here.",
        "The exact record slots the two std::function callback pairs land "
        "in (which member is parse vs serialize); the _M_invoke identities "
        "are named but the member mapping is not traced.",
        "The first elements of the two callback pairs (0x5fcc660, "
        "0x5fd5460) are not named in the vendor census; they are recorded "
        "as the likely _M_manager counterparts of the _M_invoke functions, "
        "not asserted.",
        "Why the 'target' entry carries type 26 and flags 0x2000 while "
        "'file_system'/'clock' carry type 22 and flags 0x400.",
        "The insert helper 0x5d405b0's rdx argument role (an address inside "
        "the stack-built key/record pair, compared against key+0xd8 on the "
        "already-present path); the insert/dedup behavior is pinned, the "
        "argument's exact meaning is not.",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=1, ensure_ascii=False) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
