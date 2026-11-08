#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-rot13-factory-115/gen_records.py

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
BIN = ROOT / "work" / "hl-node-115.bin"

DIGEST = hashlib.sha256(BIN.read_bytes()).hexdigest()
assert DIGEST == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RECORDS = {
    "task": "RE-001",
    "work_item": "RE-001-rot13-factory-115",
    "question": (
        "What does the 2-site RegisterOptions host 0x5ff7120 build, which "
        "option group does it register, and what does the shared map "
        "0x65052c0 hold? This cluster is 2 of the 32 unanalysed "
        "RegisterOptions sites in #4372's 37-site census."
    ),
    "artifact": "work/hl-node-115.bin",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4372,
        "open_unknown": (
            "The 37-site RegisterOptions census lists the 0x5ff7120 host "
            "cluster (sites 0x5ff7279, 0x5ff7377) as 'not individually "
            "analysed'."
        ),
        "answer": (
            "The host is the ROT13BlockCipher ':'-split factory: it builds "
            "a 0x28-byte ROT13BlockCipher, registers the group "
            "'ROT13BlockCipherOptions' with the static map 0x65052c0 at "
            "both sites, and the map holds exactly one entry, "
            "'block_size' (type 22, verification 1, flags 0x400, "
            "offset 0), inserted by the static initializer 0x5ff7c90."
        ),
    },
    "factory": {
        "address": "0x5ff7120",
        "fde": "0x5ff7120..0x5ff7419",
        "cpp_name": (
            "rocksdb::(anonymous namespace)::ROT13BlockCipher factory "
            "(name inferred from the vtable typeinfo and the registry "
            "entry under 'ROT13'; the exact factory symbol is open)"
        ),
        "signature": "(unused_arg, const std::string& spec, void** out_slot)",
        "role": (
            "Create one ROT13BlockCipher from a spec string and replace "
            "the object in *out_slot, destroying the previous object "
            "via its vtable slot 1 when non-null."
        ),
        "spec_grammar": {
            "no_colon": "block size defaults to 32 (0x20)",
            "colon": "suffix after the first ':' is parsed base-10 "
                     "(std::stoul family, strtoull via 0x61d1540); the "
                     "prefix before ':' is never read",
            "empty_or_nonnumeric_suffix": "rejected (no conversion)",
            "defensive_check": (
                "if ':' position + 1 > size, basic_string::substr throws "
                "out_of_range (unreachable for a real find result; the "
                "no-colon case takes a separate path)"
            ),
        },
        "register_options_sites": [
            {
                "site": "0x5ff7279",
                "path": "colon",
                "args": (
                    "(object, 'ROT13BlockCipherOptions' stack string, "
                    "&object+0x20, map 0x65052c0)"
                ),
            },
            {
                "site": "0x5ff7377",
                "path": "no-colon",
                "args": (
                    "(object, 'ROT13BlockCipherOptions' from literal "
                    "0x443890, &object+0x20, map 0x65052c0)"
                ),
            },
        ],
        "object_layout": {
            "size": "0x28 bytes",
            "vtable": "0x64cfea0 at +0x00",
            "group_vector_triple": "+0x08 begin, +0x10 end, +0x18 capacity",
            "block_size": "+0x20 (size_t N; the 'block_size' option field)",
        },
        "first_argument": (
            "rdi is overwritten immediately and never read; its C++ role "
            "(factory context / options pointer) is an open unknown"
        ),
        "out_slot": (
            "*rdx is an object-pointer slot: the old object (if any) is "
            "destroyed via its vtable slot 1 and the new object stored; "
            "whether the slot is a unique_ptr or a raw field is open"
        ),
        "direct_e8_callers": 0,
        "registry_reference": {
            "site": "0x5ff92b8",
            "enclosing_fde": "0x5ff88c0..0x5ff9c50",
            "entry": (
                "factory address 0x5ff7120 + std::function manager "
                "0x5fefab0 under the name 'ROT13' (literal 0x4487d6)"
            ),
            "note": (
                "The enclosing function's exact C++ name (builtin-cipher "
                "registry builder) is an open unknown."
            ),
        },
    },
    "group": {
        "name": "ROT13BlockCipherOptions",
        "name_literals": {
            "colon_path": "0x453e50 chunk + movabs 'rOptions' (23 chars)",
            "no_colon_path": "literal 0x443890",
        },
        "options_base": "&object+0x20",
        "map": "0x65052c0",
    },
    "map": {
        "address": "0x65052c0",
        "entries": 1,
        "entry": {
            "key": "block_size",
            "key_literal": "0x43a5f7",
            "type": 22,
            "verification": 1,
            "flags": "0x400",
            "field_offset": 0,
        },
        "record_layout": {
            "size": "0xb8 bytes",
            "functions": "+0x08, +0x28, +0x48, +0x68, +0x88 (std::function)",
            "pack": "+0xa8 (low dword = OptionType, high dword = "
                    "OptionVerification)",
            "flags": "+0xb0 (dword)",
        },
        "initializer": {
            "address": "0x5ff7c90",
            "fde": "0x5ff7c90..0x5ff8256",
            "insert_site": "0x5ff7fc4",
            "insert_helper": "0x5d405b0",
            "atexit_site": "0x5ff8016",
            "map_destructor": "0x5d3f820",
            "record_build": (
                "The record is built on the stack (pack 0x100000016 from "
                "literal 0x458f68 at record+0xa8, flags 0x400 at "
                "record+0xb0, field offset 0 -- the record is "
                "zero-initialized with no offset store), moved by the "
                "OptionTypeInfo move ctors 0x5e332c0 / 0x5e32b10 (which "
                "copy the +0xa8 pack and +0xb0 flags verbatim), then "
                "inserted; the key string is built afterwards in the "
                "vacated slot."
            ),
            "callback_pairs": {
                "record_1_provider": "GOT 0x64ed980/0x64ed9a8 -> "
                                     "0x5fefae0/0x5ffbde0",
                "records_2_and_3": "GOT 0x64ed988/0x64ed9b0 -> "
                                  "0x5fefb10/0x5ffae10 (staged via -0x230)",
                "note": (
                    "Each pair is one std::function's (manager, invoker); "
                    "which record member each pair fills is an open "
                    "unknown."
                ),
            },
        },
        "sibling_maps_same_initializer": [
            {
                "map": "0x6505300",
                "key": "provider",
                "key_literal": "0x4453a1",
                "insert_site": "0x5ff7e23",
            },
            {
                "map": "0x6505280",
                "key": "cipher",
                "key_literal": "0x439496",
                "insert_site": "0x5ff814c",
            },
        ],
        "other_references": {
            "sibling_factory_0x5ff6a00": "RegisterOptions at 0x5ff6af6 "
                                         "(0x38-byte object, same map)",
            "sibling_factory_0x5ff6d60": "RegisterOptions at 0x5ff6e51 "
                                         "(0x38-byte object, same map)",
            "small_host_0x5ffabd0": "RegisterOptions near 0x5ffacde "
                                   "(same map; host role open)",
            "note": (
                "The sibling factories build 0x38-byte objects (not "
                "0x28) and are separate work, not pinned here."
            ),
        },
    },
    "vtable": {
        "address": "0x64cfea0",
        "typeinfo": "0x64cf770",
        "typeinfo_name": "*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE",
        "cpp_name": "rocksdb::(anonymous namespace)::ROT13BlockCipher",
        "base_class": "N7rocksdb11BlockCipherE (rocksdb::BlockCipher)",
        "slots": 22,
        "rot13_specific_slots": {
            "0": "D2 destructor 0x5ff0130: restores the Configurable "
                 "vtable 0x64d3430, frees each group element's heap name "
                 "string (0x30-byte steps over the vector), then frees "
                 "the vector array",
            "1": "D0 destructor 0x5ff0250 (D2 + operator delete)",
            "14": "Name() 0x5fef990 returns literal 0x4487d6 ('ROT13')",
            "19": "0x5fef9a0 returns object+0x20 (the block size N)",
            "20": "0x5fef9b0: for rcx in [0, object+0x20): "
                  "buffer[rcx] += 13; then a zeroed 16-byte Status",
            "21": "0x5fef9f0: identical body to slot 20 "
                  "(both add 13; the two slots are presumably the "
                  "encode/decode entry points, but byte-wise +13 is "
                  "not self-inverse -- a second pass adds 13 again)",
        },
        "shared_slots": (
            "Slots 2-8, 11 are the shared Configurable implementations; "
            "slot 9 (0x609d0e0), slot 10 (0x60986b0), slot 12 (0x609de80), "
            "slot 13 (0x609d980), slot 15 GetId (0x5d32a30), slot 16 "
            "(0x5d2e770), slot 17 (0x5d2ca00), slot 18 (0x5d2ca10) are "
            "pinned by #4328/#4334/#4349 and cited, not re-pinned."
        ),
        "transform_note": (
            "The transform adds 13 (mod 256) to EVERY byte -- there is "
            "no alphabet check and no wraparound at 'z' ('n' + 13 is "
            "'{', not 'a'). It is a byte-wise +13 over the first N "
            "bytes, not letter-ROT13 and not self-inverse."
        ),
    },
    "suffix_parser": {
        "address": "0x61d1540",
        "fde": "0x61d1540..0x61d178b",
        "reached_via": "tail-jump through 0x61d1ef0",
        "behavior": (
            "Copies the suffix into a stack string, calls "
            "__isoc23_strtoull base 10, and validates the parse: no "
            "characters consumed -> invalid_argument path; the first "
            "unparsed character is dispatched through a jump table "
            "(0x97e998)."
        ),
        "open_unknown": (
            "The exact set of accepted trailing characters after the "
            "digits (the jump-table cases) was not fully traced."
        ),
    },
    "context_cited_not_repinned": {
        "register_options": {
            "address": "0x6099ce0",
            "fde": "0x6099ce0..0x6099e34",
            "note": "Pinned by merged #3257 and #4372; cited only.",
        },
        "insert_helper": {
            "address": "0x5d405b0",
            "fde": "0x5d405b0..0x5d40f32",
            "note": (
                "Lazy init (bucket count 1, load factor 1.0f) + insert "
                "with key dedup by length + memcmp; the pair is "
                "0xd8 bytes (key string 0x18 + 8-byte gap + record "
                "0xb8); pair+0x20 maps to node+0x28. Cited from #4379; "
                "its copy mapping is re-verified here from the "
                "disassembly."
            ),
        },
        "map_destructor": {
            "address": "0x5d3f820",
            "fde": "0x5d3f820..0x5d3f94d",
            "note": "Reached only via __cxa_atexit; cited from #4379.",
        },
        "string_ctor": {
            "address": "0x5ff0300",
            "fde": "0x5ff0300..0x5ff03e3",
            "note": "std::string ctor from a const char* literal.",
        },
        "record_move_ctors": {
            "addresses": ["0x5e32b10", "0x5e332c0"],
            "note": (
                "OptionTypeInfo move ctors: move the five std::function "
                "members in 0x20-byte steps and copy the +0xa8 pack and "
                "+0xb0 flags verbatim."
            ),
        },
    },
    "open_unknowns": [
        "The factory's first argument (rdi, never read) -- C++ role open.",
        "The *out_slot container type (unique_ptr vs raw field) -- open.",
        "The registry builder 0x5ff88c0's exact C++ name -- open.",
        "The stoul wrapper's exact accepted trailing-character set -- open.",
        "Which record std::function member each GOT callback pair fills.",
        "The sibling 0x38-byte factories 0x5ff6a00 / 0x5ff6d60 and the "
        "small host 0x5ffabd0 -- separate work, not pinned here.",
        "Whether BlockCipher adds virtuals of its own: the D2 destructor "
        "restores the Configurable vtable 0x64d3430 directly.",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=1, sort_keys=False) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
