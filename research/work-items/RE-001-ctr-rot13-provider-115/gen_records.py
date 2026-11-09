#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-ctr-rot13-provider-115/gen_records.py

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
    "work_item": "RE-001-ctr-rot13-provider-115",
    "question": (
        "What do the two unanalysed RegisterOptions host clusters "
        "0x5ff6a00 and 0x5ff6d60 build, which option groups do they "
        "register, and what is the shared 0x30-byte object built by "
        "their common callee 0x5ff6880? Two of the 32 unanalysed "
        "RegisterOptions sites in #4372's 37-site census, plus the "
        "0x5ff6880 host's own site."
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4372,
        "open_unknown": (
            "The 37-site RegisterOptions census lists the 0x5ff6a00 "
            "cluster (site 0x5ff6af6), the 0x5ff6d60 cluster (site "
            "0x5ff6e51) and the 0x5ff6880 cluster (site 0x5ff6926) as "
            "'not individually analysed'."
        ),
        "answer": (
            "Both factories build a 0x38-byte "
            "_Sp_counted_ptr_inplace<ROT13BlockCipher> (an in-place "
            "shared_ptr control block whose ROT13 cipher sits at +0x10 "
            "with block_size 32 at +0x30) and a 0x30-byte "
            "CTREncryptionProvider holding an aliasing shared_ptr to "
            "that cipher at +0x20/+0x28. The factory registers the "
            "group 'ROT13BlockCipherOptions' with the static map "
            "0x65052c0 (one entry, 'block_size'); the provider init "
            "0x5ff6880 registers the group 'Cipher' with the static "
            "map 0x6505280 (one entry, 'cipher'). The 'CTR' factory "
            "0x5ff6d60 builds the ROT13 provider only when the spec "
            "ends with '://test'; otherwise it builds an empty Cipher "
            "holder (null cipher)."
        ),
    },
    "factory_0x5ff6a00": {
        "address": "0x5ff6a00",
        "fde": "0x5ff6a00..0x5ff6c70",
        "registry_name": "1://test",
        "registry_entry": {
            "site": "0x5ff90f6",
            "enclosing_fde": "0x5ff88c0..0x5ff9c50",
            "entry": (
                "factory address 0x5ff6a00 + paired function pointer "
                "0x5fefa80 under the name '1://test' (literal "
                "0x4429ae); the paired pointer's role is an open "
                "unknown"
            ),
        },
        "signature": "(unused, unused, out_slot_ptr)",
        "role": (
            "Build one CTR provider whose cipher is the ROT13 test "
            "cipher and replace the provider in the out slot, "
            "destroying the previous provider via its vtable slot 1 "
            "when non-null; returns the new provider."
        ),
        "arguments": {
            "rdi": "never read; C++ role open",
            "rsi": "never read; C++ role open",
            "rdx": (
                "pointer to the out-pointer slot: *rdx is the address "
                "of the slot holding the current provider; the factory "
                "reads the old provider from that slot, stores the new "
                "provider there, and destroys the old one. The exact "
                "C++ type of the out parameter (a raw double pointer "
                "vs a smart-pointer out param) is an open unknown."
            ),
        },
        "wrapper_object": {
            "size": "0x38 bytes",
            "cpp_name": (
                "std::_Sp_counted_ptr_inplace<rocksdb::(anonymous "
                "namespace)::ROT13BlockCipher> (in-place shared_ptr "
                "control block)"
            ),
            "vtable": "0x64d0160 at +0x00",
            "typeinfo_name": (
                "*St23_Sp_counted_ptr_inplaceIN7rocksdb12_GLOBAL__N_1"
                "16ROT13BlockCipherESaIvELN9__gnu_cxx12_Lock_policyE2EE"
            ),
            "use_weak_counts": (
                "+0x08 = the (1, 1) qword at literal 0x459b20 "
                "(use_count 1, weak_count 1)"
            ),
            "embedded_cipher": (
                "ROT13BlockCipher in place at +0x10: vtable 0x64cfea0 "
                "at +0x10, +0x18/+0x20/+0x28 zeroed, block_size 0x20 "
                "(32) at +0x30"
            ),
        },
        "register_options_site": {
            "site": "0x5ff6af6",
            "args": (
                "(cipher at wrapper+0x10, 'ROT13BlockCipherOptions' "
                "stack string, &wrapper+0x30, map 0x65052c0)"
            ),
            "group_name_build": (
                "23-char string from the 16-byte literal at 0x453e50 "
                "('ROT13BlockCipher') plus the movabs immediate "
                "'rOptions' at buffer+0x0f, heap-allocated via "
                "_M_create, NUL-terminated"
            ),
        },
        "provider_construction": {
            "alloc": "0x30 bytes via operator new",
            "init_call": "0x5ff6880 at 0x5ff6b30",
            "shared_ptr_argument": (
                "aliasing shared_ptr: ptr = &wrapper+0x10 (the "
                "in-place cipher), control = the wrapper object "
                "itself, passed as the 16-byte struct at 0x10(%rsp)"
            ),
            "wrapper_release": (
                "after the provider takes its reference, the factory "
                "releases its own reference to the wrapper via the "
                "control-block release 0x5d350c0 (slot 0x18(%rsp))"
            ),
        },
        "old_provider_destruction": {
            "dispatch": (
                "vtable slot 1 of the old provider is compared against "
                "the CTREncryptionProvider destructor 0x5ff30b0 (held "
                "in GOT slot 0x64ed998); if different, the derived "
                "deleting destructor is called and the factory "
                "returns; if equal, the destruction is inlined below"
            ),
            "inline_steps": [
                "vtable reset to 0x64cffb0 (CTREncryptionProvider)",
                "cipher shared_ptr released via 0x5d350c0 on +0x28",
                "vtable reset to 0x64d3430 (rocksdb::Configurable)",
                "option-groups vector at +0x08..+0x10 destroyed "
                "element by element (0x30-byte steps, each element's "
                "heap name string freed when present)",
                "vector buffer freed (sized delete, size = end - begin)",
                "object freed (sized delete, 0x30 bytes)",
            ],
        },
        "direct_e8_callers": 0,
        "lea_references": ["0x5ff90f6 (registry builder 0x5ff88c0)"],
    },
    "holder_0x5ff6880": {
        "address": "0x5ff6880",
        "fde": "0x5ff6880..0x5ff6978",
        "cpp_name": "rocksdb::CTREncryptionProvider (init)",
        "vtable": "0x64cffb0 at +0x00 (lea base 0x64cffa0 + 0x10)",
        "typeinfo_name": "N7rocksdb21CTREncryptionProviderE",
        "size": "0x30 bytes",
        "layout": {
            "+0x00": "vtable 0x64cffb0",
            "+0x08": "zeroed qword (Configurable group-vector begin)",
            "+0x10": "zeroed qword (Configurable group-vector end)",
            "+0x18": "zeroed qword (Configurable group-vector capacity)",
            "+0x20": "shared_ptr<BlockCipher> ptr (copied from the argument)",
            "+0x28": "shared_ptr<BlockCipher> control (copied from the argument)",
        },
        "shared_ptr_copy": (
            "The argument shared_ptr is copied into +0x20/+0x28; when "
            "the control is non-null the use_count is bumped: plain "
            "'addl $1, 0x8(%rax)' when __libc_single_threaded "
            "(GOT 0x64ed290) is set, 'lock addl' otherwise."
        ),
        "register_options_site": {
            "site": "0x5ff6926",
            "args": (
                "(provider, 'Cipher' stack string, &provider+0x20, "
                "map 0x6505280)"
            ),
            "group_name_build": (
                "6-char stack string 'Cipher' (movl $0x68706943 "
                "'Ciph' + mov $0x7265 'er', size 6)"
            ),
        },
        "direct_e8_callers": ["0x5ff6b30", "0x5ff6e7a", "0x5ff6f8b"],
        "note": (
            "The three callers are all inside the two factories pinned "
            "here; no other caller exists binary-wide."
        ),
    },
    "destructor_0x5ff30b0": {
        "address": "0x5ff30b0",
        "fde": "0x5ff30b0..0x5ff3153",
        "cpp_name": "rocksdb::CTREncryptionProvider deleting destructor",
        "steps": [
            "vtable reset to 0x64cffb0 (CTREncryptionProvider)",
            "cipher shared_ptr released via 0x5d350c0 on +0x28",
            "vtable reset to 0x64d3430 (rocksdb::Configurable)",
            "option-groups vector at +0x08..+0x10 destroyed element "
            "by element (0x30-byte steps, heap name strings freed)",
            "vector buffer freed (sized delete, size = end - begin)",
            "object freed (sized delete, 0x30 bytes)",
        ],
        "note": (
            "The factory's inline old-provider destruction duplicates "
            "these steps exactly (same vtable resets, same release, "
            "same vector walk, same sized deletes); the GOT slot "
            "0x64ed998 holds this function's address so the factory "
            "can tell a plain CTR provider from a derived one."
        ),
        "direct_e8_callers": 0,
        "reached_via": (
            "vtable slot 1 only (through GOT slot 0x64ed998); no "
            "direct E8 caller exists binary-wide"
        ),
    },
    "factory_0x5ff6d60": {
        "address": "0x5ff6d60",
        "fde": "0x5ff6d60..0x5ff70a7",
        "registry_name": "CTR",
        "registry_entry": {
            "site": "0x5ff8aa0",
            "enclosing_fde": "0x5ff88c0..0x5ff9c50",
            "entry": (
                "factory address 0x5ff6d60 + paired function pointer "
                "0x5fefa50 under the name 'CTR' (literal 0x447699); "
                "the paired pointer's role is an open unknown"
            ),
        },
        "signature": "(unused, const std::string& spec, out_slot_ptr)",
        "gate": {
            "check": "ends_with(spec, '://test') via 0x61d1390",
            "suffix_literal": (
                "7-char stack string '://test' (movl $0x742f2f3a + "
                "movl $0x74736574, size 7)"
            ),
            "test_path": (
                "spec ends with '://test': builds the same 0x38-byte "
                "in-place ROT13 wrapper (block_size 32) and the same "
                "CTR provider as 0x5ff6a00, including the "
                "'ROT13BlockCipherOptions' registration (site "
                "0x5ff6e51) and the aliasing shared_ptr handoff to "
                "0x5ff6880 (site 0x5ff6e7a)"
            ),
            "else_path": (
                "spec does not end with '://test': allocates a 0x30-byte "
                "provider and calls 0x5ff6880 with a zeroed (null) "
                "shared_ptr, so the provider's cipher is null and "
                "must be supplied later (e.g. via the 'cipher' "
                "option); the provider is still stored into the out "
                "slot and the old provider destroyed the same way"
            ),
        },
        "group_name_build": (
            "The 'ROT13BlockCipherOptions' string is copied from the "
            "literal at 0x443890 via the string assign helper "
            "0x5ff0300 (not rebuilt from chunks as in 0x5ff6a00)"
        ),
        "direct_e8_callers": 0,
        "lea_references": ["0x5ff8aa0 (registry builder 0x5ff88c0)"],
    },
    "groups_and_maps": {
        "rot13_options": {
            "name": "ROT13BlockCipherOptions",
            "map": "0x65052c0",
            "entry": {
                "key": "block_size",
                "key_literal": "0x43a5f7",
                "type": 22,
                "verification": 1,
                "flags": "0x400",
                "field_offset": 0,
            },
            "pinned_by": "#4389 (static initializer 0x5ff7c90, insert site 0x5ff7fc4)",
            "register_sites_this_packet": ["0x5ff6af6", "0x5ff6e51"],
            "register_sites_cited": [
                "0x5ff7279, 0x5ff7377 (#4389 factory 0x5ff7120)",
                "0x5ffacee (small host 0x5ffabd0, role open)",
            ],
        },
        "cipher": {
            "name": "Cipher",
            "map": "0x6505280",
            "entry": {
                "key": "cipher",
                "key_literal": "0x439496",
                "type": 22,
                "verification": 1,
                "flags": "0x400",
                "field_offset": 0,
            },
            "pinned_by": "#4389 (static initializer 0x5ff7c90, insert site 0x5ff814c)",
            "register_sites_this_packet": ["0x5ff6926"],
        },
        "provider_map_cited": {
            "map": "0x6505300",
            "key": "provider",
            "key_literal": "0x4453a1",
            "pinned_by": "#4389 (static initializer 0x5ff7c90, insert site 0x5ff7e23)",
            "note": (
                "The map's only non-initializer lea reference is at "
                "0x5ff6763, inside FDE 0x5ff6690..0x5ff682e (the host "
                "with census site 0x5ff677e); that host is not pinned "
                "in this packet, so which group it registers against "
                "the provider map is an open unknown."
            ),
        },
    },
    "vtables": {
        "inplace_control_block": {
            "vtable": "0x64d0160",
            "typeinfo": "0x64cf838",
            "typeinfo_name": (
                "*St23_Sp_counted_ptr_inplaceIN7rocksdb12_GLOBAL__N_1"
                "16ROT13BlockCipherESaIvELN9__gnu_cxx12_Lock_policyE2EE"
            ),
        },
        "ctr_provider": {
            "vtable": "0x64cffb0 (lea base 0x64cffa0 + 0x10)",
            "typeinfo": "0x64cf740",
            "typeinfo_name": "N7rocksdb21CTREncryptionProviderE",
        },
        "configurable_base": {
            "vtable": "0x64d3430 (lea base 0x64d3420 + 0x10)",
            "typeinfo": "0x64d3410",
            "typeinfo_name": "N7rocksdb12ConfigurableE",
        },
        "rot13_cipher": {
            "vtable": "0x64cfea0",
            "typeinfo_name": (
                "*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"
            ),
            "pinned_by": "#4389; cited only",
        },
    },
    "release_helper_0x5d350c0": {
        "address": "0x5d350c0",
        "fde": "0x5d350c0..0x5d35145",
        "role": (
            "shared_ptr control-block release (_Sp_counted_base "
            "release): reads the (use_count, weak_count) pair at "
            "+0x08; the (1, 1) pair takes the dispose+destroy fast "
            "path; otherwise the use_count is decremented (plain add "
            "when __libc_single_threaded is set, lock add otherwise) "
            "and the dispose path runs when it reaches zero"
        ),
        "note": "Sibling of the 0x5d35070 release helper pinned by #4349.",
    },
    "context_cited_not_repinned": {
        "register_options": {
            "address": "0x6099ce0",
            "fde": "0x6099ce0..0x6099e34",
            "note": "Pinned by merged #3257 and #4372; cited only.",
        },
        "string_assign": {
            "address": "0x5ff0300",
            "fde": "0x5ff0300..0x5ff03e3",
            "note": "std::string assign from a const char* literal; cited from #4389.",
        },
        "ends_with": {
            "address": "0x61d1390",
            "fde": "0x61d1390..0x61d13db",
            "note": "string ends_with helper; cited from #4328.",
        },
        "rot13_factory": {
            "address": "0x5ff7120",
            "note": (
                "Pinned by #4389 (the ':'-split ROT13 factory, registry "
                "name 'ROT13'); its colon/no-colon paths are cited, "
                "not re-pinned."
            ),
        },
        "small_host": {
            "address": "0x5ffabd0",
            "note": (
                "Name dispatch host (strcmp against 'ROT13' at "
                "0x4487d6, kNotSupported 'Cannot add keys to "
                "CTREncryptionProvider' when the cipher slot is "
                "occupied, _Sp_counted_ptr<ROT13BlockCipher*> control "
                "block vtable 0x64d0128); cited as context only, not "
                "pinned here."
            ),
        },
    },
    "open_unknowns": [
        "The exact C++ type of the factories' out parameter (raw double pointer vs smart-pointer out param) -- open.",
        "The first arguments of both factories (rdi/rsi, never read) -- C++ roles open.",
        "The paired second function pointers in the registry entries (0x5fefa80 for '1://test', 0x5fefa50 for 'CTR', 0x5fefab0 for 'ROT13') -- roles open.",
        "Why the test provider registers under the name '1://test' rather than a plain name -- open.",
        "Which host registers a group against the provider map 0x6505300 -- the only non-initializer lea reference is 0x5ff6763 in FDE 0x5ff6690..0x5ff682e (census site 0x5ff677e); that host is not pinned here.",
        "The EncryptionProvider intermediate base: the destructor resets the vtable from CTREncryptionProvider straight to Configurable -- whether EncryptionProvider adds virtuals or members is open.",
        "The +0x08/+0x10/+0x18 zeroed qwords of the provider are the Configurable group-vector triple (begin/end/capacity) -- the vector's element type is the 0x30-byte group record pinned by #4372, cited.",
        "The small host 0x5ffabd0's full dispatch (the non-'ROT13' path via 0x60bb890 / 0x5ffa710) -- not pinned here.",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=1, sort_keys=False) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
