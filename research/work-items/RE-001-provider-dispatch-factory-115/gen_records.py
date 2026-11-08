#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-provider-dispatch-factory-115/gen_records.py

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
    "work_item": "RE-001-provider-dispatch-factory-115",
    "question": (
        "What does the small host 0x5ffabd0 do -- the 2-site RegisterOptions "
        "host from #4372's census and the non-'ROT13' dispatch path left "
        "open by #4395 -- and how does its delegate 0x5ffa710 resolve a "
        "provider name? Resolves the open unknowns left by #4395 (the "
        "0x5ffabd0 dispatch) and #4372 (census site 0x5ffacee)."
    ),
    "artifact": "work/hl-node-115.bin",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4395,
        "open_unknown": (
            "The small host 0x5ffabd0's full dispatch (the non-'ROT13' "
            "path via 0x60bb890 / 0x5ffa710) -- not pinned in #4395; "
            "also #4372's census site 0x5ffacee (RegisterOptions in "
            "FDE 0x5ffabd0..0x5ffae04)."
        ),
        "answer": (
            "The host 0x5ffabd0 is slot 21 of the CTREncryptionProvider "
            "vtable 0x64cffb0: a dispatch factory (Status* out, holder, "
            "name, block_size). If the holder's cipher slot (+0x20) is "
            "already occupied it returns kNotSupported 'Cannot add keys "
            "to CTREncryptionProvider' (40 bytes, literal 0x968090). "
            "If name == 'ROT13' (literal 0x4487d6) it builds a 0x28-byte "
            "ROT13BlockCipher in place (vtable 0x64cfea0, block_size "
            "from r8 at +0x20), registers group 'ROT13BlockCipherOptions' "
            "with the block_size map 0x65052c0, wraps the cipher in a "
            "0x18-byte non-inplace shared_ptr control block (vtable "
            "0x64d0128, counts (1,1) from 0x459b20) and stores it into "
            "the holder, releasing the old cipher. Otherwise it copies "
            "the name into a stack string, default-inits a ConfigOptions "
            "with 0x60bb890, and delegates to the registry dispatcher "
            "0x5ffa710, which pthread_once-inits the provider registry "
            "map 0x6505278, configures the provider through the "
            "options-map host 0x609e510, and either resets the cipher "
            "slot or dispatches to the registry factory 0x5ff9fe0."
        ),
    },
    "factory_0x5ffabd0": {
        "address": "0x5ffabd0",
        "fde": "0x5ffabd0..0x5ffae04",
        "vtable": "0x64cffb0",
        "vtable_slot": 21,
        "vtable_typeinfo": "N7rocksdb21CTREncryptionProviderE",
        "signature": "(Status* out, holder, name char*, block_size)",
        "gate": {
            "site": "0x5ffabf9",
            "test": "holder+0x20 (cipher shared_ptr object) == 0",
            "occupied_outcome": {
                "status": "kNotSupported (code 3)",
                "message": "Cannot add keys to CTREncryptionProvider",
                "message_literal": "0x968090",
                "message_bytes": 40,
                "location": "empty string 0x4376fd",
                "status_ctor_site": "0x5ffac3b",
            },
        },
        "rot13_path": {
            "name_test": "strcmp(name, 'ROT13' @ 0x4487d6) == 0 at 0x5ffac83",
            "steps": [
                "operator new 0x28 bytes for the cipher (call 0x5ffac95)",
                "build the group name 'ROT13BlockCipherOptions' from "
                "literal 0x443890 with 0x5ff0300 at 0x5ffacd9",
                "store vtable 0x64cfea0 at +0x00 (lea 0x5ffacc1); zero "
                "+0x08/+0x10/+0x18 (the Configurable group-vector triple)",
                "store the block_size argument (r8) at +0x20 (0x5ffacc8)",
                "call RegisterOptions 0x6099ce0 at 0x5ffacee with "
                "(cipher, name, options base cipher+0x20, map 0x65052c0)",
                "operator new 0x18 bytes for the shared_ptr control "
                "block (call 0x5ffad15)",
                "load the (1,1) counts from qword 0x459b20 (0x5ffad1a); "
                "store the control-block vtable 0x64d0128 at +0x00 "
                "(lea 0x5ffad31), the counts at +0x08, the cipher at "
                "+0x10",
                "store the cipher at holder+0x20 and the control block "
                "at holder+0x28; release the old control block via "
                "0x5d350c0 (call 0x5ffad44) when non-null",
                "write a 16-byte zero Status (kOk) into *out and return "
                "rdi (0x5ffad4b)",
            ],
            "object": {
                "size_bytes": 40,
                "vtable": "0x64cfea0",
                "typeinfo": "*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE",
                "typeinfo_object": "0x64cf770",
            },
            "control_block": {
                "size_bytes": 24,
                "vtable": "0x64d0128",
                "typeinfo": (
                    "*St15_Sp_counted_ptrIPN7rocksdb12_GLOBAL__N_1"
                    "16ROT13BlockCipherELN9__gnu_cxx12_Lock_policyE2EE"
                ),
                "typeinfo_object": "0x64cf820",
                "use_weak_counts": "(1, 1)",
                "counts_source": "qword 0x459b20 = 0x100000001",
                "note": (
                    "Non-inplace: the cipher (0x28) and its control "
                    "block (0x18) are separate allocations, unlike the "
                    "0x38-byte inplace blocks built by the 0x5ff6a00 / "
                    "0x5ff6d60 factories in #4395."
                ),
            },
        },
        "delegate_path": {
            "condition": "strcmp(name, 'ROT13') != 0",
            "steps": [
                "copy the name into the stack string at 0x20(%rsp) "
                "with 0x5ff0300 at 0x5ffad7c",
                "default-init the ConfigOptions at 0x40(%rsp) with "
                "0x60bb890 at 0x5ffad84",
                "call the registry dispatcher 0x5ffa710 at 0x5ffad95 "
                "with (out, opts=0x40(%rsp), name=0x20(%rsp), "
                "cipher-slot=&holder+0x20)",
                "release the ConfigOptions' shared_ptr field at "
                "0x88(%rsp) via 0x5d350c0 (call 0x5ffad9a) when "
                "non-null; dispose the stack strings; return",
            ],
        },
        "e8_callers": [],
        "lea_references": [],
        "reach_note": (
            "No direct E8 caller and no lea site binary-wide: the "
            "factory is reached only through CTREncryptionProvider "
            "vtable slot 21 (rela addend 0x5ffabd0 at 0x64d0058)."
        ),
    },
    "dispatcher_0x5ffa710": {
        "address": "0x5ffa710",
        "fde": "0x5ffa710..0x5ffaad9",
        "signature": "(Status* out, ConfigOptions* opts, name string, cipher-slot*)",
        "twin": "0x5ffba10 (byte-identical modulo RIP-relative operands)",
        "steps": [
            "pthread_once-init the provider registry map 0x6505278 "
            "with init routine 0x5ff9c50 (call 0x5ffa790; GOT guards "
            "0x64ed818/0x64ed820/0x64ed828)",
            "build a 56-byte stack option map at 0x50(%rsp) (bucket "
            "count 1, load factor 1.0f) and an empty out_name string "
            "at 0x90(%rsp)",
            "call the options-map host 0x609e510 at 0x5ffa85a with "
            "(Status@0x20(%rsp), opts, object=*cipher-slot, name, "
            "out_name, map)",
            "on a non-kOk Status: move-assign it into *out with "
            "0x5fefe90 (call 0x5ffa886), clean up, return",
            "on kOk with a non-empty out_name: call the registry "
            "factory dispatch 0x5ff9fe0 at 0x5ffa962 with (Status@"
            "0x40(%rsp), ConfigOptions+0x40, out_name, cipher-slot); "
            "the returned Status is moved to the stack temp at "
            "0x30(%rsp), then: if ConfigOptions byte +0x01 != 0 and "
            "the code is 3, the temp is zeroed (0x5ffaa70) and *out = "
            "kOk (the error is swallowed); if +0x01 == 0 and the code "
            "is 0, the null-checked configure entry 0x609e2d0 runs at "
            "0x5ffaa45 and its result becomes *out; otherwise the "
            "factory Status becomes *out",
            "on kOk with an empty out_name and a non-empty map: "
            "kNotSupported 'Cannot reset object ' (20 chars, literal "
            "0x433f9f) via the Status ctor at 0x5ffaa27",
            "on kOk with an empty out_name and an empty map: zero "
            "the cipher shared_ptr slot, release the old cipher via "
            "0x5d350c0 (call 0x5ffa918) when non-null, *out = kOk",
        ],
        "e8_callers": ["0x5ffad95", "0x5ffae40"],
        "note": (
            "The factory-dispatch tail is pinned at branch level "
            "(the +0x01 gate, the code-3 swallow, the code-0 "
            "0x609e2d0 fallback); the C++ meaning of ConfigOptions "
            "byte +0x01 and the per-move order of the Status temps "
            "are open unknowns."
        ),
    },
    "wrapper_0x5ffae10": {
        "address": "0x5ffae10",
        "fde": "0x5ffae10..0x5ffaea1",
        "signature": "(Status* out, ?, ?, record rcx, record r8, shared_ptr-slot r9)",
        "twin": "0x5ffbde0 (byte-identical modulo RIP-relative operands)",
        "steps": [
            "if rcx+0x08 == 2 and the string at (%rcx) starts with "
            "'id' (immediate 0x6469 at 0x5ffae63) and r8+0x08 == 0: "
            "zero the shared_ptr at (%r9), releasing the old cipher "
            "via 0x5d350c0 (call 0x5ffae81) when non-null, *out = kOk, "
            "return",
            "otherwise forward (out, rdx, r8, (%r9)) to the dispatcher "
            "0x5ffa710 (call 0x5ffae40)",
        ],
        "e8_callers": [],
        "address_taken": "GOT slot 0x64ed9b0 (RELATIVE reloc, addend 0x5ffae10)",
        "note": (
            "No direct E8 caller: the address is taken in a GOT slot, "
            "so the wrapper is reached through a function-pointer "
            "table; no RIP-relative lea/mov-load of that GOT slot "
            "exists in .text, so the table is reached by indexed "
            "access -- the exact indexing is an open unknown."
        ),
    },
    "registry_factory_dispatch_0x5ff9fe0": {
        "address": "0x5ff9fe0",
        "fde": "0x5ff9fe0..0x5ffa674",
        "role": (
            "Cited callee of the dispatcher: looks the resolved name "
            "up in the provider registry (lookup helper 0x5ff9c60, "
            "called at 0x5ffa023) and invokes the matched factory "
            "through an indirect call; error paths build Status "
            "messages from literals 0x4487c0 ('Cannot make a shared '), "
            "0x43fa43 ('BlockCipher'), 0x432138 (' from unguarded one "
            "'), 0x439466 ('Could not load ')."
        ),
        "e8_callers": ["0x5ffa962"],
        "note": "Internals (lookup key, factory-table layout) are open.",
    },
    "config_init_0x60bb890": {
        "address": "0x60bb890",
        "fde": "0x60bb890..0x60bb932",
        "role": "ConfigOptions default initializer (cited callee)",
        "steps": [
            "write 0x01010100 at +0x00, +0x08 = &+0x18, byte +0x04 = 0, "
            "+0x10 = 1, ';' (0x3b) at +0x18, +0x28 = 0, byte +0x2c = "
            "0xff, +0x30 = 0x80000",
            "call 0x5fe2860 twice, storing each result at +0x38; call "
            "0x61f9400 on +0x40",
        ],
        "e8_callers": [
            "0x5d8eacf", "0x5e3406f", "0x5e34458", "0x5ffad84",
            "0x60a1dcf", "0x60a20cd", "0x60d4a48", "0x612073b",
            "0x61c83aa",
        ],
        "note": (
            "A shared helper (9 call sites binary-wide); the field "
            "identities of +0x08/+0x38/+0x40 are open."
        ),
    },
    "string_ctor_0x5ff0300": {
        "address": "0x5ff0300",
        "fde": "0x5ff0300..0x5ff03e3",
        "role": "std::string ctor from a C string (cited callee)",
        "steps": [
            "strlen the source; SSO (<=15 bytes) copies inline with a "
            "NUL terminator; longer strings heap-allocate via _M_create",
        ],
        "e8_callers": [
            "0x5ff113b", "0x5ff6e3c", "0x5ff7362", "0x5ff7dbf",
            "0x5ff7e6a", "0x5ff810b", "0x5ff8918", "0x5ff8ae3",
            "0x5ff8b84", "0x5ff912e", "0x5ff92f0", "0x5ff937c",
            "0x5ffa1d4", "0x5ffa32a", "0x5ffa411", "0x5ffacd9",
            "0x5ffad7c", "0x5ffb4d4", "0x5ffb63a", "0x5ffb719",
        ],
    },
    "maps": {
        "0x65052c0": {
            "group": "ROT13BlockCipherOptions",
            "entries": [
                {
                    "key": "block_size",
                    "key_literal": "0x43a5f7",
                    "insert_site": "0x5ff7fc4",
                    "atexit_site": "0x5ff8016",
                    "pack_record+0xa8": "0x100000016",
                    "type": 22,
                    "verification": 1,
                    "flags_record+0xb0": "0x400",
                    "offset_record+0x00": 0,
                },
            ],
            "initializer": "0x5ff7c90 (pinned by #4389)",
            "note": (
                "The dispatch factory registers against the same map "
                "as the 0x5ff6a00 / 0x5ff6d60 / 0x5ff7120 factories."
            ),
        },
        "0x6505278": {
            "role": "provider registry map",
            "initializer": "0x5ff9c50 via pthread_once",
            "lea_references": ["0x5ffa786", "0x5ffba86"],
            "entries": (
                "The (factory, paired-function) pairs of #4395 "
                "('1://test' -> 0x5ff6a00, 'CTR' -> 0x5ff6d60, 'ROT13' "
                "-> 0x5ff7120); the full entry list is built by the "
                "initializer and is open."
            ),
        },
    },
    "vtables": {
        "0x64cffb0": {
            "typeinfo": "N7rocksdb21CTREncryptionProviderE",
            "typeinfo_object": "0x64cf740",
            "slots": 27,
            "pinned_slots": {
                "0": "complete dtor 0x5ff2f00",
                "1": "deleting dtor 0x5ff30b0 (#4395)",
                "9": "ConfigureOptions entry 0x609d0e0 (#4334)",
                "10": "ConfigureOption core 0x60986b0 (#4328)",
                "12": "slot-12 serializer 0x609de80 (#4328)",
                "13": "GetOptionName 0x609d980 (#4334)",
                "15": "GetId 0x5d32a30 (#4328)",
                "16": "name-match predicate override 0x5ff1030 (base "
                      "0x5d2e770, #4349)",
                "17": "Inner 0x5d2ca00 (#4349)",
                "18": "NickName() 0x5d2ca10 (#4349)",
                "21": "dispatch factory 0x5ffabd0 (pinned here)",
            },
            "open_slots": "19 (0x5fefa30), 20 (0x5ff5140), 22 (0x5ff3890), "
                          "23 (0x5ff02e0), 24 (0x5fefa40), 25 (0x5ff49b0)",
        },
        "0x64d0128": {
            "typeinfo": (
                "*St15_Sp_counted_ptrIPN7rocksdb12_GLOBAL__N_1"
                "16ROT13BlockCipherELN9__gnu_cxx12_Lock_policyE2EE"
            ),
            "typeinfo_object": "0x64cf820",
            "slots": 6,
            "slot_targets": ["0x5fefb60", "0x5fefd10", "0x5ff0580",
                             "0x5fefd20", "0x5fefc60", "0x0"],
        },
    },
    "cited_context": {
        "0x609e510": "options-map host (pinned by #4349); called at "
                     "0x5ffa85a and 0x5ffbb5a",
        "0x6099ce0": "RegisterOptions helper (pinned by #4372); the "
                     "dispatch factory's site is 0x5ffacee",
        "0x609e2d0": "null-checked configure entry (pinned by #4334); "
                     "called at 0x5ffaa45 and 0x5ffbd45",
        "0x5d350c0": "shared_ptr control-block release (pinned by "
                     "#4395); 7 sites in this packet",
        "0x61cf670": "Status ctor (code, location, message); 7 sites "
                     "in this packet",
        "0x5fefe90": "Status move-assign; the dispatcher's error path",
        "0x5ff7120": "ROT13 ':'-split factory (pinned by #4389); the "
                     "registered 'ROT13' entry",
        "0x5ff6a00": "1://test factory (pinned by #4395)",
        "0x5ff6d60": "CTR factory (pinned by #4395)",
    },
    "open_unknowns": [
        "The C++ name of the slot-21 virtual (0x5ffabd0): its behavior "
        "is an add-cipher entry (gate + ROT13 build + registry "
        "delegate), but the source name is open.",
        "The exact C++ type of the factory's holder argument and of "
        "the out slot -- open.",
        "The registry factory dispatch 0x5ff9fe0's internals: the "
        "lookup key, the factory-table layout, and the per-branch "
        "Status outcomes -- open.",
        "The C++ meaning of ConfigOptions byte +0x01 (the gate that "
        "chooses the code-3 swallow vs the code-0 0x609e2d0 fallback "
        "in the dispatcher tail) -- open; the branch structure itself "
        "is pinned.",
        "The wrapper 0x5ffae10's record arguments (rcx/r8): which "
        "option records they are, and why the 'id' + count-2 + "
        "empty-r8 case clears the cipher instead of dispatching -- open.",
        "Why two byte-identical dispatcher/wrapper pairs exist "
        "(0x5ffa710/0x5ffae10 vs 0x5ffba10/0x5ffbde0): distinct "
        "instantiations or duplicate emission -- open.",
        "The ConfigOptions field identities at +0x08/+0x38/+0x40 "
        "(0x60bb890) and +0x48 (released in the delegate cleanup) -- open.",
        "The CTR vtable slots 19/20/22/23/24/25 and the control-block "
        "vtable slots 0..4 (0x5fefb60/0x5fefd10/0x5ff0580/0x5fefd20/"
        "0x5fefc60) -- C++ names open.",
        "The slot-16 override 0x5ff1030's body (the CTR provider's "
        "name-match predicate) -- not pinned here.",
        "The remaining RegisterOptions clusters from #4372's census "
        "(2-site hosts 0x6029390 / 0x6086e00 / 0x6202a10 / 0x6205790) "
        "-- still unanalysed.",
    ],
}

if __name__ == "__main__":
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2) + "\n")
    print(f"wrote records.json ({len(RECORDS)} top-level keys)")
