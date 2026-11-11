#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-registry-factory-dispatch-115/gen_records.py

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
    "work_item": "RE-001-registry-factory-dispatch-115",
    "question": (
        "What does the registry factory dispatch 0x5ff9fe0 do -- the "
        "BlockCipher dispatch cited (not pinned) by #4402 -- how does its "
        "name lookup 0x5ff9c60 resolve a provider name in the registry, "
        "and why do two byte-similar dispatcher/wrapper pairs exist "
        "(#4402's open unknown)? Resolves #4402's open unknowns: "
        "'0x5ff9fe0 internals' and 'why two byte-identical "
        "dispatcher/wrapper pairs exist'."
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4402,
        "open_unknowns": [
            "0x5ff9fe0 internals (the registry factory dispatch)",
            "why two byte-identical dispatcher/wrapper pairs exist",
            "ConfigOptions +0x40 field identity (the registry pointer)",
        ],
        "answer": (
            "0x5ff9fe0 is the BlockCipher registry factory dispatch "
            "(Status* out, ObjectRegistry* registry, name, "
            "shared_ptr<BlockCipher>* cipher_slot). It resolves the name "
            "through the lookup 0x5ff9c60, invokes the matched creator "
            "through the factory record's +0x18 invoker, and wraps the "
            "returned raw object in a fresh 0x18-byte non-inplace "
            "shared_ptr control block (vtable 0x64d0198). The two "
            "dispatcher/wrapper pairs are parallel instantiations of the "
            "same template for two factory types: the 0x5ffa710 pair "
            "dispatches BlockCipher (lookup 0x5ff9c60, dispatch 0x5ff9fe0) "
            "while the 0x5ffba10 pair dispatches EncryptionProvider "
            "(lookup 0x5ffaeb0, dispatch 0x5ffb250). ConfigOptions+0x40 is "
            "a std::shared_ptr<ObjectRegistry> (object at +0x40, control "
            "at +0x48), built by the default init 0x60bb890 through "
            "0x61f9400; the dispatcher passes its object pointer as the "
            "registry."
        ),
    },
    "dispatch_0x5ff9fe0": {
        "fde": "0x5ff9fe0..0x5ffa674",
        "signature": (
            "(Status* out, ObjectRegistry* registry, "
            "const std::string& name, shared_ptr<BlockCipher>* cipher_slot)"
        ),
        "sole_caller": "0x5ffa962 in the dispatcher 0x5ffa710 (#4402)",
        "frame": "0xf8 bytes, stack canary at 0xe8(%rsp)",
        "lookup_call": "0x5ffa023 -> 0x5ff9c60",
        "factory_call": "indirect call *0x78(%rsp) (record+0x18, the invoker)",
        "outcomes": [
            {
                "condition": "lookup returns a zeroed record (manager null)",
                "status": "kNotSupported (code 3)",
                "message": "Could not load BlockCipher: <name>",
                "sites": ["0x5ffa3e8", "0x5ffa47d"],
            },
            {
                "condition": "factory returns null",
                "status": "kInvalidArgument (code 4)",
                "message": "Could not load BlockCipher: <name>",
                "sites": ["0x5ffa2f0", "0x5ffa372"],
            },
            {
                "condition": "factory returns non-null but stores nothing "
                             "in the slot",
                "status": "kInvalidArgument (code 4)",
                "message": "Cannot make a shared BlockCipher from "
                           "unguarded one : <name>",
                "sites": ["0x5ffa1b0", "0x5ffa29d"],
            },
            {
                "condition": "factory returns non-null and stores the raw "
                             "object in the slot",
                "status": "kOk (code 0)",
                "action": "new 0x18-byte control block (vtable 0x64d0198, "
                          "counts (1,1) from 0x459b20, object at +0x10); "
                          "store (object, control) into the out cipher "
                          "slot; release the old cipher via 0x5d350c0",
                "sites": ["0x5ffa106", "0x5ffa131", "0x5ffa13c", "0x5ffa14b"],
            },
        ],
        "record_destroy": (
            "after a non-null factory return the record is destroyed via "
            "its manager with op 3 (0x5ffa0e2); a no-op for the three "
            "registered managers"
        ),
        "status_temp": (
            "the 16 bytes at 0x30(%rsp) are a Status temp, zeroed to kOk "
            "after the factory call; a non-kOk value there would be "
            "move-assigned into *out at 0x5ffa2c0 -- no registered creator "
            "writes it, so that path is defensive (open unknown)"
        ),
        "status_ctor": (
            "0x61cf670(out, code, subcode 0, msg1, msg2, severity 0): "
            "message is msg1, or msg1 + ': ' + msg2 when msg2 is non-empty"
        ),
    },
    "lookup_0x5ff9c60": {
        "fde": "0x5ff9c60..0x5ff9fd7",
        "signature": (
            "(FactoryRecord* out, ObjectRegistry* registry, "
            "const std::string& name) -> FactoryRecord*"
        ),
        "callers": ["0x5ffa023 in 0x5ff9fe0", "0x5ff9e1c (recursion)"],
        "registry_layout": {
            "+0x00/+0x08": "libraries vector (begin/end)",
            "+0x60": "parent registry pointer (recursed into on exhaustion)",
            "+0x98": "pthread_mutex_t (locked for the whole walk)",
        },
        "algorithm": [
            "lock the registry mutex at +0x98 (lock failure throws "
            "system_error with the errno)",
            "walk the libraries vector backwards, 16-byte elements "
            "(first qword = library pointer; second qword unread, open "
            "unknown)",
            "per library lock its mutex at +0x00, then query its map at "
            "+0x28 for the type name via 0x5fd2980",
            "on a hit walk the entry's candidate vector (+0x28/+0x30) and "
            "call each candidate's vtable slot 2 (Matches, forwards to "
            "PatternEntry Matches 0x61f8670) with (candidate, name)",
            "on a match clone the factory record (manager op 2, a no-op "
            "here, plus the explicit 16-byte copy of the "
            "{manager, invoker} pair) into *out and return",
            "on exhaustion unlock and recurse into the parent registry at "
            "+0x60; with no parent zero *out",
        ],
        "map_key": "BlockCipher (11 chars, built SSO with movabs)",
        "manager_ops_observed": (
            "op 2 (clone) and op 3 (destroy) are called on the record's "
            "manager; both are no-ops for 0x5fefa50/0x5fefa80/0x5fefab0 "
            "(RegisterEncryptionBuiltins packet)"
        ),
    },
    "factory_record": {
        "size": "0x20 bytes",
        "layout": {
            "+0x00": "functor storage (16 bytes, zero for stateless lambdas)",
            "+0x10": "manager function pointer",
            "+0x18": "invoker (the creator lambda's _M_invoke)",
        },
        "invoker_signature": (
            "(record, name, slot_ptr_ptr, string*) -> raw BlockCipher* "
            "or null; stores the new raw object at *slot_ptr_ptr"
        ),
        "factory_slot_protocol": (
            "the creator stores the new raw object pointer at the slot "
            "(0x5ff729a in the ROT13 creator 0x5ff7120), destroying any "
            "previous object there through its vtable slot 1, and returns "
            "the same pointer; null return means failure"
        ),
    },
    "control_block": {
        "size": "0x18 bytes",
        "vtable": "0x64d0198",
        "typeinfo": (
            "St15_Sp_counted_ptrIPN7rocksdb11BlockCipherE"
            "LN9__gnu_cxx12_Lock_policyE2EE"
        ),
        "typeinfo_addr": "0x64cf850",
        "layout": {
            "+0x00": "vtable 0x64d0198",
            "+0x08": "counts (1, 1) from qword 0x459b20",
            "+0x10": "object pointer",
        },
        "slots": [
            {"slot": 0, "addr": "0x5fefb50"},
            {"slot": 1, "addr": "0x5fefce0"},
            {"slot": 2, "addr": "0x5fefc20"},
            {"slot": 3, "addr": "0x5fefcf0"},
            {"slot": 4, "addr": "0x5fefc40"},
        ],
    },
    "twin_pair": {
        "dispatch": "0x5ffb250 (FDE 0x5ffb250..0x5ffb981)",
        "lookup": "0x5ffaeb0 (FDE 0x5ffaeb0..0x5ffb247)",
        "dispatch_caller": "0x5ffbc62 in the twin dispatcher 0x5ffba10",
        "lookup_callers": ["0x5ffb294 in 0x5ffb250", "0x5ffb08c (recursion)"],
        "map_key": "EncryptionProvider (18 chars, heap-backed: 16 bytes "
                   "from literal 0x4539b0 via movdqa + 'er' 0x7265)",
        "error_type_name": "EncryptionProvider (literal 0x43e76f)",
        "correction_to_pr_4402": (
            "the twins are NOT byte-identical: the dispatcher calls "
            "0x5ff9fe0 at 0x5ffa962 while the twin dispatcher calls "
            "0x5ffb250 at 0x5ffbc62, and the twin lookup queries "
            "'EncryptionProvider' instead of 'BlockCipher'. The pairs are "
            "parallel instantiations of the same template, one per "
            "factory type."
        ),
    },
    "config_options_registry": {
        "field": "+0x40 (16 bytes)",
        "identity": (
            "std::shared_ptr<ObjectRegistry>: object pointer at +0x40, "
            "control block at +0x48"
        ),
        "built_by": (
            "the default init 0x60bb890 calls 0x61f9400(&opts+0x40), which "
            "allocates a fresh 0xd0-byte registry (control-block vtable "
            "0x64d8f00, counts (1,1)) from the getter 0x61f92b0 (PR #4015) "
            "and stores (object+0x10, control) at +0x40/+0x48"
        ),
        "use": (
            "the dispatcher reads opts+0x40 as the registry and passes it "
            "to 0x5ff9fe0 (0x5ffa940 -> 0x5ffa962)"
        ),
    },
    "registered_creators": {
        "CTR": {"invoker": "0x5ff6d60", "manager": "0x5fefa50",
                "pattern": "CTR", "elements": [["://test", 2]],
                "matches": ["CTR", "CTR://test"]},
        "1://test": {"invoker": "0x5ff6a00", "manager": "0x5fefa80",
                     "pattern": "1://test", "elements": [],
                     "matches": ["1://test"]},
        "ROT13": {"invoker": "0x5ff7120", "manager": "0x5fefab0",
                  "pattern": "ROT13", "elements": [[":", 3]],
                  "matches": ["ROT13", "ROT13:<digits>"]},
        "matcher": "FactoryEntry vtable slot 2 (Matches) forwards to "
                   "PatternEntry Matches 0x61f8670 (PR #3983)",
    },
    "literals": {
        "0x4487c0": "Cannot make a shared ",
        "0x43fa43": "BlockCipher",
        "0x432138": " from unguarded one ",
        "0x439466": "Could not load ",
        "0x43e76f": "EncryptionProvider",
        "0x4474d2": "basic_string::append",
        "0x4539b0": "EncryptionProvid (first 16 bytes; 'er' comes from "
                    "the 0x7265 immediate in 0x5ffaeb0)",
    },
    "open_unknowns": [
        "which factory writes a non-kOk Status into the dispatch's "
        "0x30(%rsp) temp (the 0x5ffa2c0 move-assign path is defensive; no "
        "registered creator writes it)",
        "the libraries vector element's second qword (the lookup reads "
        "only the first qword, the library pointer)",
        "the library object's fields at +0x08..+0x27 (mutex at +0x00, map "
        "at +0x28)",
        "the map value's owning type (0x5fd2980 returns the entry whose "
        "+0x28/+0x30 candidate vector the lookup walks)",
        "the control-block vtable slots 0..4 (0x5fefb50/0x5fefce0/0x5fefc20/"
        "0x5fefcf0/0x5fefc40) method identities",
        "the sibling dispatches at 0x5fd4080..0x5fd4627 and "
        "0x6136b40..0x613721b (same 'Cannot make a shared ' / "
        "'Could not load ' literals, other factory types)",
        "the twin dispatch's second release site 0x5ffb406 (the "
        "BlockCipher dispatch has one, 0x5ffa14b)",
    ],
    "cited_not_pinned": [
        "0x5ff88c0 RegisterEncryptionBuiltins host (RegisterEncryptionBuiltins packet)",
        "0x5ff6a00/0x5ff6d60/0x5ff7120 creators (#4395, #4389)",
        "0x5fefa50/0x5fefa80/0x5fefab0 managers (RegisterEncryptionBuiltins packet)",
        "0x5ffa710/0x5ffba10 dispatchers and 0x5ffae10/0x5ffbde0 wrappers (#4402)",
        "0x60bb890 ConfigOptions default init (#4402)",
        "0x61f92b0 default-registry getter (PR #4015)",
        "0x5fd2980 map lookup helper",
        "0x61cf670 Status ctor, 0x5fefe90 Status move-assign",
        "0x5d350c0 shared_ptr release, 0x5ff0300 string ctor",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2) + "\n")
    print(f"wrote records.json ({len(RECORDS)} top-level keys)")


if __name__ == "__main__":
    main()
