"""Generate records.json for RE-001-optiontypeinfo-statistics-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-statistics-115/gen_records.py

Merges the hand-derived semantic records below with the live caller
census (census.py) so the census block in records.json is always a
fresh reproduction of the binary. The semantic records are the
packet's claims; verify.py re-checks them against the excerpts,
the relocations and the model.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
import census as census_mod

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SEMANTIC = {
    "task_id": "RE-001",
    "bounded_question": (
        "How does node #115 build the OptionTypeInfo record for a "
        "custom shared_ptr Statistics option, and how do the record's "
        "two create hooks resolve that option by name?"
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "node": 115,
    "objdump": "GNU objdump (GNU Binutils for Ubuntu) 2.42",
    "builder": {
        "address": "0x6071520",
        "fde": "0x6071520..0x60716ca",
        "bytes": 426,
        "symbol": (
            "rocksdb::OptionTypeInfo::AsCustomSharedPtr<rocksdb::Statistics>"
            "(int, OptionVerificationType, OptionTypeFlags)"
        ),
        "args": {
            "out": "rdi",
            "offset": "esi",
            "verification": "edx",
            "flags": "ecx",
        },
        "record_size": "0xb8",
        "fields": [
            {"offset": "+0x00", "name": "offset", "source": "esi (int)"},
            {"offset": "+0x08..+0x18", "name": "reserved", "value": 0},
            {"offset": "+0x18", "name": "create_hook_manager",
             "value": "0x606fa80", "via": "GOT slot 0x64eda58 (RELATIVE)"},
            {"offset": "+0x20", "name": "create_hook_invoker",
             "value": "0x60780a0", "via": "GOT slot 0x64eda60 (RELATIVE)"},
            {"offset": "+0x28..+0xa8", "name": "reserved", "value": 0},
            {"offset": "+0xa8", "name": "type", "value": 22,
             "note": "the custom-shared-ptr kind this builder writes"},
            {"offset": "+0xac", "name": "verification", "source": "edx"},
            {"offset": "+0xb0", "name": "flags", "source": "ecx"},
        ],
        "stack_temp": (
            "The builder first fills an identical 0xb8-byte record as "
            "a stack temporary at rsp+0x10 (offset at temp+0x00, hooks "
            "at temp+0x18, type 22 at temp+0xa8, verification at "
            "temp+0xac, flags at temp+0xb0) and then writes out "
            "field-wise from the temporary and the argument registers. "
            "The only other use of the temporary is the manager call."
        ),
        "manager_call": {
            "site": "0x607161e",
            "target": "0x606fa80",
            "args": "(out+0x8, temp+0x8, op 2)",
            "effect": (
                "No-op: op 2 is clone_functor and the lambda captures "
                "nothing, so the manager returns 0 without touching "
                "memory. The call is emitted by the template's "
                "std::function copy construction, not by any need of "
                "this builder."
            ),
        },
        "returns": "rax = out",
    },
    "manager": {
        "address": "0x606fa80",
        "fde": "0x606fa80..0x606faad",
        "bytes": 45,
        "role": (
            "std::function manager (_Function_handler manager) for the "
            "AsCustomSharedPtr<Statistics> lambda. Open PR #3386 "
            "records this address as the manager and explicitly "
            "excludes it from its packet; its internals are pinned "
            "here for the first time."
        ),
        "args": {
            "out": "rdi",
            "functor_storage": "rsi",
            "op": "edx",
        },
        "ops": [
            {"op": 0, "name": "get_type_info",
             "effect": (
                 "*(out) = 0x64d2d38, the address of the lambda "
                 "typeinfo object (vtable "
                 "__cxxabiv1::__class_type_info + 0x10, name string at "
                 "0x975620)")},
            {"op": 1, "name": "get_functor_ptr",
             "effect": "*(out) = *(functor_storage)"},
            {"op": 2, "name": "clone_functor",
             "effect": "no-op, returns 0 (empty lambda: nothing to copy)"},
            {"op": 3, "name": "destroy_functor",
             "effect": "no-op, returns 0 (empty lambda: nothing to free)"},
            {"op": "other",
             "effect": "no-op, returns 0"},
        ],
        "returns": "0 (eax) in every path",
    },
    "invoker": {
        "address": "0x60780a0",
        "fde": "0x60780a0..0x60781ab",
        "bytes": 267,
        "role": (
            "std::function _M_invoke for the AsCustomSharedPtr<Statistics> "
            "lambda: Status (const ConfigOptions&, const std::string&, "
            "const std::string&, void*), returned through a hidden "
            "sret pointer in rdi."
        ),
        "args": {
            "sret_status": "rdi (also returned in rax)",
            "functor": "rsi (discarded: the lambda is empty)",
            "config_options": "rdx (passed to the create host as its 2nd arg)",
            "id_string": "rcx (std::string: data at +0x00, length at +0x08)",
            "name_string": "r8 (std::string: data at +0x00, length at +0x08)",
            "dest_slot": "r9 (pointer to the destination shared_ptr slot)",
        },
        "id_fast_path": {
            "condition": (
                "id_string length == 2 and its first two bytes are "
                "'id' (word 0x6469) and name_string length == 0"
            ),
            "effect": (
                "Release the shared_ptr at *(dest_slot): zero the "
                "16-byte slot, then release its control block — packed "
                "use/weak counts at control+0x08 equal to 0x100000001 "
                "take the fast path (zero the counts, call the control "
                "block's vtable slots 0x10 dispose then 0x18 destroy); "
                "otherwise decrement the use count (lock xadd when the "
                "global byte at 0x64ed290 is 0, plain decrement "
                "otherwise) and, when the old use-count was 1, call the "
                "dispose helper 0x5d35070. Then write an empty Status "
                "(code 0, subcode 0, state null) to out and return out."
            ),
        },
        "forward_path": {
            "condition": "otherwise",
            "call": {
                "site": "0x60780d1",
                "target": "0x6077820",
                "args": "(out, config_options, name_string, *(dest_slot))",
            },
            "effect": "returns out (the host fills it)",
        },
    },
    "create_host_contract": {
        "address": "0x6077820",
        "fde": "0x6077820..0x60780a0",
        "bytes": 2176,
        "pinned_by": (
            "open PR #3386 (RE-001-basic-stats-factory-115) — cited "
            "here by contract only, not re-derived"
        ),
        "args": {
            "out": "rdi",
            "config_options": "rsi",
            "name_string": "rdx",
            "dest_slot": "rcx",
        },
        "dispatch_summary": (
            "Empty name or \"BasicStatistics\" constructs a fresh "
            "StatisticsImpl via ctor 0x6071a00 (open PR #3572) and "
            "installs it into *dest_slot; a name matching the "
            "registrar-built global string releases *dest_slot with an "
            "empty Status; any other name goes through the registry "
            "lookup 0x609e510 with translator 0x6076b20 and Status "
            "builder 0x61cf670 (open PR #3440). The once-registrar is "
            "0x6075bc0 (open PR #3386)."
        ),
    },
    "installer": {
        "site": "0x6074d8f",
        "kind": "direct_call",
        "containing_fde": "0x6073060..0x6075ae2",
        "args": {
            "out": "table slot at rbp-0x1cd0",
            "offset": 0,
            "verification": 3,
            "flags": 1,
        },
        "note": (
            "The containing function (0x6073060..0x6075ae2) is the "
            "options-table builder and is NOT pinned here; only this "
            "call site and its arguments are. It is the builder's sole "
            "direct caller in the binary."
        ),
    },
    "census_correction": {
        "census_claim": (
            "RE-002 vendor census matched this body 413/426 (96.95%) "
            "to _ZN7rocksdb14OptionTypeInfo17AsCustomSharedPtrINS_10FileSystemEEE"
        ),
        "correction": (
            "The GOT-resolved hooks prove Statistics, not FileSystem: "
            "the manager 0x606fa80 is the Statistics lambda manager "
            "(its kind-0 typeinfo name at 0x975620 is the "
            "AsCustomSharedPtr<Statistics> lambda) and the invoker "
            "0x60780a0 calls the Statistics create host 0x6077820 "
            "(which dispatches on \"BasicStatistics\", per open PR "
            "#3386). The 13 differing bytes are the hook pointers; "
            "the three instantiations share one code shape."
        ),
        "copies_in_binary": 1,
        "note": (
            "Sibling instantiations exist for other types "
            "(SystemClock 0x5fd0180, SliceTransform 0x6083a90, "
            "FilterPolicy invokers); each resolves its own hooks "
            "through its own GOT slots and is a separate work item."
        ),
    },
    "literals": [
        {"value": 22, "where": "builder 0x60715f9", "role": "type field"},
        {"value": "0x606fa80", "where": "GOT 0x64eda58",
         "role": "manager hook"},
        {"value": "0x60780a0", "where": "GOT 0x64eda60",
         "role": "invoker hook"},
        {"value": "0x64d2d38", "where": "manager 0x606faa0",
         "role": "lambda typeinfo object (kind 0)"},
        {"value": "0x975620", "where": "reloc at 0x64d2d40",
         "role": "lambda typeinfo name string"},
        {"value": "0x6469", "where": "invoker 0x60780fb",
         "role": "\"id\" word in the fast-path check"},
        {"value": "0x100000001", "where": "invoker 0x6078121",
         "role": "packed use/weak counts meaning last reference"},
        {"value": "0x64ed290", "where": "invoker 0x6078130",
         "role": "atomicity selector byte for the counted release"},
        {"value": "0x5d35070", "where": "invoker 0x607816b",
         "role": "counted-base dispose helper"},
    ],
    "unknowns": [
        "The OptionVerificationType / OptionTypeFlags enum spellings "
        "for the raw values verification 3 / flags 1 used by the sole "
        "installing call site; only the raw values are pinned.",
        "The semantic names of the invoker's two string args beyond "
        "their observed roles (rcx is the string compared to \"id\", "
        "r8 is the name string the create host dispatches on); the "
        "lambda's mangled type only fixes their C++ types.",
        "The runtime content of the registrar-built global string at "
        "0x6508980 that the create host compares the name against; it "
        "lives in .bss and is built by the once-registrar 0x6075bc0 "
        "(open PR #3386).",
        "Whether the \"id\" fast path means \"reset to the default "
        "object\" or \"release and return empty\" in the caller's "
        "terms; the binary only shows the release + empty Status.",
    ],
}


def build():
    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, "work/hl-node-115.bin"))
    records = dict(SEMANTIC)
    records["census"] = {}
    for t in census_mod.TARGETS:
        records["census"][hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    records["callers"] = {
        "0x6071520": [
            {"site": "0x6074d8f", "kind": "direct_call",
             "containing_fde": ["0x6073060", "0x6075ae2"]},
        ],
        "0x606fa80": [
            {"site": "0x607161e", "kind": "direct_call",
             "containing_fde": ["0x6071520", "0x60716ca"]},
        ],
        "0x6077820": [
            {"site": "0x60780d1", "kind": "direct_call",
             "containing_fde": ["0x60780a0", "0x60781ab"]},
        ],
    }
    records["packet_internal_sites"] = {
        "0x5d35070": [
            {"site": "0x607816b", "kind": "direct_call",
             "containing_fde": ["0x60780a0", "0x60781ab"]},
        ],
    }
    return records


def main():
    records = build()
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
