"""Generate records.json, callers.tsv and relocations.txt for this packet.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-slicetransform-115/gen_records.py

Reads the census (census.py) and the frames dump, maps every census
site to its containing FDE, and writes the three files. The semantic
records below were read off the verbatim excerpts by hand; this
script only assembles them with the machine-derived census.
"""

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
import census as census_mod

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN = "work/hl-node-115.bin"

FDE_RE = re.compile(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def load_fdes():
    out = subprocess.run(
        ["objdump", "--dwarf=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in out.splitlines():
        m = FDE_RE.search(line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing_fde(fdes, site):
    for s, e in fdes:
        if s <= site < e:
            return (s, e)
    return None


RECORDS = {
    "task_id": "RE-001",
    "bounded_question": (
        "How does node #115 build the OptionTypeInfo record for a custom "
        "shared_ptr SliceTransform option, and how do the record's two "
        "create hooks resolve that option by name?"),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "node": 115,
    "objdump": "GNU objdump 2.42",
    "builder": {
        "address": "0x6083a90",
        "fde": "0x6083a90..0x6083c83",
        "bytes": 499,
        "symbol": (
            "rocksdb::OptionTypeInfo::AsCustomSharedPtr<const "
            "rocksdb::SliceTransform>(int, OptionVerificationType, "
            "OptionTypeFlags)"),
        "args": {"out": "rdi", "offset": "esi", "verification": "edx",
                 "flags": "ecx"},
        "record_size": "0xb8",
        "fields": [
            {"offset": "+0x00", "name": "offset", "source": "esi (int)"},
            {"offset": "+0x04", "name": "padding",
             "note": "never written by the builder or by the copy helper; "
                     "its content is indeterminate"},
            {"offset": "+0x08..+0x18", "name": "reserved", "value": 0},
            {"offset": "+0x18", "name": "create_hook_manager",
             "value": "0x607d190", "via": "GOT slot 0x64eda68 (RELATIVE)"},
            {"offset": "+0x20", "name": "create_hook_invoker",
             "value": "0x60809e0", "via": "GOT slot 0x64edb70 (RELATIVE)"},
            {"offset": "+0x28..+0xa8", "name": "reserved", "value": 0},
            {"offset": "+0xa8", "name": "type", "value": 22,
             "note": "the custom-shared-ptr kind this builder writes"},
            {"offset": "+0xac", "name": "verification", "source": "edx"},
            {"offset": "+0xb0", "name": "flags", "source": "ecx"},
        ],
        "stack_temp": (
            "The builder first fills an identical 0xb8-byte record as a "
            "stack temporary at rsp+0x20 (offset at temp+0x00, hooks at "
            "temp+0x18, type 22 at temp+0xa8, verification at temp+0xac, "
            "flags at temp+0xb0) and then installs it into out with the "
            "record-copy helper 0x5e332c0 (site 0x6083b76). It also builds "
            "the create-hook std::function itself on the stack at rsp+0x00 "
            "(32 bytes: zero _Any_data, manager at +0x10, invoker at "
            "+0x18)."),
        "cleanup": (
            "After the copy the builder destroys the stack functor "
            "(manager op 3, site 0x6083b90) and each of the temporary "
            "record's five std::function members in turn (manager op 3, "
            "sites 0x6083c19 for the create-hook member at rsp+0x28, "
            "0x6083c00 for rsp+0x48, 0x6083be7 for rsp+0x68, 0x6083bce "
            "for rsp+0x88, 0x6083baf for rsp+0xa8). Every one of those "
            "calls is a proven no-op: the lambda captures nothing (so "
            "its manager's op 3 returns 0 without touching memory) and "
            "the other four members are zero. The record destructor "
            "0x5d3f950 is called ONLY on the landing pad (site "
            "0x6083c55), not on the normal path. This differs from the "
            "SystemClock sibling builder 0x5fd0180 (open PR #3715), whose "
            "normal path calls the record destructor (site 0x5fd0285) "
            "and emits no per-member op-3 calls: the SliceTransform "
            "builder inlines the destructor's member destroys."),
    },
    "copy_helper": {
        "address": "0x5e332c0",
        "role": (
            "OptionTypeInfo copy-assignment, pinned by open PR #3715 and "
            "cited here by contract: copies the 4-byte offset, then for "
            "each of the five std::function members at "
            "+0x08/+0x28/+0x48/+0x68/+0x88 zeroes the destination member, "
            "clones it through the source member's manager with op 2 "
            "when the manager is non-null, and copies the "
            "manager+invoker pair; then copies type+verification (8 "
            "bytes at +0xa8) and flags (4 bytes at +0xb0). Shared by "
            "every OptionTypeInfo installer in the binary (91 direct "
            "call sites, including this builder's site 0x6083b76 and "
            "the SystemClock builder's site 0x5fd0266)."),
        "by_contract_from": "RE-001-optiontypeinfo-systemclock-115 (#3715)",
    },
    "manager": {
        "address": "0x607d190",
        "fde": "0x607d190..0x607d1bd",
        "bytes": 45,
        "role": (
            "The std::function manager for the AsCustomSharedPtr<const "
            "SliceTransform> lambda. Op 0 (get_type_info) writes the "
            "typeinfo object 0x64d3018; op 1 (get_functor_ptr) copies "
            "the functor pointer; ops 2 (clone), 3 (destroy) and "
            "anything else return 0 without touching memory. It has no "
            "direct call site: it is reached only through the GOT slot "
            "0x64eda68 and the copy helper's indirect manager call. "
            "Pinned here for the first time."),
        "typeinfo_object": "0x64d3018",
        "typeinfo_name": "0x976100",
        "typeinfo_name_string": (
            "ZN7rocksdb14OptionTypeInfo17AsCustomSharedPtrIKNS_14SliceTransformEEES0_iNS_22OptionVerificationTypeENS_15OptionTypeFlagsEEUlRKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESG_PvE_"),
    },
    "invoker": {
        "address": "0x60809e0",
        "fde": "0x60809e0..0x6080a71",
        "bytes": 145,
        "role": (
            "std::function _M_invoke for the AsCustomSharedPtr<const "
            "SliceTransform> lambda: Status (const ConfigOptions&, "
            "const std::string&, const std::string&, void*), returned "
            "through a hidden sret pointer in rdi. Reached only "
            "through the GOT slot 0x64edb70; it has no direct call site."),
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
                "id_string length == 2 and its first two bytes are 'id' "
                "(word 0x6469, site 0x6080a33) and name_string length == 0 "
                "(site 0x6080a3a)"),
            "effect": (
                "Release the shared_ptr at *(dest_slot): zero the "
                "16-byte slot, then call _M_release 0x5d350c0 (site "
                "0x6080a51) on the old control block when non-null (the "
                "packed use/weak fast path and the use-count decrement "
                "live inside _M_release itself, pinned by open PR "
                "#3674). Then write an empty Status (code 0, subcode 0, "
                "state null) to out and return out."),
        },
        "forward_path": {
            "condition": "otherwise",
            "call": {"site": "0x6080a10", "target": "0x61ca3d0",
                     "args": "(out, config_options, name_string, *(dest_slot))"},
            "effect": "Forward to the create-by-name host and return out.",
        },
    },
    "create_host": {
        "address": "0x61ca3d0",
        "fde": "0x61ca3d0..0x61cb3dc",
        "bytes": 4108,
        "role": (
            "Create-by-name host for the SliceTransform option: resolves "
            "the name through the registry translator and the "
            "SliceTransform registry find, creates the object through "
            "the found entry's factory, and installs it into the "
            "destination shared_ptr. Pinned here for the first time."),
        "args": {
            "out": "rdi (Status*)",
            "config_options": "rsi",
            "name_string": "rdx (std::string)",
            "dest_slot": "rcx (pointer to the 16-byte shared_ptr storage)",
        },
        "once_init": {
            "site": "0x61ca461",
            "detail": (
                "std::call_once over the once control at 0x6508928: the "
                "TLS slots 0x64ed818 (__once_callable) and 0x64ed820 "
                "(__once_call) are loaded with the registry initializer "
                "0x61ccfa0 and the stack argument, then pthread_once is "
                "called with __once_proxy (GLOB_DAT at 0x64ed828). On "
                "pthread_once failure the host throws a system error "
                "(site 0x61cb2e4)."),
        },
        "translator": {
            "address": "0x609e510",
            "site": "0x61ca53b",
            "by_contract_from": "open PR #3440",
            "args": (
                "(Status out at rsp+0x60, config_options, *dest_slot "
                "object, name_string, translated-name string at "
                "rsp+0xf0, once-arg at rsp+0xb0)"),
            "outputs": (
                "Writes a Status at rsp+0x60 and the translated name "
                "into the string at rsp+0xf0 (length at rsp+0xf8). The "
                "0x28-byte stack struct at rsp+0xc0 is initialised to "
                "{0, 0, 1.0f, 0, 0} before the call; its +0x08 field is "
                "read together with the translated-name length in the "
                "empty-name test, and the epilogue frees a linked list "
                "rooted at its +0x00 field (site 0x61ca7fd)."),
        },
        "outcomes": [
            {
                "condition": "translator Status code != 0",
                "site": "0x61ca998",
                "effect": "out = move(translator Status).",
            },
            {
                "condition": (
                    "translator Status code == 0 and (rsp+0xc8 | "
                    "rsp+0xf8) == 0 (translated name empty)"),
                "site": "0x61ca900",
                "effect": (
                    "Release *dest_slot (zero the 16-byte slot, release "
                    "the old control through the counted-release dance: "
                    "packed 0x100000001 fast path via the dispose helper "
                    "0x5d35070 at site 0x61ca957, lock-xadd path at sites "
                    "0x61cb0c1/0x61cb0cf, dispose at 0x61cb0b7, "
                    "vtable-slot dispose/destroy at 0x61cb0dd/0x61cb0fe) "
                    "and write an empty Status to out."),
            },
            {
                "condition": (
                    "translator Status code == 0 and translated name "
                    "non-empty"),
                "effect": (
                    "Call the registry find 0x61c9d70 (site 0x61ca580) "
                    "with (out std::function at rsp+0x110, "
                    "config_options+0x40, key = the translated-name "
                    "string at rsp+0xf0). If the found functor's manager "
                    "(rsp+0x120) is null, build an error Status code 3 "
                    "with message slices (\"Could not load "
                    "SliceTransform\", translated name) via the Status "
                    "builder 0x61cf670 (site 0x61cafbc). Otherwise invoke "
                    "the found entry's factory through its invoker "
                    "(indirect call *0x128(%rsp), site 0x61ca5fc) with "
                    "(functor at rsp+0x110, translated-name string at "
                    "rsp+0xf0, object out-slot at rsp+0xa0 pointing at "
                    "rsp+0x58, detail out-string at rsp+0x90 pointing "
                    "at rsp+0x130)."),
            },
        ],
        "create_results": [
            {
                "condition": (
                    "factory returns null (rax == 0) and the detail "
                    "string at rsp+0x130 is non-empty (length at "
                    "rsp+0x138 != 0)"),
                "site": "0x61cb028",
                "effect": (
                    "Error Status code 4 via 0x61cf670 (site 0x61cb05c) "
                    "with message slices (detail string, translated "
                    "name)."),
            },
            {
                "condition": (
                    "factory returns null (rax == 0) and the detail "
                    "string is empty"),
                "site": "0x61caa98",
                "effect": (
                    "Error Status code 4 via 0x61cf670 (site 0x61cabc8) "
                    "with message slices (\"Could not load "
                    "SliceTransform\", translated name)."),
            },
            {
                "condition": (
                    "factory returns non-null but the object slot at "
                    "rsp+0x58 is null"),
                "site": "0x61cac1c",
                "effect": (
                    "Error Status code 4 via 0x61cf670 (site 0x61cae1b) "
                    "with message slices (\"Cannot make a shared "
                    "SliceTransform from unguarded one \", translated "
                    "name)."),
            },
            {
                "condition": "factory returns non-null and the object slot is non-null",
                "site": "0x61ca688",
                "effect": (
                    "Install the created object into *dest_slot: "
                    "allocate a 0x18-byte control block via _Znwm (site "
                    "0x61ca696), load the packed counts 0x100000001 from "
                    "the global at 0x459b20, install {object, control} "
                    "into dest, set the control block's table to "
                    "0x64d7878+0x10 = 0x64d7888 (the _Sp_counted_ptr<"
                    "const SliceTransform*, _S_atomic> table, typeinfo "
                    "0x64d75c0, name at 0x97e600) and its packed counts "
                    "and object pointer, release the old dest control "
                    "through the same counted-release dance, and write "
                    "an empty Status to the intermediate at rsp+0x70."),
            },
        ],
        "status_normalization": {
            "input": "the intermediate Status at rsp+0x60 (after the install or error path)",
            "rules": [
                "code == 3 (NotSupported, per RocksDB's Status code table \u2014 inference) and config_options+1 != 0: reset the intermediate Status to empty; out = empty (site 0x61ca968).",
                "code == 0: call the second translator 0x609e2d0 (site 0x61ca9c9; by contract) with (rsp+0xa0, config_options, *dest_slot object, current object), then move the Status at rsp+0xa0 to rsp+0x60 and out.",
                "any other code: out = the intermediate Status unchanged.",
            ],
            "note": (
                "The config_options+1 byte's meaning and the 0x609e2d0 "
                "contract are open; only the branch structure is pinned."),
        },
        "epilogue": (
            "Move the rsp+0x60 Status into out (site 0x61ca7c4), free "
            "the linked list rooted at *(rsp+0xc0) (site 0x61ca7fd), "
            "memset and free the stack strings (sites 0x61ca877, "
            "0x61ca8ad, 0x61ca8cb), check the stack canary and return out."),
        "direct_callers": [
            {"site": "0x6080a10", "kind": "direct_call",
             "containing_fde": ["0x60809e0", "0x6080a71"],
             "note": "the invoker's forward path"},
            {"site": "0x6120761", "kind": "direct_call",
             "containing_fde": ["0x611fb10", "0x61213db"],
             "note": (
                 "a direct options-parser caller: calls the host with "
                 "(Status*, ConfigOptions* filled by 0x60bb890, name "
                 "string at +0x1a8 of the options struct, dest slot at "
                 "+0x1f8)")},
        ],
    },
    "registry_find": {
        "address": "0x61c9d70",
        "fde": "0x61c9d70..0x61ca265",
        "bytes": 2805,
        "role": (
            "Registry find for a named SliceTransform factory: locates "
            "the \"SliceTransform\" type node in the registry, scans "
            "its entries with the per-entry predicate (vtable slot "
            "0x10) against the requested key, and copies the matching "
            "entry's create functor (at entry+0x20) into out. Pinned "
            "here for the first time."),
        "args": {
            "out": "rdi (a 32-byte std::function: _Any_data at +0x00, manager at +0x10, invoker at +0x18)",
            "registry": "rsi (mutex at +0x98, bucket vector at +0x00/+0x08, parent registry at +0x60)",
            "key": "rdx (the translated-name string)",
        },
        "mutex": (
            "Locks the mutex at registry+0x98 (site 0x61c9dad) and "
            "holds it for the whole lookup; unlock sites 0x61c9f14, "
            "0x61ca14c, 0x61ca1c2, 0x61ca1cc. Lock failure throws a "
            "system error (sites 0x61ca1e6, 0x61ca189, 0x61ca1a3). Each "
            "bucket is additionally locked through its own lock at "
            "bucket-0x10 (site 0x61c9de0) while it is scanned."),
        "type_node_match": (
            "The find builds the literal \"SliceTransform\" (14 bytes, "
            "movabs sites 0x61c9ded/0x61c9e00, SSO string at rsp+0x50) "
            "and matches registry nodes against it: a node matches "
            "when its name length (node+0x10) is 0xe and the first 8 "
            "bytes then the next 6 bytes of its name data equal "
            "\"SliceTransform\" (sites 0x61c9e4d..0x61c9e69)."),
        "linear_path": (
            "When the bucket's entry count (bucket+0x40) is <= 0x14, "
            "walk the list at bucket+0x38 node by node (next at "
            "node+0x00) until a type-node match or the list ends."),
        "hash_path": (
            "When the count is > 0x14, hash the literal with "
            "_Hash_bytes(\"SliceTransform\", 14, 0xc70f6907) (site "
            "0x61c9fe5), take bucket = hash % table size (table at "
            "bucket+0x28, size at bucket+0x30), and walk that bucket's "
            "chain: a node matches when its stored hash (node+0x40) "
            "mod table size equals the bucket, its stored hash equals "
            "the computed hash, its name length is 0xe, and memcmp of "
            "its name data against \"SliceTransform\" is 0 (site "
            "0x61ca08a)."),
        "entry_scan": (
            "On a type-node match, scan its entries [node+0x28, "
            "node+0x30): for each entry call its vtable slot 0x10 "
            "with (entry, key) (site 0x61c9e96); on true, copy the "
            "entry's create functor at entry+0x20 (16 bytes: manager "
            "then invoker) into out: clone through the manager with "
            "op 2 (site 0x61c9ed5), copy the 16 bytes (site 0x61c9ed7), "
            "then destroy the temporary with op 3 (sites 0x61ca145, "
            "0x61ca1bd, 0x61ca22a, 0x61ca241)."),
        "parent_recursion": (
            "If no bucket matches and the parent registry pointer at "
            "registry+0x60 is non-null, recurse into the parent "
            "(self-call site 0x61c9f32). If the parent is null, out is "
            "zeroed (sites 0x61c9fb2, 0x61ca0d7, 0x61ca0f8) and the find "
            "reports no match."),
        "callers": [
            {"site": "0x61c9f32", "kind": "direct_call",
             "containing_fde": ["0x61c9d70", "0x61ca265"],
             "note": "self-recursion into the parent registry"},
            {"site": "0x61ca580", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"],
             "note": "the create host's lookup"},
        ],
    },
    "default_init": {
        "address": "0x61ccfa0",
        "fde": "0x61ccfa0..0x61cd01b",
        "bytes": 123,
        "role": (
            "The pthread_once registry initializer the host passes by "
            "lea (site 0x61ca450). Builds an empty std::string at "
            "rsp+0x10, calls the registry-mutex getter 0x61f8b60 (site "
            "0x61ccfd0), then the register helper 0x61cbd50 (site "
            "0x61ccfd8) with the dereferenced pointer. It has no "
            "direct call site: it is reached only through "
            "__once_proxy. The registry structure and the 0x61cbd50 "
            "internals are open; only the call shape is pinned."),
        "by_contract": ["0x61f8b60", "0x61cbd50"],
    },
    "installers": [
        {
            "site": "0x608d894",
            "kind": "direct_call",
            "containing_fde": ["0x6089b50", "0x6091e5c"],
            "args": {"out": "rbp-0x6310 (a stack record)", "offset": 64,
                     "verification": 2, "flags": 4352},
            "name": "prefix_extractor",
            "name_literal": "0x445493",
            "note": (
                "The containing function (0x6089b50..0x6091e5c) is the "
                "options-table construction function: it installs many "
                "OptionTypeInfo records. Right after this builder call "
                "it assigns the string \"prefix_extractor\" (literal at "
                "0x445493) via 0x607d9f0 and inserts the record via "
                "0x5e32b10. It is NOT pinned here; only this call site, "
                "its arguments and the following name assignment are."),
        },
        {
            "site": "0x6090205",
            "kind": "direct_call",
            "containing_fde": ["0x6089b50", "0x6091e5c"],
            "args": {"out": "rbp-0x6d00 (a stack record)", "offset": 192,
                     "verification": 2, "flags": 0},
            "name": "memtable_insert_with_hint_prefix_extractor",
            "name_literal": "0x959c80",
            "note": (
                "Second install site in the same options-table "
                "construction function: installs the same record shape "
                "with offset 0xc0 and flags 0. Right after this builder "
                "call it assigns the string "
                "\"memtable_insert_with_hint_prefix_extractor\" (literal "
                "at 0x959c80) via 0x607d9f0 and inserts the record via "
                "0x5e32b10. Same scoping note as the first site."),
        },
    ],
    "sibling_note": {
        "claim": (
            "The SliceTransform builder shares the record field map "
            "with the Statistics builder 0x6071520 (open PR #3685) and "
            "the SystemClock builder 0x5fd0180 (open PR #3715) \u2014 "
            "same 0xb8-byte record, same type 22, same hook-pair "
            "layout \u2014 and shares the SystemClock builder's "
            "copy-helper install shape (this builder's copy-helper "
            "site is 0x6083b76). It differs from the SystemClock "
            "builder in cleanup: it destroys each temporary member "
            "explicitly with manager op 3 instead of calling the "
            "record destructor on the normal path."),
        "census_correction": (
            "The GOT-resolved hooks prove SliceTransform (const), not "
            "Statistics, FileSystem or SystemClock: the manager's "
            "kind-0 typeinfo name at 0x976100 is the "
            "AsCustomSharedPtr<const SliceTransform> lambda, the "
            "invoker calls the SliceTransform create host 0x61ca3d0, "
            "whose registry find looks up the \"SliceTransform\" type "
            "node, and whose install wraps the created object in a "
            "_Sp_counted_ptr<const SliceTransform*, _S_atomic> control "
            "block (typeinfo name at 0x97e600)."),
        "copies_in_binary": 1,
    },
    "control_table": {
        "stored_base": "0x64d7888 (0x64d7878+0x10, the value the host stores into the new control block)",
        "typeinfo_cell": "0x64d7880 (stored base - 0x08) -> 0x64d75c0",
        "typeinfo_name": "0x97e600",
        "typeinfo_name_string": (
            "St15_Sp_counted_ptrIPKN7rocksdb14SliceTransformELN9__gnu_cxx12_Lock_policyE2EE"),
        "slots": {
            "+0x00": "0x61c64d0 (5 bytes: endbr64; ret \u2014 a no-op stub)",
            "+0x08": "0x61c6580",
            "+0x10": "0x61c6530",
            "+0x18": "0x61c6590",
        },
        "note": (
            "The counted-release helper _M_release 0x5d350c0 (pinned by "
            "open PR #3674) calls vtable slots 0x10 and 0x18 "
            "(dispose/destroy); the +0x00/+0x08 slot attributions are "
            "open. The +0x00 no-op stub is pinned as read."),
    },
    "literals": [
        {"value": 22, "where": "builder 0x6083b4a", "role": "type field"},
        {"value": "0x607d190", "where": "GOT 0x64eda68",
         "role": "manager hook"},
        {"value": "0x60809e0", "where": "GOT 0x64edb70",
         "role": "invoker hook"},
        {"value": "0x64d3018", "where": "manager 0x607d1b0",
         "role": "lambda typeinfo object (kind 0)"},
        {"value": "0x976100", "where": "reloc at 0x64d3020",
         "role": "lambda typeinfo name string"},
        {"value": "0x6469", "where": "invoker 0x6080a33",
         "role": "\"id\" word in the fast-path check"},
        {"value": "0x64ed290", "where": "host 0x61ca6f0 / 0x61ca932",
         "role": "atomicity selector byte for the counted use-count bump"},
        {"value": "0x100000001", "where": "global at 0x459b20",
         "role": "packed use/weak counts for the new control block"},
        {"value": "0x64d7888", "where": "host 0x61ca6bd",
         "role": "control-block table (0x64d7878+0x10)"},
        {"value": "0x97e600", "where": "reloc at 0x64d75c8",
         "role": "control-block typeinfo name string"},
        {"value": "0xc70f6907", "where": "find 0x61c9fd8",
         "role": "seed for _Hash_bytes over \"SliceTransform\""},
        {"value": "SliceTransform", "where": "find 0x61c9ded / 0x61c9e00",
         "role": "type-node key literal built by the find"},
        {"value": "SliceTransform", "where": "literal 0x44b556",
         "role": "name appended in the host's \"Could not load \" errors"},
        {"value": "Could not load ", "where": "host 0x61caafe / 0x61caeec (movabs)",
         "role": "first error-message part (15 chars)"},
        {"value": "Cannot make a shared ", "where": "host 0x61cac7e (movdqa from 0x456270) + 0x61cac86 (movabs)",
         "role": "first error-message part (21 chars)"},
        {"value": " from unguarded one ", "where": "literal 0x432138",
         "role": "second error-message part (20 chars)"},
        {"value": "prefix_extractor", "where": "literal 0x445493",
         "role": "option name installed at builder site 0x608d894"},
        {"value": "memtable_insert_with_hint_prefix_extractor",
         "where": "literal 0x959c80",
         "role": "option name installed at builder site 0x6090205"},
    ],
    "unknowns": [
        "The OptionVerificationType / OptionTypeFlags enum spellings for the raw values verification 2 / flags 0x1100 and 0 used by the two installing call sites; only the raw values are pinned.",
        "The semantic names of the invoker's two string args beyond their observed roles (rcx is the string compared to \"id\", r8 is the name string the create host dispatches on); the lambda's mangled type only fixes their C++ types.",
        "The exact vtable-base/header attribution of the SliceTransform control table: the typeinfo-bearing cell sits at the stored base minus 0x08 in this binary (verified on five vtables in the SystemClock packet), so slot numbers here are relative to the stored base as the code reads them; the +0x00/+0x08 slot roles (0x61c64d0 no-op stub, 0x61c6580) are open.",
        "The registry structure (bucket vector, bucket locks, entry ranges, parent chain) beyond the pinned offsets, and the roles of the 0x61f8b60 / 0x61cbd50 helpers the initializer calls.",
        "The translator 0x609e510's stack struct layout beyond the pinned out-params (translated-name string at rsp+0xf0, the rsp+0xc0 scratch struct with the 1.0f field at +0x10) and the second translator 0x609e2d0's contract.",
        "The config_options+1 byte's meaning in the Status normalization branch.",
        "The create functor's exact signature: it returns non-null on success and writes the object through the rsp+0xa0 indirection to rsp+0x58, and may leave an error-detail string at rsp+0x130; which of its three post-_Any_data args is the options struct vs the out-params is open.",
        "Whether the \"id\" fast path means \"reset to the default object\" or \"release and return empty\" in the caller's terms; the binary only shows the release + empty Status.",
        "The host's landing-pad stubs (FDE 0x61cb334..0x61cb3dc region) are shared rethrow blocks, not decoded; the LSDA call-site tables are not decoded.",
        "The two install sites live in one options-table construction function (FDE 0x6089b50..0x6091e5c) whose other records are not pinned; the name-to-record association at the second site follows the same positional pattern as the first (name assigned immediately after the builder call, before the table insert).",
    ],
}


def main():
    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, BIN))
    fdes = load_fdes()
    records = dict(RECORDS)
    census_json = {}
    for t in census_mod.TARGETS:
        census_json[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    records["census"] = census_json
    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        for v in calls[t]:
            fe = containing_fde(fdes, v)
            assert fe is not None, "no FDE for site %#x" % v
            rows.append({"site": hex(v), "kind": "direct_call",
                         "containing_fde": [hex(fe[0]), hex(fe[1])]})
        for v in tails[t]:
            fe = containing_fde(fdes, v)
            assert fe is not None, "no FDE for site %#x" % v
            rows.append({"site": hex(v), "kind": "tail_jump",
                         "containing_fde": [hex(fe[0]), hex(fe[1])]})
        callers[hex(t)] = rows
    records["callers"] = callers
    records["packet_internal_sites"] = {
        "0x5d350c0": [
            {"site": "0x6080a51", "kind": "direct_call",
             "containing_fde": ["0x60809e0", "0x6080a71"]}],
        "0x5d35070": [
            {"site": "0x61ca957", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]},
            {"site": "0x61cb0b7", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]}],
        "0x5d3f950": [
            {"site": "0x6083c55", "kind": "direct_call",
             "containing_fde": ["0x6083a90", "0x6083c83"]}],
        "0x609e510": [
            {"site": "0x61ca53b", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]}],
        "0x609e2d0": [
            {"site": "0x61ca9c9", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]}],
        "0x61cf670": [
            {"site": "0x61cabc8", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]},
            {"site": "0x61cae1b", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]},
            {"site": "0x61cafbc", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]},
            {"site": "0x61cb05c", "kind": "direct_call",
             "containing_fde": ["0x61ca3d0", "0x61cb3dc"]}],
        "0x61f8b60": [
            {"site": "0x61ccfd0", "kind": "direct_call",
             "containing_fde": ["0x61ccfa0", "0x61cd01b"]}],
        "0x61cbd50": [
            {"site": "0x61ccfd8", "kind": "direct_call",
             "containing_fde": ["0x61ccfa0", "0x61cd01b"]}],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=False)
        fh.write("\n")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fe = row["containing_fde"]
                fh.write("%s\t%s\t%s\t%s..%s\n" % (
                    hex(t), row["site"], row["kind"], fe[0], fe[1]))
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write(
            "Relocations for RE-001-optiontypeinfo-slicetransform-115\n"
            "Binary work/hl-node-115.bin, SHA-256\n"
            "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301\n"
            "(provenance/artifacts.json, artifacts/node/115/hl-node).\n"
            "Read with objdump -R; type 8 is R_X86_64_RELATIVE, type 1\n"
            "is R_X86_64_64. The .data.rel.ro cells are zero in the\n"
            "captured file: the values below are the relocation addends\n"
            "the loader applies, as objdump -R reports them.\n\n"
            "Hook GOT slots (the builder's two create hooks):\n"
            "  0x64eda68 R_X86_64_RELATIVE -> 0x607d190 (manager)\n"
            "  0x64edb70 R_X86_64_RELATIVE -> 0x60809e0 (invoker)\n\n"
            "Lambda typeinfo (manager op 0, lea at 0x607d1b0):\n"
            "  0x64d3018 R_X86_64_64 -> "
            "_ZTVN10__cxxabiv117__class_type_infoE + 0x10\n"
            "  0x64d3020 R_X86_64_RELATIVE -> 0x976100 (typeinfo name:\n"
            "    the AsCustomSharedPtr<const SliceTransform> lambda)\n\n"
            "Control-block table (host loads 0x64d7878, stores +0x10):\n"
            "  0x64d7880 R_X86_64_RELATIVE -> 0x64d75c0 (typeinfo cell,\n"
            "    stored base - 0x08)\n"
            "  0x64d75c0 R_X86_64_64 -> "
            "_ZTVN10__cxxabiv120__si_class_type_infoE + 0x10\n"
            "  0x64d75c8 R_X86_64_RELATIVE -> 0x97e600 (typeinfo name:\n"
            "    _Sp_counted_ptr<const SliceTransform*, _S_atomic>)\n"
            "  0x64d7888 R_X86_64_RELATIVE -> 0x61c64d0 (table slot +0x00)\n"
            "  0x64d7890 R_X86_64_RELATIVE -> 0x61c6580 (table slot +0x08)\n"
            "  0x64d7898 R_X86_64_RELATIVE -> 0x61c6530 (table slot +0x10)\n"
            "  0x64d78a0 R_X86_64_RELATIVE -> 0x61c6590 (table slot +0x18)\n\n"
            "Host once / TLS machinery:\n"
            "  0x64ed818 R_X86_64_TPOFF64 -> _ZSt15__once_callable\n"
            "  0x64ed820 R_X86_64_TPOFF64 -> _ZSt11__once_call\n"
            "  0x64ed828 R_X86_64_GLOB_DAT -> __once_proxy\n"
            "  0x64ed290 R_X86_64_GLOB_DAT -> "
            "__libc_single_threaded (atomicity selector)\n\n"
            "No R_X86_64_RELATIVE entry points at a packet window "
            "(builder 0x6083a90..0x6083c83, manager 0x607d190..0x607d1bd,\n"
            "invoker 0x60809e0..0x6080a71, host 0x61ca3d0..0x61cb3dc,\n"
            "find 0x61c9d70..0x61ca265, init 0x61ccfa0..0x61cd01b); the\n"
            "only RELATIVE slots naming a window are the two hook GOT\n"
            "slots above. The qword hits for the manager/invoker in the\n"
            "census are the .rela.dyn addend fields of those same two\n"
            "slots (file offsets 0x15e428 / 0x15e740).\n")
    print("wrote records.json, callers.tsv, relocations.txt")
    print("copy-helper call sites:", len(calls[0x5E332C0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
