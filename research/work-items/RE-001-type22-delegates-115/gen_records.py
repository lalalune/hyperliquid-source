#!/usr/bin/env python3
"""Build records.json (semantic records only) for RE-001 type22-delegates-115.

No per-instruction mnemonic lists: instruction-level detail lives only in
the verbatim objdump excerpts. Re-run to regenerate; verify.py diffs it.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
OUT = Path(__file__).resolve().parent
ARTIFACT = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

RECORDS = {
    "task": "RE-001",
    "node": 115,
    "artifact_sha256": ARTIFACT,
    "artifact": "artifacts/node/115/hl-node",
    "question": "What do the type-22 apply delegate 0x609a740 and the "
                "serializer helper 0x60971c0 do in node #115?",
    "resolves": ["#4320 open unknowns: 0x609a740 internals, 0x60971c0 internals"],
    "functions": [
        {"address": "0x609a740", "fde": "0x609a740..0x609b6f3",
         "role": "type-22 apply delegate",
         "signature": "(Status* out, ConfigOptions* config, Configurable* object, "
                      "OptionTypeInfo* record, std::string* name, "
                      "std::string* remaining_key, std::string* value, "
                      "options-base* out_slot)",
         "sole_caller": "0x609b80f (inside apply-created dispatch 0x609b700, type==22 arm)"},
        {"address": "0x60971c0", "fde": "0x60971c0..0x609755b",
         "role": "serializer helper: brace-wrap a nested Configurable's options",
         "signature": "(std::string* out, Configurable* object, "
                      "ConfigOptions* config, std::string* empty)",
         "callers": 8},
        {"address": "0x609de80", "fde": "0x609de80..0x609e29e",
         "role": "vtable slot 12: shared nested-Configurable serializer",
         "signature": "(std::string* out, Configurable* object, "
                      "ConfigOptions* config, std::string* rcx_arg)",
         "callers_direct": 3, "callers_vtable": "slot 12 of every Configurable vtable"},
        {"address": "0x5d32a30", "fde": "0x5d32a30..0x5d32a51",
         "role": "vtable slot 15: GetId (shared) -> out = object->Name()",
         "signature": "(std::string* out, Configurable* object)"},
        {"address": "0x60986b0", "fde": "0x60986b0..0x6098a9c",
         "role": "vtable slot 10: ConfigureOption core (shared)",
         "signature": "(Status* out, Configurable* object, "
                      "ConfigOptions* config, OptionTypeInfo* record, "
                      "std::string* remaining_key, std::string* value)"},
        {"address": "0x61d1390", "fde": "0x61d1390..0x61d13db",
         "role": "ends_with(haystack, suffix) -> bool",
         "signature": "(const std::string* haystack, const std::string* suffix)"},
        {"address": "0x61d13e0", "fde": "0x61d13e0..0x61d1437",
         "role": "string_compare(a, b) -> int (memcmp over min length, then length difference)",
         "signature": "(const std::string* a, const std::string* b)"},
    ],
    "field_resolution": {
        "record_offset_field": "+0x00 (i64)",
        "record_flags_field": "+0xb0 (i32)",
        "deref_gate": "flags & (0x200 | 0x400 | 0x800) -> deref field once; else use field address",
        "null_base": "options-base null -> resolved target is null (skip offset math)",
        "caller_chain": "arm 0x60bf212 (in #4320) -> forwarder 0x609ba30 -> "
                        "create-by-name 0x609b8a0 -> scan 0x6096f40 -> "
                        "apply-created 0x609b700 (type==22) -> 0x609a740",
    },
    "config_options_copy": {
        "size_bytes": 80,
        "fields": [
            {"offset": "+0x00", "type": "u32", "note": "low bytes hold bool flags"},
            {"offset": "+0x04", "type": "u8", "note": "bool; zeroed on flags-0x100 path, tested on flags-clear path"},
            {"offset": "+0x08", "type": "std::string", "note": "separator between id and nested options in slot-12 output"},
            {"offset": "+0x28", "type": "u32", "note": "gate in slot 12: == 1 changes emission"},
            {"offset": "+0x2c", "type": "u8", "note": "sanity_level (per #4146)"},
            {"offset": "+0x30", "type": "u64", "note": "file_readahead_size (per #4146)"},
            {"offset": "+0x38", "type": "bytes[16]", "note": "opaque"},
            {"offset": "+0x48", "type": "shared_ptr", "note": "refcount++ on copy"},
        ],
        "copy_function": "0x60b9d70 (shipped in #4320)",
    },
    "delegate_branches": [
        {"condition": "record flags bit 0x100 set",
         "effect": "zero the ConfigOptions copy's +0x04 byte, then take the nested-key path"},
        {"condition": "record flags bit 0x100 clear and ConfigOptions+0x04 == 0",
         "effect": "same nested-key path (without zeroing)"},
        {"condition": "record flags bit 0x100 clear and ConfigOptions+0x04 != 0 and object null",
         "effect": "value empty -> Status OK; value non-empty -> kInvalidArgument "
                   "'Option not changeable: <name>'"},
        {"condition": "remaining_key size == name size and bytes equal, or remaining_key == 'id'",
         "effect": "call object vtable slot 10 (ConfigureOption) with "
                   "(Status*, object, config-copy, record, remaining_key, value)"},
        {"condition": "name ends with '.id'",
         "effect": "call object vtable slot 15 (GetId); value must equal that id, "
                   "else kInvalidArgument 'Option not changeable: <name>'; "
                   "on match, configure via helpers 0x609a410 / 0x6097150"},
        {"condition": "value empty on the terminal path",
         "effect": "Status code 0, empty message (store at 0x609aacf)"},
        {"condition": "name lacks '.id', value non-empty, target non-null",
         "effect": "GetId into the value string, append '.', compare the "
                   "remaining key against '<id>.' via 0x61d13e0; equal -> "
                   "slot-10 ConfigureOption; not equal -> split value on '=': "
                   "found -> 0x6099e70, not found -> 0x609ba30"},
    ],
    "serializer_rules": [
        {"rule": "empty slot-12 output -> verbatim move into *out",
         "site": "0x60971c0, find('=') skipped when empty"},
        {"rule": "slot-12 output with no '=' -> verbatim move into *out"},
        {"rule": "slot-12 output containing '=' -> out = '{' + output + '}'",
         "brace_literals": ["0x44ecd8 = '{'", "0x432097 = '}'"]},
        {"rule": "slot 12 emits [rcx-arg string] + 'id' + '=' + id + "
                  "[ConfigOptions+0x08 string] + [0x60985e0 nested options]",
         "gate": "only when ConfigOptions+0x28 != 1 AND id non-empty AND the "
                 "0x60985e0 output is non-empty; otherwise out = id "
                 "(empty when id is empty, the bare id when +0x28 == 1)"},
        {"rule": "nested options come from 0x60985e0 (slot-12 internal, FDE 0x60985e0..0x609865e)",
         "note": "0x60985e0 internals not decoded here; cited by address"},
    ],
    "vtable_convention": {
        "observation": "Configurable vtable callees take (out/status-string, object, ...) "
                       "with the object in RSI, not RDI. Verified in GetId 0x5d32a30: "
                       "it loads the vtable from (%rsi), calls slot 14 with rdi=rsi "
                       "(object), and writes the returned name into *rdi (string).",
        "slots_pinned": {
            "10": "0x60986b0 ConfigureOption core (BBT wrapper 0x60d7d20 calls it)",
            "12": "0x609de80 nested serializer (shared in both vtables)",
            "13": "0x609d980 GetOptionName (shipped in #4320)",
            "15": "0x5d32a30 GetId (shared in both vtables)",
        },
        "open": "why the object is second is not established; recorded as an open unknown",
    },
    "literals": [
        {"address": "0x44ecd8", "bytes": "{", "len": 1},
        {"address": "0x432097", "bytes": "}", "len": 1},
        {"address": "0x4341c2", "bytes": "Option not changeable: ", "len": 23},
        {"address": "0x43821e", "bytes": ".", "len": 1},
        {"address": "0x445245", "bytes": "=", "len": 1},
        {"address": "0x4376fd", "bytes": "", "len": 0},
        {"address": "0x43d5c7", "bytes": ";", "len": 1},
        {"address": "0x43fb8a", "bytes": "Could not find configurable: ", "len": 29},
        {"address": "0x44e056", "bytes": "Could not find option", "len": 21},
        {"address": "0x4373cf", "bytes": "Cannot serialize option: ", "len": 25},
        {"address": "0x4477ed", "bytes": "Error parsing:", "len": 14},
        {"address": "0x43e863", "bytes": "Could not find option: ", "len": 23},
        {"address": "0x441b15", "bytes": "id", "len": 2},
    ],
    "status_codes": [
        {"code": 0, "name": "kOk", "site": "0x609aacf"},
        {"code": 1, "name": "kNotFound", "site": "0x609b700 / 0x609b8a0 error paths (cited)"},
        {"code": 4, "name": "kInvalidArgument", "site": "0x609ae22 and 0x609b217 via Status ctor 0x61cf670"},
    ],
    "open_unknowns": [
        "0x609a410 internals (id-configure helper; 3 callers incl. 0x609b190)",
        "0x6097150 / 0x6097110 internals beyond the thin wrapper (slot-9 entry)",
        "0x60985e0 internals (slot-12 nested-options emitter)",
        "ConfigOptions+0x00/+0x04/+0x08/+0x28 C++ names and defaults",
        ".bss string at 0x6508980 identity (serializer null-object string; 10 lea sites enumerated in bss-string-lea.tsv)",
        "record+0xb8 name-string inference (from #4320)",
        "why the vtable callees take (out, object) with the object in RSI",
        "type-21/22 entries in maps beyond DBOptions/CFOptions (from #4320)",
    ],
}


def main() -> int:
    digest = hashlib.sha256(BIN.read_bytes()).hexdigest()
    assert digest == ARTIFACT, f"artifact digest mismatch: {digest}"
    (OUT / "records.json").write_text(json.dumps(RECORDS, indent=2) + "\n")
    print("records.json written; artifact digest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
