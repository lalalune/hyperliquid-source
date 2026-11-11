#!/usr/bin/env python3
"""Generate the semantic records for RE-001 parse-then-apply-wrapper-115.

Semantic records only: no per-instruction mnemonic/operand lists.
Instruction-level detail lives only in the raw disassembly excerpts.

Run from the repo root:
    python3 research/work-items/RE-001-parse-then-apply-wrapper-115/gen_records.py
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
ARTIFACT = "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    assert sha256_file(BIN).startswith(DIGEST), "node #115 binary digest mismatch"
    records = {
        "task": "RE-001",
        "node": 115,
        "artifact": ARTIFACT,
        "artifact_sha256": DIGEST,
        "work_item": "parse-then-apply wrapper 0x60c1bb0",
        "resolves": "#4349 open unknown: the map-parse internal call site 0x60c1c2e",
        "wrapper": {
            "address": "0x60c1bb0",
            "fde": "0x60c1bb0..0x60c1cc5",
            "signature": "(Status* out, void* options_base, const std::string& input, const std::unordered_map<std::string, OptionTypeInfo>* type_info, void* arg5, std::unordered_map<std::string, std::string>* overflow_or_null)",
            "returns": "out (Status*)",
            "steps": [
                {"step": 1, "what": "Build a stack unordered_map<string,string> at 0x10(%rsp): buckets = &single_bucket at 0x40(%rsp), bucket_count 1, before_begin null, element_count 0, max_load_factor 1.0f, next_resize 0, single_bucket null (56-byte object). A stack Status temp lives at (%rsp)."},
                {"step": 2, "what": "Parse call at 0x60c1c2e: 0x60c1190(stack Status, input, &stack map) with arg4/arg5/arg6 still live in rcx/r8/r9 (the parser ignores them). This is the call site #4349 left open: it is the wrapper's own parse step, not a separate routine."},
                {"step": 3, "what": "Parse failure (stack Status code != 0 at 0x60c1c33): copy the 16-byte Status into *out (code bytes 0-1 and 2-5, message pointer at +0x08; message ownership transfers to out), destroy the stack map via 0x5d36110 at 0x60c1c53, return out. The apply stage is never reached."},
                {"step": 4, "what": "Parse success (code == 0): apply call at 0x60c1c92: 0x60c18b0(out, options_base, &stack map, type_info, arg5, overflow) - the apply loop writes its Status directly into the caller's out."},
                {"step": 5, "what": "After apply: free the parse Status message at 0x60c1c97 if non-null (delete[] on the stack Status message pointer at 0x8(%rsp)), destroy the stack map via 0x5d36110 at 0x60c1c53, return out. The temporary map never escapes: it is destroyed on both paths."},
            ],
            "arg_map": [
                {"arg": "rdi -> rbx", "role": "out Status* (returned)"},
                {"arg": "rsi -> r12", "role": "options_base: forwarded to the apply loop as its rsi, then to the per-entry apply as its rdx (field = options_base + record->offset)"},
                {"arg": "rdx -> parser rsi", "role": "input string to parse (const std::string&)"},
                {"arg": "rcx -> r13", "role": "type_info map: forwarded to the apply loop as its rcx, then to the lookup 0x60ba0b0 as its rsi"},
                {"arg": "r8 -> r14", "role": "arg5: forwarded opaquely to the apply loop as its r8, then as r9 to every per-entry apply call; the per-entry apply faults when it is null (see per-entry rule below); C++ identity open"},
                {"arg": "r9 -> r15", "role": "overflow map (nullable): forwarded to the apply loop as its r9; unknown keys divert into it when non-null, error when null (see apply-loop rule below)"},
            ],
        },
        "map_parser_cited": {
            "address": "0x60c1190",
            "fde": "0x60c1190..0x60c1887",
            "note": "Pinned by #4320/#4349; re-shipped byte-identical here. Signature (Status*, input, map*); rcx/r8/r9 ignored. Braced '{k=v;k=v}' input is unwrapped (first byte '{' 0x7b, last '}'), then segments split on ';' with find_first_of; each segment needs '='. Three kInvalidArgument (code 4) outcomes: no '=' -> 'Mismatched key value pair, '=' expected' (0x969140, 39 bytes); special char in key -> 'Unexpected char in key' (0x44ff0e, 22 bytes); empty key -> 'Empty key found' (0x4362e1, 15 bytes).",
        },
        "apply_loop_cited": {
            "address": "0x60c18b0",
            "fde": "0x60c18b0..0x60c1b7c",
            "note": "Pinned by #4237; whole-function excerpt re-generated here for the overflow/arg5 rules. Signature (Status* out, void* options_base, unordered_map<string,string>* parsed, type_info map, void* arg5, unordered_map<string,string>* overflow_or_null). Iterates the parsed map's nodes (next +0x00, key string +0x08/+0x10, value string +0x28/+0x30, hash +0x48); per node, lookup 0x60ba0b0(key, type_info) then per-entry apply 0x60bedc0.",
            "rules": [
                {"rule": "known key", "what": "lookup hits -> per-entry apply 0x60bedc0(Status temp, record, options_base, name temp, value string, arg5); the temp Status is copied into out on failure."},
                {"rule": "unknown key, overflow non-null", "what": "at 0x60c19f0: 0x60c0e90(overflow, &key) returns the value-string slot (operator[], creates the entry when missing), then _M_assign(slot, node value string) at 0x60c1a0d - the unknown pair is diverted into the overflow map and the loop continues with no error."},
                {"rule": "unknown key, overflow null, options_base byte +0x00 != 0", "what": "at 0x60c1ac8: cmpb $0x0,(options_base); nonzero -> silent skip, loop continues (0x60c1a9d)."},
                {"rule": "unknown key, overflow null, options_base byte +0x00 == 0", "what": "at 0x60c1ace: kNotFound (code 1) Status 'Unrecognized option' + key (literal 0x4497a0, 19 bytes) via 0x61cf670 at 0x60c1b0e; the error is copied into out and the loop stops."},
            ],
        },
        "overflow_insert_cited": {
            "address": "0x60c0e90",
            "fde": "0x60c0e90..0x60c112f",
            "note": "unordered_map<string,string>::operator[]: _Hash_bytes(key, size, seed 0xc70f6907) at 0x60c0e96, bucket = hash % bucket_count, walks the bucket chain comparing hash at node+0x48 and key bytes via memcmp, creates a 0x50-byte node when missing, returns &value string (node+0x28). Two direct callers: 0x60c1460 (inside the parser, inserting parsed pairs) and 0x60c1a01 (inside the apply loop, the overflow divert).",
        },
        "per_entry_arg5_rule_cited": {
            "address": "0x60bedc0",
            "fde": "0x60bedc0..0x60bf5bc",
            "note": "Pinned by #4311/#4320/#4328. Its r9 is the wrapper's arg5 (via the apply loop's r8). It is only null-tested: on the value-parse path, r9 null -> kNotFound (code 1) 'Could not find option' (literal 0x44e056) via 0x61cf670 at 0x60beff1 (0x60befb4 block, reached from 0x60bee32 and 0x60befab). No store through r9 exists in the function. The concrete arg5 values at the three wrapper call sites are a stack-string address (caller A), a 32-bit tag value (caller B), and a stack-passed pointer-sized value (caller C); the C++ identity of arg5 is left open.",
        },
        "callers": [
            {"site": "0x5e317f1", "function": "0x5e317a0..0x5e3190a", "note": "No direct E8 caller (vtable-called). Args: out = own rdi, options_base = own rdx, input = own r8, type_info = static map 0x6501d20, arg5 = &empty stack string at 0x30(%rsp), overflow = null. After the call it builds a kOk/err Status via 0x61cf670 with the empty location string 0x4376fd (0x5e31833)."},
            {"site": "0x5e344d6", "function": "0x5e34160..0x5e347c1", "note": "Sole caller 0x5e4382c (in 0x5e41fa0). Args: out = own rdi (rbx), options_base = stack options struct at 0x50(%rsp) (r15), input = stack string at 0x30(%rsp) built from the caller's string with its first 4 bytes stripped (size-4 at 0x5e34486, first byte copied at 0x5e344ae), type_info = static map 0x6501ce0, arg5 = rbp = first 4 bytes of the input string as an int32 (compared against magic 0x3b9ac9ff at 0x5e3422a), overflow = null."},
            {"site": "0x60c20d2", "function": "0x60c1d50..0x60c26d5", "note": "Prefix-match forwarder with 5 callers (0x5d3fd98, 0x5e30b66, 0x607e611, 0x608340c, 0x60834ec). Forwards its own (options_base, input, type_info, arg5) to the wrapper and passes a fresh stack map at 0x60(%rsp) (buckets = &0x90(%rsp), count 1, 1.0f) as the overflow map; out is a stack Status at 0x50(%rsp). Walks candidates with a memcmp name check at 0x60c2056 before the call."},
        ],
        "static_maps": [
            {"address": "0x6501ce0", "role": "static OptionTypeInfo map passed as caller B arg4; 2 lea sites (0x5e344c9, 0x5e3f4ac); built by the static initializer 0x5e20620..0x5e20d40; owning class open"},
            {"address": "0x6501d20", "role": "static OptionTypeInfo map passed as caller A arg4; 4 lea sites (0x5e316bf, 0x5e317a9, 0x5e3205d, 0x5e3ed02); also passed to the lookup helper 0x60bfcb0 at 0x5e316c6; built by the static initializer 0x5e20620..0x5e20d40; owning class open"},
        ],
        "literals": [
            {"address": "0x969140", "bytes": "Mismatched key value pair, '=' expected", "role": "parser kInvalidArgument, no '='"},
            {"address": "0x44ff0e", "bytes": "Unexpected char in key", "role": "parser kInvalidArgument, special char in key"},
            {"address": "0x4362e1", "bytes": "Empty key found", "role": "parser kInvalidArgument, empty key"},
            {"address": "0x4497a0", "bytes": "Unrecognized option", "role": "apply loop kNotFound, unknown key with null overflow and options_base byte +0x00 == 0"},
            {"address": "0x44e056", "bytes": "Could not find option", "role": "per-entry apply kNotFound, null arg5 on the value-parse path"},
            {"address": "0x4376fd", "bytes": "", "role": "empty location string used verbatim by the parser's second message slice and by caller A"},
        ],
        "open_unknowns": [
            "The C++ identity of wrapper arg5 (forwarded opaquely to the apply loop and then as r9 to the per-entry apply; only null-tested there).",
            "The owning C++ classes of the static maps 0x6501ce0 and 0x6501d20 (which option structs' OptionTypeInfo maps they are).",
            "The C++ names of wrapper callers A (0x5e317a0), B (0x5e34160), and C (0x60c1d50) and of the 5 callers of C.",
            "Caller B's 32-bit tag: what the first-4-bytes value and the 0x3b9ac9ff magic denote.",
            "The 0x30-byte option-group element's +0x00..+0x18 fields and C++ name (still open from #4337; the serializer and the apply loop read only +0x20/+0x28).",
            "The .bss string at 0x6508980 identity/content (still open from #4328/#4349).",
        ],
        "do_not_pick": [
            "0x60c1bb0", "0x60c1190 (cited)", "0x60c18b0 (cited)", "0x60c0e90",
            "0x5e317a0", "0x5e34160", "0x60c1d50", "0x60bedc0 (cited)",
            "0x60ba0b0 (cited)", "0x5d36110 (cited)", "0x61cf670 (cited)",
            "0x6097630 (cited)", "0x609e510 (cited)", "0x609c8c0 (cited)",
            "0x609bcb0 (cited)", "0x609d0e0 (cited)", "0x609a410 (cited)",
            "0x6098510 (cited)", "0x60985e0 (cited)", "0x60c1c2e (call site inside the wrapper)",
        ],
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=2) + "\n")
    print("records.json written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
