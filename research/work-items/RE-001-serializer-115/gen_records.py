#!/usr/bin/env python3
"""Build records.json for RE-001-serializer-115.

Reads the packet's own export_excerpts.py (WINDOWS), census.py
(TARGETS) and callers.tsv, and writes records.json next to this
script. Run from the repository root.

The JSON holds semantic records only -- kind rules, jump-table
targets, caller counts, literals, constants. Instruction-level
detail lives only in the whole-function verbatim excerpts.
"""

import collections
import json
import re
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402
from census import TARGETS  # noqa: E402

# --- census counts: "name kind" -> count, from callers.tsv ---------------
rows = open(PACKET / "callers.tsv").read().splitlines()[1:]
counts = collections.Counter()
for line in rows:
    parts = line.split("\t")
    counts["%s %s" % (TARGETS[int(parts[1], 16)],
                      parts[3].strip())] += 1

ROLES = {
    0x60BA600: "Value serializer: dispatches on kind (jump table 0x978650, 25 entries, 19 targets) and writes the value's text form into the out string; returns 1 on success, 0 with out untouched for kinds 0x11..0x16 and kind > 0x18. Sole direct caller is the matcher 0x60bb9a0 (site 0x60bbb97).",
    0x5F06BB0: "Signed i32 decimal (std::to_string(int)): sign bit, absolute value, magnitude thresholds, '-' fill, two-digit table loop; INT32_MIN formats as '-2147483648'.",
    0x60BA450: "vsnprintf into a string: calls the function pointer in GOT 0x64ed730 (vsnprintf) with a 328-byte stack buffer, then installs the result in the out string (SSO or _M_create + memcpy).",
    0x61D0F30: "Backslash-escape copy: for each input byte, escape_predicate decides; escaped bytes become '\\\\' + escape_letter, the rest are copied raw. The inverse of the escape decoder 0x61d0ee0 pinned by #3560.",
    0x61D0F1C: "Escape-copy landing pad: disposes the out string, then _Unwind_Resume.",
    0x61D0E90: "Needs-escape test: true for 0x0a, 0x0d, '#' (0x23), ':' (0x3a) and '\\\\' (0x5c) only; the bit-test mask is 0x0200000000800001 (bits {0, 23, 57} over byte - 0x23); bytes above 0x5c return 0.",
    0x61D0F00: "Escape letter: 0x0a -> 'n', 0x0d -> 'r', anything else -> the byte itself.",
    0x61C7E30: "Hex encode / raw copy: flag 1 reserves 2*len and writes two UPPERCASE hex chars per byte via hexchar; flag 0 replaces out with the raw input bytes. The serializer always passes flag 1.",
    0x61C7DA0: "Nibble to hex char: 0..9 -> '0'+n, 10..15 -> 'A'..'F' (adds 0x37 past 9).",
    0x60B79E0: "String move-assign: moves the source string into the destination (re-shipped byte-identical from #3488).",
}

KIND_RULES = [
    {"kind": 0, "target": "0x60bab78",
     "rule": "bool: byte at *value, nonzero -> \"true\" (0x43f883), zero -> \"false\" (0x430e89); _M_replace into out."},
    {"kind": 1, "target": "0x60ba678",
     "rule": "i32 at *value -> signed decimal via int_to_string 0x5f06bb0, then move_assign into out."},
    {"kind": 2, "target": "0x60ba678",
     "rule": "i32 at *value -> same helper, same value; behaviorally identical to kind 1."},
    {"kind": 3, "target": "0x60ba8a8",
     "rule": "i64 at *value -> signed decimal: absolute value, '-' fill, two-digit table loop; INT64_MIN -> \"-9223372036854775808\"."},
    {"kind": 4, "target": "0x60baf78",
     "rule": "u32 at *value -> unsigned decimal, 32-bit divide-by-100 loop, two-digit table."},
    {"kind": 5, "target": "0x60baf60",
     "rule": "u8 at *value -> signed decimal via int_to_string 0x5f06bb0 (zero-extended byte)."},
    {"kind": 6, "target": "0x60bad90",
     "rule": "u32 at *value -> unsigned decimal, second copy of the kind-4 loop (separate code, same behaviour)."},
    {"kind": 7, "target": "0x60babb0",
     "rule": "u64 at *value -> unsigned decimal, 64-bit divide-by-100 loop, two-digit table."},
    {"kind": 8, "target": "0x60ba6b0",
     "rule": "u64 at *value -> unsigned decimal, second copy of the kind-7 loop (separate code, same behaviour)."},
    {"kind": 9, "target": "0x60bb2b0",
     "rule": "(ptr, len) at *value -> backslash-escaped copy via escape_copy 0x61d0f30, then move_assign into out."},
    {"kind": 10, "target": "0x60bb280",
     "rule": "f64 at *value -> \"%f\" via snprintf_string 0x60ba450 (vsnprintf, 328-byte buffer), then move_assign into out."},
    {"kind": 11, "target": "0x60bb240",
     "rule": "u8 enum name: linear walk of the head list at map 0x65070a0 + 0x10 (node next +0x00, name +0x08, key +0x28); on match _M_assign the name into out; on miss return 0."},
    {"kind": 12, "target": "0x60bb200",
     "rule": "u8 enum name, map 0x6507060; same walk as kind 11."},
    {"kind": 13, "target": "0x60bb1c0",
     "rule": "u8 enum name, map 0x6507120; same walk as kind 11."},
    {"kind": 14, "target": "0x60bb180",
     "rule": "u32 enum name, map 0x6507020; the one u32 key compare (full u32 at node +0x28)."},
    {"kind": 15, "target": "0x60bb140",
     "rule": "u8 enum name, map 0x6507160; same walk as kind 11."},
    {"kind": 16, "target": "0x60baaf8",
     "rule": "u8 enum name, map 0x65070e0; same walk as kind 11."},
    {"kind": 17, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 18, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 19, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 20, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 21, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 22, "target": "0x60ba648",
     "rule": "Unhandled: falls through to the return-0 path; out untouched."},
    {"kind": 23, "target": "0x60baac8",
     "rule": "(ptr, len) at *value -> UPPERCASE hex via hex_encode 0x61c7e30 with flag 1, then move_assign into out."},
    {"kind": 24, "target": "0x60bab40",
     "rule": "u8 enum name, map 0x6506fe0; same walk as kind 11."},
]

routines = {}
for name, start, stop in WINDOWS:
    key = "%#x" % start
    calls = []
    for line in (PACKET / "excerpts" / name).read_text().splitlines():
        m = re.search(r"\b(call|jmp)\s+([0-9a-f]+)\s", line)
        if m:
            t = int(m.group(2), 16)
            if t in TARGETS and "%#x" % t not in calls:
                calls.append("%#x" % t)
    routines[key] = {
        "name": TARGETS[start],
        "role": ROLES[start],
        "end": "%#x" % stop,
        "size": stop - start,
        "calls": calls,
    }

records = {
    "artifact_path": "artifacts/node/115/hl-node",
    "artifact_sha256": "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
    "bounded_question": "What are the serializer 0x60ba600's 25 per-kind rules -- the single documented boundary of #3485 -- and how does each rule turn a Find-pipeline value into its text form, end to end including the decimal, escape, hex, double and enum-name helpers?",
    "census": {"counts": dict(sorted(counts.items())),
               "rows": len(rows)},
    "constants": {
        "jump_table": "0x978650",
        "kind_count": 25,
        "kind_max": "0x18",
        "digits_table_sha256": "bedfbc17dfedc3a783c817da8b2eec13baff8e36c4e6a61c346332973895315a",
        "digits_table_chunks": ["0x451750", "0x453230", "0x456910",
                                "0x453e00", "0x451db0", "0x452ba0",
                                "0x455590", "0x456240", "0x456920",
                                "0x4528d0", "0x456250", "0x453240",
                                "0x454870"],
        "escape_mask": "0x0200000000800001",
        "bool_false_literal": "0x430e89",
        "bool_true_literal": "0x43f883",
        "double_format_literal": "0x432165",
        "double_format_buffer": 328,
        "vsnprintf_got": "0x64ed730",
        "enum_map_a": "0x65070a0",
        "enum_map_b": "0x6507060",
        "enum_map_c": "0x6507120",
        "enum_map_u32": "0x6507020",
        "enum_map_d": "0x6507160",
        "enum_map_e": "0x65070e0",
        "enum_map_f": "0x6506fe0",
    },
    "kind_rules": KIND_RULES,
    "landing_pads": {
        "0x61d0f1c": {"end": "0x61d0f2c",
                     "role": "Escape-copy cleanup fragment."},
    },
    "literals": [
        {"address": "0x430e89", "value": "false"},
        {"address": "0x43f883", "value": "true"},
        {"address": "0x432165", "value": "%f"},
    ],
    "model": "tools/serializer_115.py",
    "open_unknowns": [
        "Kinds 1 and 2 are behaviorally identical (both call int_to_string 0x5f06bb0 with the same 32-bit value), as are kinds 4/6 (u32) and 7/8 (u64); the binary gives no gloss for which C++ types the duplicated kinds stand for, so the model records the duplication faithfully and does not name the types.",
        "The seven enum maps live in .bss (runtime-built); the model takes them as harness-injected EnumMap objects, not binary reads. The serializer's enum walk is a plain head-list walk, unlike the hash-bucket walk the #3560 parsers use in the other direction.",
        "The double kind formats with C %f via vsnprintf; Python '%f' matches it on ordinary values, inf and nan. A negative NaN's sign is not pinned (the binary's vsnprintf would print '-nan'; the model does not special-case it).",
        "The serializer's value struct layout beyond the per-kind reads is not pinned: each kind reads only the bytes its rule needs (1, 4 or 8 bytes at *value, or a 16-byte (ptr, len) pair for kinds 9 and 23).",
        "Which construction paths install a non-null +0x28 delegate (carried from #3485) is still not pinned.",
        "The global default name at 0x6508980 and the delegate vtable base (carried from #3485/#3560) are still not pinned.",
    ],
    "relocations": [
        {"address": "0x64ed730", "symbol": "vsnprintf",
         "type": "R_X86_64_GLOB_DAT"},
    ],
    "routines": routines,
    "slug": "serializer-115",
    "task_id": "RE-001",
    "tests": "tests/test_serializer_115.py",
    "verify": "research/work-items/RE-001-serializer-115/verify.py",
    "vtables": {},
}

out = PACKET / "records.json"
out.write_text(json.dumps(records, indent=1, sort_keys=True) + "\n")
print("wrote", out, "routines=%d census-rows=%d"
      % (len(routines), len(rows)))
