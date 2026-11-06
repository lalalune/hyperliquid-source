#!/usr/bin/env python3
"""Build records.json for RE-001-find-family-merge-115.

Reads the packet's own export_excerpts.py (WINDOWS), census.py
(TARGETS) and callers.tsv, reuses #3537's routine records for the
44 re-shipped windows, and writes records.json next to this script.
Run from the repository root.
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

PREV = Path("/tmp/prev-packet/research/work-items/"
            "RE-001-find-family-hosts-115/records.json")
prev = json.load(open(PREV))

# --- census counts: "name kind" -> count, from callers.tsv ---------------
rows = open(PACKET / "callers.tsv").read().splitlines()[1:]
counts = collections.Counter()
for line in rows:
    parts = line.split("\t")
    counts["%s %s" % (TARGETS[int(parts[1], 16)],
                      parts[3].strip())] += 1

NEW_ROLES = {
    0x609D0E0: "Find host A: the empty-map slot-0x28 path, the '; ' worker-wrapper path, the merge-driver call, and the post-driver slot-0x28 / find_e70-0x0101 tail (whose Status is discarded).",
    0x609D08E: "Host A landing pad: destroys the local value, frees the out message and the accumulator, then _Unwind_Resume.",
    0x60BEDC0: "Find host B: the kind switch on desc+0xa8 (jump table 0x9786b4, 25 entries) over the nine text parsers, the seven enum lookups, the hex decode, the string assign, the 0x15/0x16 flag/link path and the code-3/code-4 reports.",
    0x60BEA8C: "Host B landing pad: cleanup, then selector 1 catches std::exception and reports code 4 'Error parsing <name>:<what>' via the status builder.",
    0x609C8C0: "Merge driver: clones the source options map first-wins per bucket, walks the descriptor's entries through the walker, merges survivors into arg7 when present, else reports the first surviving clone as 'Could not find option: '.",
    0x6098510: "Worker wrapper: empties the options string, then calls the worker 0x6097630 with an empty prefix string and the emptied options string as the accumulator.",
    0x60B7CD0: "String range ctor: builds a string from [first, last); SSO up to 15 bytes, else heap _M_create + memcpy, NUL-terminated.",
    0x6095B80: "Options-map node clone: allocates a 0x50-byte node and deep-copies the key and value strings; +0x40/+0x48 are NOT copied (the caller writes the hash).",
    0x5D38260: "Hash-table rehash: new bucket array, same-bucket nodes re-linked contiguously in old-list order; count 1 takes the inline-bucket path; count>>60 throws bad_array_new_length.",
    0x61D10A0: "Escape-assign: unescapes src into out; '\\\\' + char appends the decoded char, a trailing lone '\\\\' is dropped.",
    0x61D0EE0: "Escape decoder: 'r' -> 13, 'n' -> 10, anything else -> the character itself.",
    0x61D1480: "Bool parser: 'true' -> 1, 'false' -> 0, '1' -> 1, '0' -> 0; anything else throws invalid_argument built from the first argument.",
    0x61D1540: "stoull parser (__isoc23_strtoull, base 10): no digits -> invalid_argument('stoull'); ERANGE -> out_of_range('stoull'); suffix T/G/M/K shifts by 40/30/20/10.",
    0x61D18A0: "stoll parser (__isoc23_strtoll, base 10): instruction-identical to stoull except the conversion and the literal; same T/G/M/K suffix shifts.",
    0x61D1B90: "stoi parser (__isoc23_strtol): range check before the suffix shift; G/M/K shift by 30/20/10 with 32-bit wrap; T/t shifts by NOTHING.",
    0x61D1840: "u32 parser: stoull, then (value >> 32) == 0 or the shared stub throws out_of_range with the input text as the message.",
    0x61D17D0: "u8 parser: stoull, then (value >> 8) == 0 or the shared stub throws out_of_range with the input text as the message.",
    0x61D1B30: "i32-via-stoll parser: stoll, then (value + 0x80000000) >> 32 == 0 or the shared stub throws out_of_range with the input text as the message.",
    0x61D1EF0: "stoull alias: two instructions -- endbr64; jmp 0x61d1540.",
    0x61D1E30: "stod parser (strtod): no digits -> invalid_argument('stod'); ERANGE -> out_of_range('stod'); no suffix handling; trailing content ignored.",
    0x61C7FC0: "Hex decode: odd input length or a null out -> False; an invalid digit -> False with out left partially filled; success -> True.",
    0x61C7DC0: "Hex digit value: '0'-'9' -> 0-9, 'A'-'F'/'a'-'f' -> 10-15, anything else -> -1.",
    0x60BE160: "Enum lookup (u8): linear walk at size <= 20, else the _Hash_bytes walk; map 0x65070a0.",
    0x60BE2B0: "Enum lookup (u8): byte-identical to 0x60be160; map 0x6507060.",
    0x60BE400: "Enum lookup (u8): byte-identical to 0x60be160; map 0x6507120.",
    0x60BE550: "Enum lookup (u8): byte-identical to 0x60be160; map 0x6507160.",
    0x60BE6A0: "Enum lookup (u8): byte-identical to 0x60be160; map 0x65070e0.",
    0x60BE7F0: "Enum lookup (u32): the one u32 lookup -- reads/writes a full u32 at +0x28; map 0x6507020.",
    0x60BE940: "Enum lookup (u8): byte-identical to 0x60be160; map 0x6506fe0.",
}

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
    if start in NEW_ROLES:
        routines[key] = {
            "name": TARGETS[start],
            "role": NEW_ROLES[start],
            "end": "%#x" % stop,
            "size": stop - start,
            "calls": calls,
        }
    else:
        old = prev["routines"].get(key)
        if old is None:
            pad = prev["landing_pads"].get(key)
            routines[key] = {
                "name": TARGETS[start],
                "role": pad["role"] if pad else
                "Re-shipped whole-function excerpt from #3537.",
                "end": "%#x" % stop,
                "size": stop - start,
                "calls": calls,
            }
            continue
        routines[key] = {
            "name": old["name"],
            "role": old["role"],
            "end": "%#x" % stop,
            "size": stop - start,
            "calls": calls,
        }
        for extra in ("linear_limit", "local_set_node_size"):
            if extra in old:
                routines[key][extra] = old[extra]

records = {
    "artifact_path": "artifacts/node/115/hl-node",
    "artifact_sha256": "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
    "bounded_question": "How do the two sibling Find-family hosts (host A 0x609d0e0, host B 0x60bedc0) and the merge driver 0x609c8c0 drive the already-pinned Find pipeline (find_e70 0x6099e70, no_equals 0x609ba30, kind_dispatch 0x609b700, walker 0x609bcb0, matcher 0x60bb9a0, worker 0x6097630), and what does each report when the name cannot be resolved?",
    "census": {"counts": dict(sorted(counts.items())),
               "rows": len(rows)},
    "constants": {
        "hash_seed": "0xc70f6907",
        "linear_walk_limit": 20,
        "options_map_node_size": 80,
        "value_size": 80,
        "host_b_kind_table": "0x9786b4",
        "stoull_suffix_table": "0x97e998",
        "stoll_suffix_table": "0x97ea50",
        "enum_map_a": "0x65070a0",
        "enum_map_b": "0x6507060",
        "enum_map_c": "0x6507120",
        "enum_map_d": "0x6507160",
        "enum_map_e": "0x65070e0",
        "enum_map_u32": "0x6507020",
        "enum_map_f": "0x6506fe0",
        "shared_control_counts": "0x100000001",
    },
    "landing_pads": {
        "0x609d08e": {"end": "0x609d0d8",
                      "role": "Host A cleanup fragment."},
        "0x60bea8c": {"end": "0x60bedba",
                      "role": "Host B catch: std::exception -> code 4 'Error parsing <name>:<what>'."},
        "0x6080a71": {"end": "0x6080b0d",
                      "role": "Plain host cleanup fragment."},
        "0x608183a": {"end": "0x60818eb",
                      "role": "Block host cleanup fragment."},
        "0x6098a9c": {"end": "0x6098ace",
                      "role": "Element-scan host cleanup fragment."},
    },
    "literals": [
        {"address": "0x43e863", "value": "Could not find option: "},
        {"address": "0x43fb8a", "value": "Could not find configurable: "},
        {"address": "0x44e056", "value": "Could not find option"},
        {"address": "0x4409b0", "value": "; "},
        {"address": "0x445245", "value": "="},
        {"address": "0x4477ed", "value": "Error parsing:"},
        {"address": "0x4477fc", "value": "Error parsing "},
        {"address": "0x441b18", "value": ":"},
        {"address": "0x4376fd", "value": ""},
        {"address": "0x4373e9", "value": "Deserializing the option "},
        {"address": "0x437403", "value": " is not supported"},
        {"address": "0x434345", "value": "stoull"},
        {"address": "0x43434c", "value": "stoll"},
        {"address": "0x4311eb", "value": "stoi"},
        {"address": "0x441d25", "value": "stod"},
        {"address": "0x963298",
         "value": "basic_string: construction from null is not valid"},
    ],
    "model": "tools/find_family_merge_115.py",
    "open_unknowns": [
        "The '; ' literal host A writes into the copied value's name (code low byte 0) is an open unknown: the worker parses ';'-separated options, so it likely means 'no options', but the binary gives no gloss; the model records the literal and the branch faithfully.",
        "Host A's find_e70 tail writes its Status into a local that is then discarded (only the message is freed); the call survives only through its side effects via the descriptor's slot 0x28 / delegate_impl. Modelled literally and pinned by test.",
        "The worker's prefix is the string at element+0x20 (the matcher's prefix argument); the element's +0x00 name string is the scan's key. The model takes the +0x20 string as the prefix.",
        "The seven enum maps live in .bss (runtime-built); the model takes them as harness-injected EnumMap objects, not binary reads.",
        "The global default name at 0x6508980: its runtime contents are set by static init and were not located (carried from #3440); the model takes 'default' as the documented assumption.",
        "The delegate vtable base is not pinned; the model holds the delegate's slots as callables supplied by the harness.",
        "The serializer 0x60ba600 per-kind rules (25 jump-table cases) are a boundary; the default model reports every kind as serialized.",
        "Which construction paths install a non-null +0x28 delegate is not pinned.",
        "stod is modelled with Python float() on ordinary decimal inputs; inf/nan/hex-float edge inputs differ from C strtod.",
        "The rehash excerpt may end with undecodable padding bytes at 0x5d3833a-0x5d3833c; verify.py's raw-bytes check confirms the excerpt matches the binary.",
    ],
    "relocations": [
        {"address": "0x64ed290", "symbol": "__libc_single_threaded",
         "type": "R_X86_64_GLOB_DAT"},
    ],
    "routines": routines,
    "slug": "find-family-merge-115",
    "task_id": "RE-001",
    "tests": "tests/test_find_family_merge_115.py",
    "verify": "research/work-items/RE-001-find-family-merge-115/verify.py",
    "vtables": prev["vtables"],
}

out = PACKET / "records.json"
out.write_text(json.dumps(records, indent=1, sort_keys=True) + "\n")
print("wrote", out, "routines=%d census-rows=%d"
      % (len(routines), len(rows)))
