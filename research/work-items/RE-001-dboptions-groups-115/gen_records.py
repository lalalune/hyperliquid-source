#!/usr/bin/env python3
"""Build records.json for RE-001-dboptions-groups-115 from the census.

Run from the repo root:
    python3 research/work-items/RE-001-dboptions-groups-115/gen_records.py

Cross-checks every claim against the excerpts and the raw binary before
writing: the two RegisterOptions argument setups in the 0x60a47f0
excerpt, the group-name literals, and the map addresses. The artifact
digest is stored in full (64 hex chars) — never a prefix.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Cited instruction lines, copied verbatim from the excerpts.
HOST_SPOTS = {
    "vector_begin_zero": "movq   $0x0,0x8(%rbx)",
    "vector_end_zero": "movq   $0x0,0x10(%rbx)",
    "vector_cap_zero": "movq   $0x0,0x18(%rbx)",
    "vtable_first": "# 64d3628",
    "mutable_name_literal": "# 4541e0",
    "mutable_map_lea": "# 6506dc0",
    "mutable_base_lea": "lea    0x20(%rbx),%r14",
    "mutable_register_call": "call   6099ce0",
    "vtable_second": "# 64d36a8",
    "immutable_base_lea": "lea    0x98(%rbx),%rax",
    "immutable_name_literal": "# 450aa0",
    "immutable_map_lea": "# 6506d80",
    "immutable_ns_immediate": "mov    $0x736e,%edx",
}
HELPER_SPOTS = {
    "growth_call": "call   6099790",
    "end_advance": "addq   $0x30,0x10(%rbx)",
    "base_map_store": "movups %xmm0,0x20(%rbp)",
}


def main() -> None:
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    assert want == DIGEST, "provenance digest changed"
    assert len(DIGEST) == 64, "digest must be the full 64 hex chars"

    data = BIN.read_bytes()
    assert __import__("hashlib").sha256(data).hexdigest() == DIGEST
    assert data[0x4541E0:0x4541F0] == b"MutableDBOptions"
    assert data[0x450AA0:0x450AB0] == b"ImmutableDBOptio"

    host = (HERE / "fn-60a47f0-dboptions-configurable-ctor.objdump.txt").read_text()
    helper = (HERE / "fn-6099ce0-register-options.objdump.txt").read_text()
    for label, spot in HOST_SPOTS.items():
        assert spot in host, f"host excerpt missing: {label} ({spot})"
    for label, spot in HELPER_SPOTS.items():
        assert spot in helper, f"helper excerpt missing: {label} ({spot})"
    assert host.count("call   6099ce0") == 2, "host must call RegisterOptions twice"

    callers = (HERE / "callers.tsv").read_text().splitlines()[1:]
    assert len(callers) == 37, f"expected 37 caller rows, got {len(callers)}"

    records = {
        "task": "RE-001",
        "work_item": "RE-001-dboptions-groups-115",
        "question": ("What are the 0x30-byte option-group elements at "
                     "object+0x08..+0x10 — their +0x00..+0x18 fields and "
                     "C++ name — and which groups does the DBOptions "
                     "configurable register?"),
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "host": {
            "address": "0x60a47f0",
            "fde": "0x60a47f0..0x60a636b",
            "cpp_name": ("rocksdb::DBOptionsConfigurable::"
                         "DBOptionsConfigurable(const rocksdb::DBOptions&, "
                         "const std::unordered_map<std::string, "
                         "std::string>*)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1)",
            "role": ("Builds a Configurable adapter around a DBOptions "
                     "plus an input string map; registers exactly two "
                     "option groups, then constructs the ImmutableDBOptions "
                     "subobject at +0x98."),
            "vector_triple": {
                "begin": "object+0x08", "end": "object+0x10",
                "capacity_end": "object+0x18",
                "initial": "all zero (0x60a486e, 0x60a4895, 0x60a48a6)",
                "input_map_slot": "object+0x90 holds the ctor's third argument (0x60a484f)",
            },
            "vtable_change": {
                "first": "0x64d3638 stored at (%rbx) (0x60a48ae)",
                "second": "0x64d36b8 stored at (%rbx) (0x60a4958)",
                "note": ("The vtable pointer is overwritten between the "
                         "two registrations; the reason is not pinned here."),
            },
        },
        "register_helper": {
            "address": "0x6099ce0",
            "fde": "0x6099ce0..0x6099e34",
            "cpp_name": ("rocksdb::Configurable::RegisterOptions("
                         "const std::string&, void*, "
                         "const std::unordered_map<std::string, "
                         "rocksdb::OptionTypeInfo>*)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1)",
            "signature": ("(Configurable* object, const std::string* name, "
                          "void* base, const unordered_map<string, "
                          "OptionTypeInfo>* map)"),
            "element_layout": {
                "size_bytes": 48,
                "name": "element+0x00..+0x20 is a std::string: data pointer +0x00, size +0x08, SSO buffer +0x10..+0x20",
                "base": "element+0x20 is the options-base pointer",
                "map": "element+0x28 is the OptionTypeInfo map pointer",
            },
            "growth_helper": {
                "address": "0x6099790",
                "fde": "0x6099790..0x6099cad",
                "called_at": "0x6099e0a, only when end == capacity-end",
                "capacity_rule": ("1 for an empty vector, else "
                                  "min(2*size, MAX_SIZE); MAX_SIZE = "
                                  "(2**63 - 1) // 48 = 192153584101141162 (#3257)"),
            },
            "fast_path": ("When spare capacity exists the record is "
                          "written into the slot at end (SSO name copied "
                          "inline, heap name via _M_create + memcpy, base "
                          "and map by one movdqa at 0x6099d7f), then end "
                          "advances by 0x30 (0x6099d89)."),
        },
        "registrations": [
            {
                "index": 0,
                "call_site": "0x60a492a",
                "name": "MutableDBOptions",
                "name_chars": 16,
                "name_storage": "heap (16 > 15 SSO limit; _M_create + memcpy)",
                "name_literal": "0x4541e0 (movdqa at 0x60a48f1)",
                "base": "object+0x20 (lea at 0x60a48e7)",
                "map": "0x6506dc0",
                "map_entries": 19,
                "map_source": "#4237 (MutableDBOptions map, 19 entries)",
                "arg_setup": ("rdi=object, rsi=stack string at 0x2f0(%rsp), "
                              "rdx=object+0x20, rcx=0x6506dc0"),
                "growth": "vector empty, end == capacity-end == 0, so the growth path runs; capacity becomes 1",
            },
            {
                "index": 1,
                "call_site": "0x60a50f2",
                "name": "ImmutableDBOptions",
                "name_chars": 18,
                "name_storage": "heap (18 > 15 SSO limit; _M_create + memcpy)",
                "name_literal": ("0x450aa0 chunk \"ImmutableDBOptio\" "
                                 "(movdqa at 0x60a50aa) + immediate 0x736e "
                                 "\"ns\" at buffer+16 (mov at 0x60a50c9)"),
                "base": "object+0x98 (lea at 0x60a495b, staged in (%rsp) at 0x60a4965, still live at the call)",
                "map": "0x6506d80",
                "map_entries": 81,
                "map_source": "#4237 (DBOptions map, 81 entries)",
                "arg_setup": ("rdi=object, rsi=stack string at 0x2f0(%rsp), "
                              "rdx=object+0x98, rcx=0x6506d80"),
                "growth": "after group 0, end == capacity-end again (capacity 1), so the growth path runs; capacity becomes 2",
            },
        ],
        "resulting_vector": {
            "size": 2,
            "capacity": 2,
            "elements": [
                {"name": "MutableDBOptions", "base": "object+0x20", "map": "0x6506dc0"},
                {"name": "ImmutableDBOptions", "base": "object+0x98", "map": "0x6506d80"},
            ],
        },
        "census": {
            "register_options_sites": 37,
            "note": ("Every direct E8 call site of 0x6099ce0 (callers.tsv, "
                     "with enclosing FDE). Matches #3257 exactly. Three "
                     "sites were pinned by #3257 (BlockTableOptions, "
                     "SkipListFactoryOptions, empty-key); the two sites in "
                     "this packet are new; the remaining 32 are listed but "
                     "not individually analysed."),
        },
        "readers_negative_evidence": {
            "note": ("The map serializer 0x6097630 (#4337) and the apply "
                     "loop 0x609c8c0 (#4334) walk the same vector but read "
                     "only element+0x20 (base) and element+0x28 (map); "
                     "neither reads the element name at +0x00..+0x18. "
                     "Slot 12's rcx string comes from the literal 0x4376fd "
                     "(#4328), not from an element. Which code reads the "
                     "group name at runtime is an open unknown."),
        },
        "resolves": [
            "#3257 open unknown, for these two sites: the keys and fields of the RegisterOptions call sites in DBOptionsConfigurable",
            "#4337 open unknown, for the DBOptions object: the 0x30-byte element's +0x00..+0x18 fields are a std::string name, and the element is a Configurable::RegisterOptions group record",
        ],
        "open_unknowns": [
            "The keys and fields of the other 32 RegisterOptions call sites (listed in callers.tsv, not individually analysed).",
            "Which code reads the element name string (+0x00..+0x18) at runtime; the serializer and apply loop read only +0x20/+0x28.",
            "Why DBOptionsConfigurable overwrites its vtable pointer (0x64d3638 -> 0x64d36b8) between the two registrations.",
            "The internals of the adjacent ctor calls in 0x60a47f0 (0x60a43c0 at object+0x98, 0x5d38750 at object+0x2d8, 0x60a3b60); only their arg registers are recorded here.",
            "The contents of the .bss maps at 0x6506dc0 / 0x6506d80 beyond their entry counts from #4237 (file-unbacked; only addresses are pinned).",
        ],
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=1) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
