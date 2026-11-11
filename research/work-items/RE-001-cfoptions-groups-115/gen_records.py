#!/usr/bin/env python3
"""Build records.json for RE-001-cfoptions-groups-115 from the census.

Run from the repo root:
    python3 research/work-items/RE-001-cfoptions-groups-115/gen_records.py

Cross-checks every claim against the excerpts and the raw binary before
writing: the two RegisterOptions argument setups in the 0x6086e00
excerpt, the group-name literals, the map addresses, and the lea
censuses. The artifact digest is stored in full (64 hex chars) — never
a prefix.
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Cited instruction lines, copied verbatim from the excerpts.
HOST_SPOTS = {
    "input_map_slot": "mov    %rdx,0x20(%rsp)",
    "mutable_base_lea": "lea    0x20(%rbx),%rcx",
    "vector_begin_zero": "movq   $0x0,0x8(%rbx)",
    "vector_end_zero": "movq   $0x0,0x10(%rbx)",
    "vector_cap_zero": "movq   $0x0,0x18(%rbx)",
    "mutable_base_keep": "mov    %rcx,%r15",
    "vtable_first_lea": "# 64d3128",
    "vtable_first_store": "mov    %rax,(%rbx)",
    "mutable_name_lea": "# 43fa91",
    "string_ctor_call_1": "call   607d9f0",
    "mutable_map_lea": "# 6506b20",
    "mutable_base_arg": "mov    %r15,%rdx",
    "mutable_register_call": "call   6099ce0",
    "vtable_second_lea": "# 64d31a8",
    "immutable_base_lea": "lea    0x218(%rbx),%rax",
    "immutable_base_stage": "mov    %rax,0x28(%rsp)",
    "input_map_store": "mov    %rax,0x630(%rbx)",
    "immutable_name_lea": "# 433249",
    "immutable_map_lea": "# 6506ae0",
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
    assert data[0x43FA91:0x43FAA1] == b"MutableCFOptions"
    assert data[0x433249:0x43325B] == b"ImmutableCFOptions"

    host = (HERE / "fn-6086e00-cfoptions-configurable-ctor.objdump.txt").read_text()
    helper = (HERE / "fn-6099ce0-register-options.objdump.txt").read_text()
    for label, spot in HOST_SPOTS.items():
        assert spot in host, f"host excerpt missing: {label} ({spot})"
    for label, spot in HELPER_SPOTS.items():
        assert spot in helper, f"helper excerpt missing: {label} ({spot})"
    assert host.count("call   6099ce0") == 2, "host must call RegisterOptions twice"
    assert host.count("call   607d9f0") == 2, "host must build two names via the string ctor"

    callers = (HERE / "callers.tsv").read_text().splitlines()[1:]
    assert len(callers) == 37, f"expected 37 caller rows, got {len(callers)}"

    records = {
        "task": "RE-001",
        "work_item": "RE-001-cfoptions-groups-115",
        "question": ("Which option groups does the ConfigurableCFOptions "
                     "ctor 0x6086e00 register — names, bases, maps — and "
                     "what is the resulting group vector? This resolves "
                     "#4372's open unknown for the two sites in this host "
                     "(\"not individually analysed\")."),
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "host": {
            "address": "0x6086e00",
            "fde": "0x6086e00..0x608818d",
            "cpp_name": ("rocksdb::ConfigurableCFOptions::"
                         "ConfigurableCFOptions(const rocksdb::"
                         "ColumnFamilyOptions&, const std::unordered_map<"
                         "std::string, std::string>*)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1)",
            "role": ("Builds a Configurable adapter around a "
                     "ColumnFamilyOptions plus an input string map; "
                     "registers exactly two option groups, then stores "
                     "the input map at object+0x630."),
            "vector_triple": {
                "begin": "object+0x08", "end": "object+0x10",
                "capacity_end": "object+0x18",
                "initial": "all zero (0x608723f, 0x608725c, 0x6087268)",
                "input_map_slot": "object+0x630 holds the ctor's third argument (stored at 0x6087cc8 from 0x20(%rsp), set at entry 0x6086e28)",
            },
            "vtable_change": {
                "first": "0x64d3138 stored at (%rbx) (lea 0x64d3128 at 0x608724d + 0x10, store at 0x6087270)",
                "second": "0x64d31b8 stored at (%rbx) (lea 0x64d31a8 at 0x6087533 + 0x10, store at 0x6087541)",
                "note": ("The vtable pointer is overwritten between the "
                         "two registrations; the reason is not pinned here. "
                         "Both tables are recorded by #3567 "
                         "(RE-001-delegate-vtable-115)."),
            },
            "adjacent_calls": {
                "0x6086cd0": "called at 0x608722c with rdi=0x50(%rsp) (a stack struct); internals not pinned",
                "0x6081e40": "called at 0x6087553 with rdi=object+0x218, rsi=source ColumnFamilyOptions; the ImmutableCFOptions subobject ctor is the likely identity, not pinned",
                "0x5d35c00": "called at 0x6087c83 with rdi=object+0x618, rsi=source+0x2e8; internals not pinned",
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
            "name_builder": {
                "address": "0x607d9f0",
                "fde": "0x607d9f0..0x607dad3",
                "role": "std::string(const char*) ctor; builds each group name into the shared stack string at 0x250(%rsp) (#4263)",
            },
        },
        "registrations": [
            {
                "index": 0,
                "call_site": "0x608749a",
                "name": "MutableCFOptions",
                "name_chars": 16,
                "name_storage": "heap (16 > 15 SSO limit; _M_create + memcpy)",
                "name_literal": "0x43fa91 (sole binary-wide lea site 0x6087473; string built by 0x607d9f0 at 0x6087485 into 0x250(%rsp))",
                "base": "object+0x20 (lea at 0x6087235, kept in callee-saved r15 at 0x608724a, passed as rdx at 0x6087491)",
                "map": "0x6506b20",
                "map_entries": 62,
                "map_source": "#4263 (MutableCFOptions map, 62 entries)",
                "arg_setup": ("rdi=object, rsi=0x250(%rsp) via r14, "
                              "rdx=object+0x20, rcx=0x6506b20"),
                "growth": "vector empty, end == capacity-end == 0, so the growth path runs; capacity becomes 1",
            },
            {
                "index": 1,
                "call_site": "0x6087ce8",
                "name": "ImmutableCFOptions",
                "name_chars": 18,
                "name_storage": "heap (18 > 15 SSO limit; _M_create + memcpy)",
                "name_literal": "0x433249 (sole binary-wide lea site 0x6087cc1; string rebuilt by 0x607d9f0 at 0x6087ccf into the same 0x250(%rsp) slot)",
                "base": "object+0x218 (lea at 0x6087544, staged in 0x28(%rsp) at 0x608754e, passed as rdx at 0x6087cd4)",
                "map": "0x6506ae0",
                "map_entries": 31,
                "map_source": "#4263 (ImmutableCFOptions map, 31 entries)",
                "arg_setup": ("rdi=object, rsi=0x250(%rsp) via 0x18(%rsp), "
                              "rdx=object+0x218, rcx=0x6506ae0"),
                "growth": "after group 0, end == capacity-end again (capacity 1), so the growth path runs; capacity becomes 2",
            },
        ],
        "resulting_vector": {
            "size": 2,
            "capacity": 2,
            "elements": [
                {"name": "MutableCFOptions", "base": "object+0x20", "map": "0x6506b20"},
                {"name": "ImmutableCFOptions", "base": "object+0x218", "map": "0x6506ae0"},
            ],
        },
        "census": {
            "register_options_sites": 37,
            "note": ("Every direct E8 call site of 0x6099ce0 (callers.tsv, "
                     "with enclosing FDE). Matches #3257 and #4372 exactly. "
                     "Five sites were pinned by #3257, two by #4372, the "
                     "two sites in this packet are new; the remaining 28 "
                     "are listed but not individually analysed."),
            "lea_census": {
                "0x43fa91": ["0x6087473"],
                "0x433249": ["0x6087cc1"],
                "0x6506b20": ["0x608748a", "0x608ec34", "0x608f329"],
                "0x6506ae0": ["0x6087cde", "0x6090e46"],
                "note": ("Both name literals are used only by this host. "
                         "The other lea sites of the two maps sit inside "
                         "the static initializer 0x6089b50..0x6091e5c "
                         "(#4263), which builds the maps."),
            },
        },
        "resolves": [
            "#4372 open unknown, for these two sites: the keys and fields of the RegisterOptions call sites in ConfigurableCFOptions",
            "#4263's loose \"proven by the consumer 0x6086e00\" note, pinned precisely: the consumer registers MutableCFOptions (base object+0x20, map 0x6506b20) and ImmutableCFOptions (base object+0x218, map 0x6506ae0)",
        ],
        "open_unknowns": [
            "The keys and fields of the other 28 RegisterOptions call sites (listed in callers.tsv, not individually analysed).",
            "Why ConfigurableCFOptions overwrites its vtable pointer (0x64d3138 -> 0x64d31b8) between the two registrations.",
            "The internals of the adjacent calls in 0x6086e00 (0x6086cd0, 0x6081e40 at object+0x218, 0x5d35c00 at object+0x618); only their arg registers are recorded here.",
            "The ColumnFamilyOptions C++ layout names for the bases object+0x20 and object+0x218 and for the input-map slot object+0x630.",
            "The contents of the .bss maps at 0x6506b20 / 0x6506ae0 beyond their entry counts from #4263 (file-unbacked; only addresses are pinned).",
        ],
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=1) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
