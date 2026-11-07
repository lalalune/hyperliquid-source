#!/usr/bin/env python3
"""Build records.json for RE-001-optiontypeinfo-type2122-arm-115.

The records are semantic only: branch sites, address ranges, literal
records, entry/reachability tables, and frame identities. No per-instruction
mnemonic list is recorded here; instruction detail lives only in the verbatim
whole-function objdump excerpts. Excerpt sha256 values are computed from the
files on disk (see export_excerpts.py) at generation time.
"""
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ARTIFACT_SIZE = 105896032

EXCERPTS = [
    ("fn-60bedc0-apply.objdump.txt", 0x60BEDC0, 0x60BF5BC, "apply (OptionTypeInfo::Apply); re-shipped byte-identical from #4311"),
    ("fn-60bb9a0-serialize.objdump.txt", 0x60BB9A0, 0x60BBDEB, "serializer (OptionTypeInfo::Serialize); re-shipped byte-identical from #4311"),
    ("fn-60b9d70-config-copy.objdump.txt", 0x60B9D70, 0x60B9DFC, "ConfigOptions 0x50-byte copy"),
    ("fn-6099e70-set-equals.objdump.txt", 0x6099E70, 0x609A1A9, '"=" path setter'),
    ("fn-609ba30-set-no-equals-fwd.objdump.txt", 0x609BA30, 0x609BA76, 'no-"=" path forwarder'),
    ("fn-609b8a0-create-by-name.objdump.txt", 0x609B8A0, 0x609BA2A, "create-by-name (GetOptionName + registry scan + apply-created)"),
    ("fn-6096f40-scan-options.objdump.txt", 0x6096F40, 0x609710F, "options-vector scan (nested-key lookup)"),
    ("fn-609b700-apply-created.objdump.txt", 0x609B700, 0x609B869, "apply-created (type-22 delegate / ParseOption slot 0x50)"),
    ("fn-6097110-configure-slot9.objdump.txt", 0x6097110, 0x609714E, "ConfigureOptions slot-9 tail-call"),
    ("fn-5e33fb0-config-dtor.objdump.txt", 0x5E33FB0, 0x5E33FEA, "ConfigOptions-copy dtor"),
    ("fn-6083a90-type22-helper.objdump.txt", 0x6083A90, 0x6083C83, "type-22 record builder (prefix_extractor + memtable_insert_with_hint_prefix_extractor)"),
    ("fn-60809e0-custom-parse.objdump.txt", 0x60809E0, 0x6080A71, 'custom parse for the helper entries ("id" reset, else delegate 0x61ca3d0)'),
    ("fn-607d190-parse-manager.objdump.txt", 0x607D190, 0x607D1BD, "std::function manager for the custom parse"),
    ("fn-60956f0-empty-status.objdump.txt", 0x60956F0, 0x609570C, "empty-Status stub (Configurable slot 0x40)"),
    ("fn-609d980-get-option-name.objdump.txt", 0x609D980, 0x609DC18, "GetOptionName (Configurable slot 0x68)"),
    ("fn-60c1190-map-parse.objdump.txt", 0x60C1190, 0x60C1887, 'map parser ("k=v;k=v" and "{k=v;k=v}")'),
    ("fn-607ea10-factory-builder.objdump.txt", 0x607EA10, 0x607EB17, "CF factory record builder"),
]

# (map, name, type, verification, offset, flags) — from #4237 (DBOptions) and
# #4263 (CFOptions) maps packets; see type22-entries.tsv.
TYPE22_ENTRIES = [
    ("DBOptions", "statistics", 22, 0, 0x48, 0x3401),
    ("DBOptions", "wal_filter", 22, 1, 0x188, 0x1201),
    ("DBOptions", "file_checksum_gen_factory", 22, 3, 0x1A8, 0x1400),
    ("MutableCFOptions", "prefix_extractor", 22, 2, 0x40, 0x1100),
    ("ImmutableCFOptions", "comparator", 22, 1, 0x8, 0x202),
    ("ImmutableCFOptions", "merge_operator", 22, 3, 0x20, 0x1402),
    ("ImmutableCFOptions", "compaction_filter", 22, 1, 0x30, 0x1200),
    ("ImmutableCFOptions", "compaction_filter_factory", 22, 1, 0x38, 0x1400),
    ("ImmutableCFOptions", "memtable", 22, 5, 0x68, 0x400),
    ("ImmutableCFOptions", "memtable_factory", 22, 1, 0x68, 0x400),
    ("ImmutableCFOptions", "block_based_table_factory", 22, 5, 0x78, 0x402),
    ("ImmutableCFOptions", "plain_table_factory", 22, 5, 0x78, 0x402),
    ("ImmutableCFOptions", "table_factory", 22, 1, 0x78, 0xC402),
    ("ImmutableCFOptions", "memtable_insert_with_hint_prefix_extractor", 22, 2, 0xC0, 0x0),
    ("ImmutableCFOptions", "sst_partitioner_factory", 22, 1, 0xF8, 0x1400),
]

# name -> (parse_manager, parse_invoker, construction, reaches_arm)
REACHABILITY = {
    "statistics": (0x606FA80, 0x60780A0, "DB special pair", False),
    "wal_filter": (0x609F250, 0x609FC80, "DB special pair", False),
    "file_checksum_gen_factory": (0x609F370, 0x60A2360, "DB special pair", False),
    "prefix_extractor": (0x607D190, 0x60809E0, "type22 helper 0x6083a90", False),
    "memtable_insert_with_hint_prefix_extractor": (0x607D190, 0x60809E0, "type22 helper 0x6083a90", False),
    "comparator": (0, 0, "CF direct writes", True),
    "merge_operator": (0, 0, "CF direct writes", True),
    "compaction_filter": (0, 0, "CF direct writes", True),
    "compaction_filter_factory": (0, 0, "CF direct writes", True),
    "table_factory": (0, 0, "CF direct writes", True),
    "sst_partitioner_factory": (0, 0, "CF direct writes", True),
    "memtable": (0, 0, "CF factory builder 0x607ea10", True),
    "memtable_factory": (0, 0, "CF factory builder 0x607ea10", True),
    "block_based_table_factory": (0, 0, "CF factory builder 0x607ea10", True),
    "plain_table_factory": (0, 0, "CF factory builder 0x607ea10", True),
}


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def build():
    excerpts = []
    for name, start, end, role in EXCERPTS:
        excerpts.append({
            "file": name,
            "start": "0x%x" % start,
            "end": "0x%x" % end,
            "role": role,
            "sha256": sha256_file(os.path.join(HERE, name)),
        })
    entries = []
    for (map_name, name, typ, verif, offset, flags) in TYPE22_ENTRIES:
        manager, invoker, construction, reaches = REACHABILITY[name]
        entries.append({
            "map": map_name, "name": name, "type": typ,
            "verification": verif, "offset": "0x%x" % offset,
            "flags": "0x%x" % flags,
            "parse_manager": ("0x%x" % manager) if manager else None,
            "parse_invoker": ("0x%x" % invoker) if invoker else None,
            "construction": construction, "reaches_arm": reaches,
        })
    return {
        "task": "RE-001",
        "work_item": "RE-001-optiontypeinfo-type2122-arm-115",
        "node": 115,
        "artifact": {
            "path": "artifacts/node/115/hl-node",
            "sha256": ARTIFACT_SHA256,
            "size": ARTIFACT_SIZE,
            "source": "provenance/artifacts.json",
        },
        "question": (
            "What does the type-21/22 arm of the OptionTypeInfo apply (0x60bedc0) do on "
            "node #115, which entries can reach it, and what Status does each path return? "
            "Resolves #4311 open unknowns 1, 3 and 4."
        ),
        "apply": {
            "address": "0x60bedc0", "fde": "0x60bedc0..0x60bf5bc",
            "signature": {
                "rdi": "Status* out (r12)", "rsi": "record (rbp)",
                "rdx": "ConfigOptions* (rbx)", "rcx": "name string (r14)",
                "r8": "value string (copied to rsp+0x70 = r15)",
                "r9": "options base (r13)",
            },
            "record_layout": {
                "offset": "+0x00 i64", "parse_function": "+0x08 std::function (functor +0x08, manager +0x18, invoker +0x20)",
                "serialize_function": "+0x28 std::function (functor +0x28, manager +0x38, invoker +0x40)",
                "other_functions": "+0x48, +0x68, +0x88 std::function",
                "type": "+0xa8 i32", "verification": "+0xac i32", "flags": "+0xb0 i32",
                "record_size": "0xd8",
            },
            "verification_4": "Status OK immediately at 0x60bedeb; never parses (see #4311)",
            "custom_parse_dispatch": "record+0x18 (parse manager) != 0: copy ConfigOptions, call *0x20(%rbp) with (Status*, record+0x8, config-copy, name, value, field-addr)",
            "base_null": {"code": 1, "message": "Could not find option", "literal": "0x44e056", "length": 21, "site": "0x60befb4"},
            "jump_table": {
                "address": "0x9786b4", "entries": 25, "types": "0..0x18",
                "entry_width": "int32 relative offsets: movslq (%rcx,%rdx,4),%rdx; add %rcx,%rdx; jmp *%rdx (at 0x60bf050-0x60bf057)",
                "range_check": "type > 0x18 bypasses the table: cmp $0x18; ja 0x60bf07e (at 0x60bf042-0x60bf045)",
                "types_17_22_target": "0x60bf07e (table entries 17-22 all hold the 0x60bf07e offset)",
                "types_21_22": "sub $0x15; cmp $1; jbe 0x60bf1e0 (the arm)",
                "types_17_20": "fail the range test -> verification error path",
                "type_14_target": "0x60bf05a (table entry 14)",
                "type_14": "parse via 0x60be7f0, enum registry 0x6507020; on failure falls to 0x60bf078 -> 0x60bf07e -> verification error",
            },
            "arm_is_primary": (
                "The arm is the PRIMARY parse for types 21/22 (jump-table direct dispatch), "
                "not a fallback after a failed primary parse; corrects #4311's phrasing. "
                "Whether a given entry reaches it depends on its parse function (see reachability)."
            ),
        },
        "arm": {
            "address": "0x60bf1e0",
            "flags_gate": {
                "test": "flags %ah bits 0x2/0x4/0x8 = flags bits 0x200/0x400/0x800",
                "any_set": "0x60bf418: deref field as pointer; value size == 0 -> Status OK; *(field) != 0 -> main body 0x60bf212; else kNotFound",
                "none_set": "0x60bf20d: empty value -> Status OK, else main body 0x60bf212",
            },
            "null_object_error": {
                "code": 1, "message": "Could not find configurable: <name>",
                "literal": "0x43fb8a", "length": 29, "tail": "0x60befda (shared, code 1)",
            },
            "main_body": {
                "address": "0x60bf212",
                "steps": [
                    "ConfigOptions copy via 0x60b9d70 (0x50 bytes)",
                    'find("=", 0, 1) in the value (literal 0x445245)',
                    "found -> 0x6099e70 (the '=' path); not found -> 0x609ba30 (the no-'=' path)",
                ],
            },
            "error_outcome": (
                "The arm itself never synthesizes a verification error: a failure Status is "
                "whatever the callee returned, propagated verbatim. The only arm-level errors "
                "are the two kNotFound messages above."
            ),
        },
        "entries": entries,
        "type_21_count": 0,
        "type_22_count": 15,
        "flags_survey": (
            "Across all 214 mapped entries (#4237 DBOptions 100 + #4263 CFOptions 114), ONLY "
            "type-22 entries carry any of flags bits 0x200/0x400/0x800; none carries 0x800. "
            "The two apparent exceptions (prefix_extractor 0x1100, "
            "memtable_insert_with_hint_prefix_extractor 0x0) are pre-OR immediates: the "
            "type-22 helper forces 0x400 (or $0x4,%ch at 0x6083a99), so stored flags always "
            "have a bit set and the arm always derefs to the object pointer."
        ),
        "construction": {
            "type22_helper": {
                "address": "0x6083a90", "fde": "0x6083a90..0x6083c83",
                "builds": ["prefix_extractor", "memtable_insert_with_hint_prefix_extractor"],
                "parse_pair": {"manager": "0x607d190", "invoker": "0x60809e0"},
                "relocs": ["0x64eda68", "0x64edb70"],
                "flags_force": "or $0x4,%ch at 0x6083a99 (forces 0x400)",
                "call_sites": ["0x608d894", "0x6090205"],
                "call_site_count": 2,
            },
            "db_special_pairs": {
                "statistics": {"parse": ["0x606fa80", "0x60780a0"], "relocs": ["0x64eda58", "0x64eda60"], "load": "initializer 0x60aa2e8/0x60aa31a, saved -0x8d90, reloaded 0x60b0594, stored temp+0x18 at 0x60b0660"},
                "wal_filter": {"parse": ["0x609f250", "0x609fc80"], "relocs": ["0x64edbc0", "0x64edc70"], "load": "xmm7 saved -0x8cc0 at 0x60aa39c, reloaded as xmm1 at 0x60ac4e5, stored temp+0x18 at 0x60ac5ad"},
                "file_checksum_gen_factory": {"parse": ["0x609f370", "0x60a2360"], "relocs": ["0x64edbf8", "0x64edc98"], "load": "xmm5 saved -0x8d50 at 0x60aa348, reloaded as xmm3 at 0x60b046d, stored temp+0x18 at 0x60b0535"},
            },
            "cf_direct_writes": {
                "comparator_verified": "temp -0x3550: offset 8 at +0x00 (0x60900be); +0x18 manager = 0 at 0x60900c9; +0x20 invoker = 0 at 0x60900d4; type/verification packed qword 0x100000016 (type 22, verification 1) read from 0x458f68 into rbx at 0x609007b, stored at +0xa8 via 0x6090137; flags 0x202 at +0xb0 (0x609013e)",
                "table_factory_verified": "temp -0x3550: +0x18=0 at 0x60903ad, +0x20=0 at 0x60903b8; flags 0xc402 at 0x609041b",
                "others": "merge_operator, compaction_filter, compaction_filter_factory, sst_partitioner_factory share the direct-write construction class (census classification 'writes')",
            },
            "cf_factory_builder": {
                "address": "0x607ea10", "fde": "0x607ea10..0x607eb17",
                "zeroing": "pxor %xmm0,%xmm0 then movups stores at 0x607ea1c-0x607ea36 zero +0x18/+0x20",
                "builds": ["memtable", "memtable_factory", "block_based_table_factory", "plain_table_factory"],
            },
        },
        "reachable_entries": [
            "comparator", "merge_operator", "compaction_filter", "compaction_filter_factory",
            "table_factory", "sst_partitioner_factory", "memtable", "memtable_factory",
            "block_based_table_factory", "plain_table_factory",
        ],
        "custom_parse_path_entries": [
            "statistics", "wal_filter", "file_checksum_gen_factory",
            "prefix_extractor", "memtable_insert_with_hint_prefix_extractor",
        ],
        "equals_path": {
            "setter": "0x6099e70", "fde": "0x6099e70..0x609a1a9",
            "config_copy": "0x60b9d70 (0x50 bytes: u32 +0x0, byte +0x4, string +0x8 via 0x60b7cd0, u32 +0x28, byte +0x2c, 16B +0x38, u64 +0x30, u64 +0x48 shared_ptr with refcount bump, GOT 0x64ed290)",
            "steps": [
                "writes Status OK first",
                "value non-empty: find(';', 0); found -> build empty unordered_map on stack (buckets rsp+0x50, count 1, max_load_factor 1.0f), parse via 0x60c1190, propagate its Status; if OK call 0x6097110",
                "0x6097110 tail-calls object vtable slot 0x48 (index 9) = ConfigureOptions (0x609d0e0) with (Status*, field-addr, config-copy, map), propagates",
                "';' not found -> 0x609a0b0: find('=', 0); found -> same map path",
                "neither ';' nor '=': compare object vtable slot 0x40 (index 8) against 0x60956f0 (empty-Status stub); equal -> Status OK and continue, else call slot 0x40 with (Status*, field-addr, config-copy) and propagate",
                "then: config+0x3 == 0 -> OK; else call object vtable slot 0x28 (index 5) = PrepareOptions (0x6095e70) with (Status*, field-addr, config-copy) and propagate",
            ],
            "map_parser": {
                "address": "0x60c1190", "fde": "0x60c1190..0x60c1887",
                "braces": "value starting with '{' and ending with '}' has both stripped before parsing",
                "split": "find_first_of(\"={};\") per pair (literal 0x44b52b); split on ';', then on '='",
                "errors": [
                    {"trigger": "no '=', ';', '{' or '}' in the pair", "code": 4, "message": "Mismatched key value pair, '=' expected", "literal": "0x969140", "length": 39, "site": "0x60c16c0"},
                    {"trigger": "first special char in the pair is not '=' (e.g. ';', '{', '}')", "code": 4, "message": "Unexpected char in key", "literal": "0x44ff0e", "length": 22, "site": "0x60c1710"},
                    {"trigger": "key length 0 (value starts with '=')", "code": 4, "message": "Empty key found", "literal": "0x4362e1", "length": 15, "site": "0x60c1740"},
                ],
                "substr_throw": "std::out_of_range via __throw_out_of_range_fmt at 0x60c1835 (literal 0x43e542 'basic_string::substr') on a bad range",
            },
        },
        "no_equals_path": {
            "forwarder": "0x609ba30", "fde": "0x609ba30..0x609ba76",
            "create_by_name": "0x609b8a0", "fde": "0x609b8a0..0x609ba2a",
            "steps": [
                "calls object vtable slot 0x68 (index 13) = GetOptionName (0x609d980) with (Status*, config-copy, name); return ignored",
                "0x609d980 treats rsi as this, calls *(rsi)->Name() slot 0x70, compares Name() to the input string (strlen + memcmp, '.' check at 0x609da8b)",
                "calls 0x6096f40 with (field+8, stack string, empty SSO string, &stack slot): iterates 0x30-byte records at [field+8] (begin/end pair; StatisticsImpl+0x08 options vector per #4207, 48-byte elements starting with a string); per record builds the name string (SSO-aware) and calls 0x60ba0b0 (nested-key lookup, splits on '.', literal 0x43821e); returns first non-null result or null",
                "null -> Status kNotFound (code 1) 'Could not find option: <name>' (literal 0x43e863, 23 bytes, via 0x61cf670)",
                "else calls 0x609b700 (apply-created)",
            ],
            "apply_created": {
                "address": "0x609b700", "fde": "0x609b700..0x609b869",
                "type_22": "delegate 0x609a740 (FDE 0x609a740..0x609b6f3; internals open)",
                "type_19_or_21_22": "name memcmp loop; on match calls object vtable slot 0x50 (index 10) = ParseOption (0x60986b0)",
                "other_types_no_match": {"code": 1, "message": "Could not find option: <name>", "literal": "0x43e863", "site": "0x609b845"},
            },
        },
        "custom_parse": {
            "function": "0x60809e0", "fde": "0x60809e0..0x6080a71",
            "args": "(Status* out, config-copy, name, value, field-addr via r9)",
            "id_reset": 'name == "id" (size 2, bytes 0x6469) AND value size == 0: resets the shared_ptr at *(field) to null (zeroes 16 bytes, releases control via 0x5d350c0), writes Status OK',
            "delegate": "else calls 0x61ca3d0 (FDE 0x61ca3d0..0x61cb3dc; internals open) with (Status*, config-copy, object-ptr, value)",
            "manager": {"address": "0x607d190", "fde": "0x607d190..0x607d1bd", "op_0": "typeinfo 0x64d3018", "op_1": "copy functor", "other": "0"},
        },
        "config_dtor": {
            "address": "0x5e33fb0", "fde": "0x5e33fb0..0x5e33fea",
            "behavior": "releases shared_ptr at +0x48 via 0x5d350c0, frees +0x8 string buffer if heap",
        },
        "serializer": {
            "address": "0x60bb9a0", "fde": "0x60bb9a0..0x60bbdeb",
            "custom_serialize": "record+0x38 (serialize manager) != 0: call *0x40(%r13) (invoker)",
            "type_dispatch": "type == 22 -> 0x60bbbf0; types 21/22 -> shared body at 0x60bba43; other types -> 0x60bbb78",
            "type_21_22_body": {
                "flags_gate": "flags %ah bits 0x2/0x4/0x8 set -> 0x60bbcb0/0x60bbc70: deref field; null object -> Status OK, emit nothing; non-null -> main body 0x60bba66",
                "main_body": "ConfigOptions copy (0x60b9d70); _M_replace output with ';' (literal 0x43d5c7); 0x60971c0 serializes the object's options into the string; append to output; Status OK",
                "name_emission": "0x60bbc3e: calls object vtable slot 0x78 (index 15) to get the name string, appends it to the output, Status OK",
                "flags_0x8000_branch": "0x60bbc15: flags bit 0x8000 not set -> main body; ConfigOptions+0x28 == 2 -> main body; ConfigOptions+0x4 == 0 -> name emission; flags bit 0x100 not set -> OK emit nothing, else name emission",
                "null_object": "0x60bbc85: flags bit 0x100 set -> assign the .bss string at 0x6508980 into the output, OK; not set and ConfigOptions+0x4 != 0 -> assign '' (0x4376fd) into the output, OK; else the 0x6508980 string",
            },
            "other_types": "0x60bbb78: ConfigOptions+0x4 == 0 -> call 0x60ba600 helper; true -> OK; false -> kNotSupported (code 3) 'Cannot serialize option: <name>' (literal 0x4373cf, 25 bytes); ConfigOptions+0x4 != 0 and flags bit 0x100 not set -> OK emit nothing",
        },
        "statisticsimpl_vtable": {
            "base": "0x64d2d88", "slots": 32, "source": "#4207",
            "used_slots": {
                "0x28": "PrepareOptions 0x6095e70", "0x40": "empty-Status stub 0x60956f0",
                "0x48": "ConfigureOptions 0x609d0e0", "0x50": "ParseOption 0x60986b0",
                "0x68": "GetOptionName 0x609d980", "0x70": "Name 'BasicStatistics' 0x606fa20",
                "0x78": "GetId 0x5d32a30",
            },
        },
        "status_ctor": "0x61cf670",
        "literals": [
            {"address": "0x43e863", "length": 23, "text": "Could not find option: "},
            {"address": "0x43fb8a", "length": 29, "text": "Could not find configurable: "},
            {"address": "0x44e056", "length": 21, "text": "Could not find option"},
            {"address": "0x4373cf", "length": 25, "text": "Cannot serialize option: "},
            {"address": "0x43d5c7", "length": 1, "text": ";"},
            {"address": "0x4376fd", "length": 0, "text": ""},
            {"address": "0x445245", "length": 1, "text": "="},
            {"address": "0x44b52b", "length": 4, "text": "={};"},
            {"address": "0x969140", "length": 39, "text": "Mismatched key value pair, '=' expected"},
            {"address": "0x44ff0e", "length": 22, "text": "Unexpected char in key"},
            {"address": "0x4362e1", "length": 15, "text": "Empty key found"},
            {"address": "0x43e542", "length": 19, "text": "basic_string::substr"},
        ],
        "excerpts": excerpts,
        "open_unknowns": [
            "C++ enum names for verification 0..5 (binary pins behavior, not names; #4311 open unknown 2, still open)",
            "0x609a740 internals (the type-22 apply delegate called by 0x609b700)",
            "0x61ca3d0 internals (the delegate the custom parse 0x60809e0 calls for non-'id' values)",
            "0x60971c0 internals (the serializer's object-options helper)",
            "ConfigOptions+0x4 and +0x28 C++ field names (the serializer's gates)",
            "The .bss string at 0x6508980 emitted when serializing a null type-22 object",
            "Whether any OptionTypeInfo map beyond DBOptions/CFOptions has type-21/22 entries (only the two maps were censused)",
            "0x60ba0b0 nested-key lookup internals (cited from #4263)",
            "Record+0xb8 as the name string (unverified inference)",
        ],
    }


def main():
    records = build()
    out = os.path.join(HERE, "records.json")
    with open(out, "w") as f:
        json.dump(records, f, indent=1)
        f.write("\n")
    print("wrote %s (%d excerpts, %d entries)" % (out, len(records["excerpts"]), len(records["entries"])))


if __name__ == "__main__":
    main()
