#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-filter-policy-registrations-115/gen_records.py

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
    "work_item": "RE-001-filter-policy-registrations-115",
    "question": (
        "Which named FilterPolicy factories does node #115 register at "
        "startup -- the creators #4458 left as an open unknown ('the "
        "creator routines themselves are not pinned') -- and what does "
        "each creator build? Resolves #4458's open unknowns 'registered "
        "FilterPolicy creators' and 'the registrar's base names before "
        "the \":false\"/\":true\" suffixes'."
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4458,
        "open_unknowns": [
            "registered FilterPolicy creators",
            "the registrar's base names before the ':false'/':true' suffixes",
        ],
        "answer": (
            "The builtin registrar 0x6137fe0 registers NINE FilterPolicy "
            "factories under the single map key 'FilterPolicy': one inlined "
            "('rocksdb.BuiltinBloomFilter' -> ReadOnlyBuiltinFilterPolicy) "
            "and eight through the per-factory registrar 0x6137810. The "
            "base names are 'bloomfilter' (full name "
            "'rocksdb.BloomFilter') and 'ribbonfilter' (full name "
            "'rocksdb.RibbonFilter'), plus the three internal names "
            "'rocksdb.internal.LegacyBloomFilter', "
            "'rocksdb.internal.FastLocalBloomFilter' and "
            "'rocksdb.internal.Standard128RibbonFilter'. Every creator "
            "takes (record, name, &slot, &string), splits the requested "
            "name on ':' (0x61d2380) and parses the second part as a double "
            "(0x61d1e30), then builds its policy object, stores it in the "
            "slot and releases the old object through its vtable slot 1. "
            "The ':true'-suffixed ribbon factory is the exception in the "
            "table: it builds a 0x40-byte BloomFilterPolicy (vtable "
            "0x64d4f20), not a RibbonFilterPolicy -- the plain and ':' "
            "ribbon factories build 0x48-byte RibbonFilterPolicy objects "
            "(vtable 0x64d52e0)."
        ),
    },
    "registrar_0x6137fe0": {
        "fde": "0x6137fe0..0x61389e4",
        "name": (
            "RegisterBuiltinFilterPolicies (anonymous namespace): the "
            "mangled lambda typeinfos of its nine managers all name "
            "'...29RegisterBuiltinFilterPoliciesERNS_13ObjectLibraryE...'"
        ),
        "sole_caller": "0x6138a48 in the pthread_once init 0x6138a10 (cited)",
        "signature": "(ObjectLibrary* library)",
        "registrations": [
            {
                "index": 1,
                "entry_name": "rocksdb.BuiltinBloomFilter",
                "pattern_parts": ["rocksdb.BuiltinBloomFilter"],
                "option_elements": [],
                "manager": "0x612d2a0",
                "invoker": "0x612de10",
                "call_site": "inlined in 0x6137fe0; register call 0x613818f",
                "builds": "rocksdb::ReadOnlyBuiltinFilterPolicy, 0x20 bytes, vtable 0x64d4af0",
            },
            {
                "index": 2,
                "entry_name": "bloomfilter",
                "pattern_parts": ["bloomfilter", "rocksdb.BloomFilter"],
                "option_elements": [],
                "manager": "0x612d2d0",
                "invoker": "0x6134130",
                "call_site": "0x613825f -> 0x6137810",
                "builds": "rocksdb::BloomFilterPolicy, 0x40 bytes, vtable 0x64d4f20",
            },
            {
                "index": 3,
                "entry_name": "bloomfilter",
                "pattern_parts": ["bloomfilter", "rocksdb.BloomFilter"],
                "option_elements": [{":false": "tag 2"}],
                "manager": "0x612d300",
                "invoker": "0x61338a0",
                "call_site": "0x6138356 -> 0x6137810",
                "builds": "rocksdb::BloomFilterPolicy, 0x40 bytes, vtable 0x64d4f20",
            },
            {
                "index": 4,
                "entry_name": "ribbonfilter",
                "pattern_parts": ["ribbonfilter", "rocksdb.RibbonFilter"],
                "option_elements": [{":true": "tag 2"}],
                "manager": "0x612d330",
                "invoker": "0x6134010",
                "call_site": "0x6138450 -> 0x6137810",
                "builds": (
                    "rocksdb::BloomFilterPolicy, 0x40 bytes, vtable "
                    "0x64d4f20 -- NOT a RibbonFilterPolicy (see observations)"
                ),
            },
            {
                "index": 5,
                "entry_name": "ribbonfilter",
                "pattern_parts": ["ribbonfilter", "rocksdb.RibbonFilter"],
                "option_elements": [],
                "manager": "0x612d360",
                "invoker": "0x6133ef0",
                "call_site": "0x61384e3 -> 0x6137810",
                "builds": "rocksdb::RibbonFilterPolicy, 0x48 bytes, vtable 0x64d52e0",
            },
            {
                "index": 6,
                "entry_name": "ribbonfilter",
                "pattern_parts": ["ribbonfilter", "rocksdb.RibbonFilter"],
                "option_elements": [{":": "tag 3, length 1"}],
                "manager": "0x612d390",
                "invoker": "0x6133dc0",
                "call_site": "0x61385eb -> 0x6137810",
                "builds": "rocksdb::RibbonFilterPolicy, 0x48 bytes, vtable 0x64d52e0",
            },
            {
                "index": 7,
                "entry_name": "rocksdb.internal.LegacyBloomFilter",
                "pattern_parts": ["rocksdb.internal.LegacyBloomFilter"],
                "option_elements": [],
                "manager": "0x612d3c0",
                "invoker": "0x61339e0",
                "call_site": "0x6138662 -> 0x6137810",
                "builds": (
                    "rocksdb::test::LegacyBloomFilterPolicy, 0x40 bytes, "
                    "vtable 0x64d4fe0"
                ),
            },
            {
                "index": 8,
                "entry_name": "rocksdb.internal.FastLocalBloomFilter",
                "pattern_parts": ["rocksdb.internal.FastLocalBloomFilter"],
                "option_elements": [],
                "manager": "0x612d3f0",
                "invoker": "0x6133b30",
                "call_site": "0x61386c9 -> 0x6137810",
                "builds": (
                    "rocksdb::test::FastLocalBloomFilterPolicy, 0x40 bytes, "
                    "vtable 0x64d50a0"
                ),
            },
            {
                "index": 9,
                "entry_name": "rocksdb.internal.Standard128RibbonFilter",
                "pattern_parts": ["rocksdb.internal.Standard128RibbonFilter"],
                "option_elements": [],
                "manager": "0x612d420",
                "invoker": "0x6133c80",
                "call_site": "0x6138730 -> 0x6137810",
                "builds": (
                    "rocksdb::test::Standard128RibbonFilterPolicy, 0x40 "
                    "bytes, vtable 0x64d5160"
                ),
            },
        ],
        "map_key": (
            "every registration uses the map key 'FilterPolicy' (literal "
            "0x44d20e): the inlined registration calls the register helper "
            "0x5fd1da0 at 0x613818f, and 0x6137810 calls it at 0x6137b87"
        ),
        "frame": "0x108 bytes, stack canary at 0xf8(%rsp)",
    },
    "per_factory_registrar_0x6137810": {
        "fde": "0x6137810..0x6137d58",
        "signature": (
            "(ObjectLibrary* library, const PatternEntry& spec, "
            "const FactoryRecord& factory)"
        ),
        "e8_callers": [
            "0x613825f", "0x6138356", "0x6138450", "0x61384e3",
            "0x61385eb", "0x6138662", "0x61386c9", "0x6138730",
        ],
        "steps": [
            "clones the factory record's functor through its manager with "
            "op 2 into 0x40(%rsp) (a no-op for the stateless creator "
            "lambdas) and copies the {manager, invoker} pair to 0x50(%rsp)",
            "allocates a fresh 0x70-byte PatternEntry (vtable 0x64d8ed0) "
            "and deep-copies the spec into it: the name string at +0x08, "
            "the size at +0x28, the names vector at +0x30..+0x40, the flag "
            "byte at +0x48, the accumulated length at +0x50, and the "
            "option-elements vector at +0x58..+0x68",
            "allocates a fresh 0x30-byte FactoryEntry record (vtable "
            "0x64d53a0) with +0x08 = the new entry, +0x10..+0x20 = the "
            "cloned functor, +0x20 = manager, +0x28 = invoker",
            "locks the library mutex, builds the 'FilterPolicy' name "
            "string, calls the register helper 0x5fd1da0 at 0x6137b87 "
            "with (library+0x28, name), then appends the new record to "
            "the returned map node's record list",
        ],
        "frame": "0x78 bytes, stack canary at 0x68(%rsp)",
    },
    "pattern_entry_0x70_bytes": {
        "vtable": "0x64d8ed0 (typeinfo N7rocksdb13ObjectLibrary12PatternEntryE)",
        "layout": {
            "+0x00": "vtable pointer (0x64d8ed0)",
            "+0x08": "std::string: the entry name (e.g. 'bloomfilter')",
            "+0x28": "the name string's size, duplicated",
            "+0x30..+0x40": "vector<string>: the pattern parts (the full name, e.g. 'rocksdb.BloomFilter')",
            "+0x48": "flag byte (1 in the inlined builtin registration)",
            "+0x50": "accumulated name length (0xd0(%rsp) in the registrar)",
            "+0x58..+0x68": "vector<{string, tag}>: the option elements (':false'/':true' tag 2, ':' tag 3)",
        },
        "vtable_slots": {
            "0": "0x5ff2030 (destroy)",
            "1": "0x5ff2150",
            "2": "0x61f8670 (Matches -- forwards to PatternEntry Matches, cited)",
            "3": "0x61f8120",
            "4": "0x0 (trailing zero slot)",
        },
        "built_by": (
            "the entry-builder helper 0x6134be0 (cited): 8 callers, all in "
            "0x6137fe0; it fills the entry with the vtable, the name "
            "string from its C-string argument, and a ':' option element "
            "(tag 4)"
        ),
    },
    "factory_entry_0x30_bytes": {
        "vtable": "0x64d53a0 (typeinfo N7rocksdb13ObjectLibrary12FactoryEntryIKNS_12FilterPolicyEEE)",
        "layout": {
            "+0x00": "vtable pointer (0x64d53a0)",
            "+0x08": "pointer to the 0x70-byte PatternEntry",
            "+0x10..+0x20": "functor (16 bytes; zeroes for the stateless creator lambdas)",
            "+0x20": "manager function pointer",
            "+0x28": "invoker (creator) function pointer",
        },
        "vtable_slots": {
            "0": "0x612d450",
            "1": "0x612e010",
            "2": "0x612d4e0",
            "3": "0x612d4f0",
            "4": "0x0 (trailing zero slot)",
        },
    },
    "creators": {
        "common_contract": (
            "each invoker takes (record, name, &slot, &string); the "
            "dispatch (#4458) invokes it through the record's +0x18 "
            "invoker. The invoker stores the new raw object pointer at "
            "the slot, releases the previous object through its vtable "
            "slot 1 when non-null, and returns the new object. Eight of "
            "the nine split the requested name on ':' with 0x61d2380 and "
            "parse the second part as a double with 0x61d1e30; the "
            "builtin creator 0x612de10 does no parsing at all."
        ),
        "0x612de10": {
            "fde": "0x612de10..0x612de51",
            "builds": "rocksdb::ReadOnlyBuiltinFilterPolicy",
            "size": "0x20 bytes, zeroed",
            "vtable": "0x64d4af0 (typeinfo N7rocksdb27ReadOnlyBuiltinFilterPolicyE)",
            "vtable_slots": "0: 0x61321a0 (Name), 1: 0x61321c0 (CreateFilter); slots 2..13, 19 (0x612d290) and 21 (0x61318a0) shared; per-class slots 14..21: 0x6130150/0x5d32a30/0x612fb20/0x5d2ca00/0x5d2ca10/0x612cf60; slot 22 trailing zero",
            "parse": "none -- ignores the requested name entirely",
            "ctor": "none -- the object is zeroed and only the vtable is stored",
        },
        "0x6134130": {
            "fde": "0x6134130..0x6134238",
            "builds": "rocksdb::BloomFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d4f20 (typeinfo N7rocksdb17BloomFilterPolicyE)",
            "vtable_slots": "0: 0x6132150 (Name), 1: 0x6132170 (CreateFilter); slots 2..13, 19 and 21 shared; per-class slots 14..21: 0x6130190/0x6130bc0/0x61300d0/0x5d2ca00/0x61301b0/0x6136510; slot 22 trailing zero",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30), preserved in xmm0 across the allocation",
            "ctor": "0x6130160 (calls the shared base ctor 0x612fc30, then stores vtable 0x64d4f20)",
        },
        "0x61338a0": {
            "fde": "0x61338a0..0x61339a8",
            "builds": "rocksdb::BloomFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d4f20 (typeinfo N7rocksdb17BloomFilterPolicyE)",
            "parse": "same ':'-split + double parse as 0x6134130",
            "ctor": "0x6130160",
            "note": "same body shape as 0x6134130; the two differ only in the registered option element (':false', tag 2)",
        },
        "0x6134010": {
            "fde": "0x6134010..0x61340fc",
            "builds": "rocksdb::BloomFilterPolicy -- NOT RibbonFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d4f20 (typeinfo N7rocksdb17BloomFilterPolicyE)",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30), preserved in xmm0",
            "ctor": (
                "0x6131df0 with edi=1: allocates 0x40 bytes and calls "
                "0x6130160; the edi=1 argument is ignored by 0x6131df0 "
                "(it overwrites edi with 0x40 immediately)"
            ),
        },
        "0x6133ef0": {
            "fde": "0x6133ef0..0x6133fdc",
            "builds": "rocksdb::RibbonFilterPolicy",
            "size": "0x48 bytes",
            "vtable": "0x64d52e0 (typeinfo N7rocksdb18RibbonFilterPolicyE)",
            "vtable_slots": "0: 0x6132010 (Name), 1: 0x6132030 (CreateFilter); slots 2..13, 19 and 21 shared; per-class slots 14..21: 0x6131e80/0x6130d90/0x61300d0/0x5d2ca00/0x6131ea0/0x6136560; slot 22 trailing zero",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30)",
            "ctor": (
                "0x6131ec0 with edi=0: allocates 0x48 bytes and calls "
                "0x6131e40 (stores edi at +0x40, calls the shared base "
                "ctor 0x612fc30, stores vtable 0x64d52e0)"
            ),
        },
        "0x6133dc0": {
            "fde": "0x6133dc0..0x6133ebc",
            "builds": "rocksdb::RibbonFilterPolicy",
            "size": "0x48 bytes",
            "vtable": "0x64d52e0 (typeinfo N7rocksdb18RibbonFilterPolicyE)",
            "parse": (
                "':'-split (0x61d2380) + double of the second part "
                "(0x61d1e30) + an integer parsed by 0x61d1b90 from the "
                "third part"
            ),
            "ctor": (
                "0x6131ec0 with edi = the 0x61d1b90 result: allocates "
                "0x48 bytes and calls 0x6131e40, which stores that int "
                "at +0x40"
            ),
        },
        "0x61339e0": {
            "fde": "0x61339e0..0x6133af8",
            "builds": "rocksdb::test::LegacyBloomFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d4fe0 (typeinfo N7rocksdb4test23LegacyBloomFilterPolicyE)",
            "vtable_slots": "0: 0x6132100 (Name), 1: 0x6132120 (CreateFilter); slots 2..13, 19 and 21 shared; per-class slots 14..21: 0x6131530/0x6130a20/0x61300d0/0x5d2ca00/0x5d2ca10/0x61302b0; slot 22 trailing zero",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30), preserved in xmm0",
            "ctor": "the shared base ctor 0x612fc30 directly, then the invoker stores vtable 0x64d4fe0 itself",
        },
        "0x6133b30": {
            "fde": "0x6133b30..0x6133c48",
            "builds": "rocksdb::test::FastLocalBloomFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d50a0 (typeinfo N7rocksdb4test26FastLocalBloomFilterPolicyE)",
            "vtable_slots": "0: 0x61320b0 (Name), 1: 0x61320d0 (CreateFilter); slots 2..13, 19 and 21 shared; per-class slots 14..21: 0x6131550/0x6130a20/0x61300d0/0x5d2ca00/0x5d2ca10/0x6136540; slot 22 trailing zero",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30), preserved in xmm0",
            "ctor": "the shared base ctor 0x612fc30 directly, then the invoker stores vtable 0x64d50a0 itself",
        },
        "0x6133c80": {
            "fde": "0x6133c80..0x6133d98",
            "builds": "rocksdb::test::Standard128RibbonFilterPolicy",
            "size": "0x40 bytes",
            "vtable": "0x64d5160 (typeinfo N7rocksdb4test29Standard128RibbonFilterPolicyE)",
            "vtable_slots": "0: 0x6132060 (Name), 1: 0x6132080 (CreateFilter); slots 2..13, 19 and 21 shared; per-class slots 14..21: 0x6131570/0x6130a20/0x61300d0/0x5d2ca00/0x5d2ca10/0x6135ef0; slot 22 trailing zero",
            "parse": "':'-split (0x61d2380) + double of the second part (0x61d1e30), preserved in xmm0",
            "ctor": "the shared base ctor 0x612fc30 directly, then the invoker stores vtable 0x64d5160 itself",
        },
    },
    "managers": {
        "shape": (
            "nine 0x2d-byte functions at 0x612d2a0 + k*0x30, byte-identical "
            "except the op-0 lea rel32: op 0 stores the lambda typeinfo "
            "into *rdi, op 1 stores rsi into *rdi, op 2 and op 3 return 0 "
            "(no-op: the creator lambdas are stateless, so clone and "
            "destroy do nothing). The registrar calls op 2 (clone) and "
            "op 3 (destroy); the dispatch calls op 2 (clone) and op 3 "
            "(destroy) on the matched record."
        ),
        "typeinfos": [
            "0x612d2a0 -> 0x64d4a20",
            "0x612d2d0 -> 0x64d4a30",
            "0x612d300 -> 0x64d4a40",
            "0x612d330 -> 0x64d4a50",
            "0x612d360 -> 0x64d4a60",
            "0x612d390 -> 0x64d4a70",
            "0x612d3c0 -> 0x64d4a80",
            "0x612d3f0 -> 0x64d4a90",
            "0x612d420 -> 0x64d4aa0",
        ],
        "typeinfo_name": (
            "all nine name the same lambda type: "
            "'*ZN7rocksdb12_GLOBAL__N_1L29RegisterBuiltinFilterPoliciesE"
            "RNS_13ObjectLibraryERKNSt7__cxx1112basic_stringIcSt11char_"
            "traitsIcESaIcEEEEUlSA_PSt10unique_ptrIKNS_12FilterPolicyESt"
            "14default_deleteISD_EEPS8' -- a lambda taking (const "
            "std::string&, unique_ptr<const FilterPolicy>*) inside "
            "RegisterBuiltinFilterPolicies"
        ),
        "e8_callers": "none -- managers are reached only through the record's +0x10 manager pointer",
    },
    "name_literals": {
        "0x44481b": "rocksdb.BuiltinBloomFilter (lea sites 0x612d294, 0x612fc24, 0x6130144)",
        "0x43c831": "bloomfilter (lea site 0x6130184)",
        "0x44ff67": "rocksdb.BloomFilter (lea site 0x61301a4)",
        "0x43e8eb": "ribbonfilter (lea site 0x6131e74)",
        "0x4466f4": "rocksdb.RibbonFilter (lea site 0x6131e94)",
        "0x442ac3": ":false (lea sites 0x6130c06, 0x61382e6)",
        "0x4384f5": ":true (lea site 0x61383e0)",
        "0x95dea0": "rocksdb.internal.LegacyBloomFilter (lea site 0x6131524)",
        "0x965bc0": "rocksdb.internal.FastLocalBloomFilter (lea site 0x6131544)",
        "0x96a630": "rocksdb.internal.Standard128RibbonFilter (lea site 0x6131564)",
        "0x44d20e": "FilterPolicy (lea sites 0x6136d62, 0x6136eb5, 0x6136fbc, 0x6137b6c, 0x6138179 -- as in #4458)",
    },
    "observations": [
        "The ':true' ribbon factory builds a BloomFilterPolicy. The "
        "plain ribbon factory (0x6133ef0, edi=0) and the ':' ribbon "
        "factory (0x6133dc0, edi = the 0x61d1b90 int parse) both build "
        "0x48-byte RibbonFilterPolicy objects through 0x6131ec0 -> "
        "0x6131e40, but the ':true' factory (0x6134010, edi=1) goes "
        "through 0x6131df0 -> 0x6130160 and builds a 0x40-byte "
        "BloomFilterPolicy instead. Whether upstream intends ':true' to "
        "select a Bloom policy is an open unknown; the bodies are "
        "pinned, the intent is not.",
        "The tiny name function 0x612d290..0x612d29c returns "
        "'rocksdb.BuiltinBloomFilter' and has no E8 caller binary-wide "
        "-- but it is reachable: it occupies slot 19 of all six policy "
        "vtables. The same literal is also returned by 0x6130140, which "
        "the registrar does call (lea 0x6130144).",
        "The shared base ctor 0x612fc30 itself references "
        "'rocksdb.BuiltinBloomFilter' (lea at 0x612fc24, inside the "
        "0x612fc20..0x612fc2c FDE) -- cited, not pinned.",
        "All six policy vtables have 23 slots (0..22, slot 22 a trailing "
        "zero). Slots 0/1 (Name/CreateFilter) and 14..21 differ per "
        "class; slots 2..13 are the shared FilterPolicy base slots "
        "(0x609d760/0x609dc40/0x5d32560/0x6095e70/0x6096790/0x5d2e090/"
        "0x60956f0/0x609d0e0/0x60986b0/0x6095710/0x609de80/0x609d980); "
        "slot 19 is the shared 0x612d290 and slot 21 the shared "
        "0x61318a0.",
        "The PatternEntry option elements carry tags: ':false'/':true' "
        "are tag 2, ':' is tag 3, and the entry-builder 0x6134be0 adds a "
        "':' element with tag 4. The tag meanings are not pinned -- "
        "Matches (0x61f8670) is cited, not traced.",
    ],
    "open_unknowns": [
        "the exact matching semantics of PatternEntry Matches (0x61f8670): how the entry name, pattern parts and option-element tags decide whether a requested name selects a factory",
        "the exact parse semantics of the helpers 0x61d2380 (':'-split), 0x61d1e30 (double parse) and 0x61d1b90 (int parse), including failure modes on malformed names",
        "the field layout of the 0x40-byte BloomFilterPolicy / 0x48-byte RibbonFilterPolicy objects built by the shared base ctor 0x612fc30 (where the parsed double lands, what +0x40 holds beyond the Ribbon int)",
        "whether the ':true' ribbon factory building a BloomFilterPolicy is upstream intent or a registration quirk",
        "the Name()/CreateFilter() bodies behind the per-class vtable slots 0/1 (0x61321a0/0x61321c0, 0x6132150/0x6132170, 0x6132100/0x6132120, 0x61320b0/0x61320d0, 0x6132060/0x6132080, 0x6132010/0x6132030)",
        "the tag meanings of the PatternEntry option elements (2, 3, 4) and the entry +0x48 flag byte / +0x50 accumulated length semantics",
        "the remaining #4458 open unknowns not touched here: libraries vector element second qword; library +0x08..+0x27 fields; map value owning type; control-block vtable slots 0..4; dispatcher 0x6137290 internals; wrapper 0x60dafb0's caller",
    ],
}


def main() -> None:
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2) + "\n")
    print(f"wrote records.json ({len(json.dumps(RECORDS))} bytes)")


if __name__ == "__main__":
    main()
