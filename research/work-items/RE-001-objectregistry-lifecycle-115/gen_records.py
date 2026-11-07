"""Generate records.json for the RE-001-objectregistry-lifecycle-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-lifecycle-115/gen_records.py

The census entries, relocation rows and caller lists are
re-derived from a fresh census run (census.py in this packet);
the roles, layout and literals are the pinned findings from
the verbatim excerpts. The JSON holds semantic records only:
no per-instruction mnemonic list. Instruction-level detail
lives in the raw objdump excerpts.
"""

import json
from pathlib import Path

import census

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CALLER_NOTES = {
    0x5FF99D3: "big registry method 0x5ff88c0",
    0x61F9060: "add-library grow path 0x61f8dc0",
    0x61F922F: "reg-ctor 0x61f91b0",
    0x6206C78: "TTL register grow path 0x62069f0",
    0x61F8D3C: "add-library landing pad 0x61f8d12",
    0x61F81E6: "rec-destroy self 0x61f81d0",
    0x61F87C3: "cb-dispose inline 0x61f8760",
    0x61F9150: "ctor landing pad 0x61f913e",
    0x61F9199: "ctor landing pad 0x61f913e",
    0x61F9253: "reg-ctor registrar loop 0x61f91b0",
    0x61F9380: "reg-getter init path 0x61f92b0",
    0x5FF88FC: "big registry method 0x5ff88c0",
    0x61F9420: "clone 0x61f9400",
    0x6206A3D: "TTL register 0x62069f0",
    0x60BB8F0: "function 0x60bb890 (identity not pinned)",
    0x6202DF2: "function 0x6202da0 (identity not pinned)",
}


def annotate(sites):
    out = []
    for site in sites:
        note = CALLER_NOTES.get(site)
        out.append("%#x (%s)" % (site, note) if note else "%#x" % site)
    return out


def main():
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()

    targets = {}
    for target in sorted(census.TARGETS):
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        targets["%#x" % target] = {
            "calls": len(calls),
            "jumps": len(jumps),
            "leas": len(leas),
            "qwords": len(census.qwords(data, target)),
            "relative": len([o for o, a in relocs.items() if a == target]),
        }

    rows = []
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        if line.strip():
            rows.append(line)
    reloc_rows = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        reloc_rows.append({
            "offset": int(parts[0], 16),
            "addend": int(parts[3], 16),
        })

    def callers(target):
        return annotate(census.scan(sites, target)[0])

    def leas(target):
        return annotate(sites.get(target, ([], [], []))[2])

    records = {
        "target": {
            "artifact": "work/hl-node-115.bin",
            "sha256": DIGEST,
            "node": 115,
        },
        "work_item": "RE-001-objectregistry-lifecycle-115",
        "task": "RE-001",
        "question": (
            "How does the node #115 ObjectRegistry live and die: "
            "its control block, its 0xc0-byte layout, construction "
            "from the default library plus the global registrar map, "
            "AddLibrary registration, the singleton getter, the "
            "clone that links its parent to the singleton, the TTL "
            "registration, and the teardown order?"),
        "registry": {
            "object_size": 0xC0,
            "layout": [
                {"offset": 0x00, "size": 0x18,
                 "field": "vector<shared_ptr<ObjectLibrary>> libraries",
                 "note": "begin +0x00, end +0x08, capacity +0x10; "
                         "element {object +0x00, control block +0x08}"},
                {"offset": 0x18, "size": 0x18,
                 "field": "vector<std::string> names",
                 "note": "begin +0x18, end +0x20, capacity +0x28; "
                         "element 0x20 bytes"},
                {"offset": 0x30, "size": 0x30,
                 "field": "std::map<std::string, std::weak_ptr<...>> registry",
                 "note": "key-compare +0x30, RB header +0x38: color "
                         "+0x38 = 0, parent/root +0x40, left +0x48 = "
                         "&header, right +0x50 = &header, node_count "
                         "+0x58 = 0 when empty"},
                {"offset": 0x60, "size": 0x10,
                 "field": "shared_ptr<ObjectRegistry> parent",
                 "note": "null in the singleton; the clone stores "
                         "the singleton here"},
                {"offset": 0x70, "size": 0x28,
                 "field": "40 bytes, unidentified",
                 "note": "OPEN UNKNOWN: zeroed by the ctor and the "
                         "clone, never read or written by any pinned "
                         "routine, trivially destructible (dispose "
                         "does not touch it); possibly a second mutex "
                         "or plain data"},
                {"offset": 0x98, "size": 0x28,
                 "field": "pthread_mutex_t",
                 "note": "zero-initialised (PTHREAD_MUTEX_INITIALIZER); "
                         "locked by AddLibrary, the TTL registration "
                         "and the big registry method 0x5ff88c0"},
            ],
            "map_node": {
                "size": 0x50,
                "layout": [
                    {"offset": 0x00, "field": "color"},
                    {"offset": 0x08, "field": "parent"},
                    {"offset": 0x10, "field": "left"},
                    {"offset": 0x18, "field": "right"},
                    {"offset": 0x20, "size": 0x20,
                     "field": "std::string key (ptr +0x20, size +0x28, "
                              "SSO buffer +0x30)"},
                    {"offset": 0x40, "size": 0x10,
                     "field": "std::weak_ptr value (object +0x40, "
                              "control block +0x48)"},
                ],
            },
            "registrar_node": {
                "size": 0x48,
                "layout": [
                    {"offset": 0x00, "field": "_M_nxt"},
                    {"offset": 0x08, "size": 0x20,
                     "field": "std::string name"},
                    {"offset": 0x28, "size": 0x20,
                     "field": "std::function creator (functor +0x28, "
                              "manager +0x38, invoker +0x40)"},
                ],
                "map": "global registrar unordered_map at 0x6509540; "
                       "empty after static init (buckets = self+0x30, "
                       "bucket_count 1, before_begin 0, element_count 0, "
                       "max_load_factor 1.0, next_resize 0)",
            },
        },
        "control_block": {
            "vtable": 0x64D8F00,
            "typeinfo": (
                "St23_Sp_counted_ptr_inplace"
                "IN7rocksdb14ObjectRegistryESaIvE"
                "LN9__gnu_cxx12_Lock_policyE2EE"),
            "typeinfo_addr": 0x97FC20,
            "block_size": 0xD0,
            "header_size": 0x10,
            "object_size": 0xC0,
            "fresh_counts": 0x100000001,
            "packed_counts_global": 0x459B20,
            "selector": 0x64ED290,
            "selector_note": "byte at 0x64ed290: 0 selects `lock xadd`, "
                             "nonzero selects a plain `addl` for every "
                             "shared_ptr count update",
            "slots": [
                {"slot": 0, "addr": 0x61F8130, "name": "D1",
                 "role": "ret; the object is inside the block, so "
                         "there is nothing to delete"},
                {"slot": 1, "addr": 0x61F8140, "name": "D0",
                 "role": "operator delete(block, 0xd0)"},
                {"slot": 2, "addr": 0x61F8760, "name": "_M_dispose",
                 "role": "destroy the ObjectRegistry: release the "
                         "parent shared_ptr, destroy the map tree, "
                         "destroy the names vector, destroy the "
                         "libraries vector"},
                {"slot": 3, "addr": 0x61F8170, "name": "_M_destroy",
                 "role": "operator delete(block, 0xd0)"},
                {"slot": 4, "addr": 0x61F8180, "name": "_M_get_deleter",
                 "role": "return this+0x10 iff the argument typeinfo "
                         "is _Sp_make_shared_tag; `*`-prefixed names "
                         "return null; otherwise strcmp against the "
                         "control-block typeinfo name"},
            ],
            "excerpt": "cb-dispose-61f8760.objdump.txt",
        },
        "object_registry_cb_vtable": {
            "vtable": 0x64D8F00,
            "typeinfo": (
                "St23_Sp_counted_ptr_inplace"
                "IN7rocksdb14ObjectRegistryESaIvE"
                "LN9__gnu_cxx12_Lock_policyE2EE"),
            "slots": [
                {"slot": 0, "addr": 0x61F8130},
                {"slot": 1, "addr": 0x61F8140},
                {"slot": 2, "addr": 0x61F8760},
                {"slot": 3, "addr": 0x61F8170},
                {"slot": 4, "addr": 0x61F8180},
            ],
        },
        "cb_d1": {
            "addr": 0x61F8130, "fde": "0x61f8130..0x61f8135",
            "role": "Control-block D1: endbr64; ret. The registry "
                    "object lives inside the 0xd0 make-shared block, "
                    "so deleting the object is a no-op.",
            "calls": 0, "callers": [],
            "excerpt": "cb-d1-61f8130.objdump.txt",
        },
        "cb_d0": {
            "addr": 0x61F8140, "fde": "0x61f8140..0x61f814e",
            "role": "Control-block D0: operator delete(block, 0xd0).",
            "calls": 0, "callers": [],
            "excerpt": "cb-d0-61f8140.objdump.txt",
        },
        "cb_dispose": {
            "addr": 0x61F8760, "fde": "0x61f8760..0x61f89db",
            "role": "Control-block _M_dispose: (1) release the "
                    "parent shared_ptr at +0x60 (fast path (1,1) "
                    "inlines dispose+destroy; the slow last-use path "
                    "calls 0x5d35070); (2) destroy the map tree rooted "
                    "at +0x40 with the rec-destroy loop; (3) destroy "
                    "the names vector at +0x18 (per-string heap free "
                    "plus buffer free); (4) destroy the libraries "
                    "vector at +0x00 (per-element shared_ptr release "
                    "plus buffer free via a tail jump to _ZdlPvm).",
            "calls": 0, "callers": [],
            "excerpt": "cb-dispose-61f8760.objdump.txt",
        },
        "cb_destroy": {
            "addr": 0x61F8170, "fde": "0x61f8170..0x61f817e",
            "role": "Control-block _M_destroy: operator delete(block, 0xd0).",
            "calls": 0, "callers": [],
            "excerpt": "cb-destroy-61f8170.objdump.txt",
        },
        "cb_getdeleter": {
            "addr": 0x61F8180, "fde": "0x61f8180..0x61f81c7",
            "role": "Control-block _M_get_deleter: return this+0x10 "
                    "iff the argument typeinfo is _Sp_make_shared_tag "
                    "(GOT 0x64ecdc8 -> 0x96cb48); `*`-prefixed names "
                    "return null; otherwise strcmp the argument name "
                    "against the string at 0x96c770.",
            "calls": 0, "callers": [],
            "excerpt": "cb-getdeleter-61f8180.objdump.txt",
        },
        "rec_destroy": {
            "addr": 0x61F81D0, "fde": "0x61f81d0..0x61f8271",
            "role": "Recursive map-node destroy: recurse the right "
                    "child (+0x18); release the weak_ptr at +0x48 "
                    "(decrement cb+0x0c, if the old count was 1 call "
                    "vtable slot 3 _M_destroy); destroy the string "
                    "key at +0x20 (heap free via _ZdlPvm with "
                    "capacity+1); operator delete(node, 0x50); loop "
                    "to the left sibling (+0x10).",
            "calls": 3,
            "callers": callers(0x61F81D0),
            "excerpt": "rec-destroy-61f81d0.objdump.txt",
        },
        "lockguard": {
            "addr": 0x61F814E, "fde": "0x61f814e..0x61f8165",
            "role": "lock_guard destructor {pthread_mutex_t*, bool "
                    "owns}: if the stored pointer is non-null, "
                    "pthread_mutex_unlock it, then clear owns.",
            "calls": 1,
            "callers": callers(0x61F814E),
            "excerpt": "lockguard-61f814e.objdump.txt",
        },
        "vec_sp_destroy": {
            "addr": 0x61F89E0, "fde": "0x61f89e0..0x61f8ac1",
            "role": "Destroy a vector<shared_ptr> at its address "
                    "(begin +0x00, end +0x08, capacity +0x10): "
                    "release each element's control block with the "
                    "(1,1) fast path or 0x5d35070, then free the buffer.",
            "calls": 1,
            "callers": callers(0x61F89E0),
            "excerpt": "vec-sp-destroy-61f89e0.objdump.txt",
        },
        "vec_insert": {
            "addr": 0x5FF7960, "fde": "0x5ff7960..0x5ff7b45",
            "role": "libstdc++ vector<shared_ptr>::_M_realloc_insert: "
                    "16-byte elements, growth doubling (minimum one "
                    "element), copies 16 bytes from *rdx and bumps "
                    "the copied control block's use count if non-null.",
            "calls": 4,
            "callers": callers(0x5FF7960),
            "excerpt": "vec-insert-5ff7960.objdump.txt",
        },
        "add_library": {
            "addr": 0x61F8DC0, "fde": "0x61f8dc0..0x61f913d",
            "role": "ObjectRegistry::AddLibrary(registry, name, "
                    "creator): return -1 if the name is empty or the "
                    "creator's manager is null. Append the name to "
                    "the names vector (in-place SSO construction; "
                    "grow via 0x5d655b0 when full). Allocate a new "
                    "ObjectLibrary make-shared block 0x90 (control-"
                    "block vtable 0x64d00f0, counts 0x100000001, "
                    "mutex zeroed +0x10..0x38, map buckets = +0x68, "
                    "bucket_count 1, max_load_factor 1.0, name = the "
                    "argument via _M_assign). Lock registry+0x98, "
                    "append the new library's shared_ptr to the "
                    "libraries vector (direct store or _M_realloc_"
                    "insert 0x5ff7960), unlock, then call the "
                    "creator's invoker (vtable slot 3) with (creator, "
                    "new library, name); __throw_bad_function_call "
                    "if the creator is empty at that point. Release "
                    "the temp shared_ptr afterwards.",
            "calls": 1,
            "callers": callers(0x61F8DC0),
            "excerpt": "add-library-61f8dc0.objdump.txt",
            "landing_pads": "add-library-landingpads-61f8d12.objdump.txt",
        },
        "reg_ctor": {
            "addr": 0x61F91B0, "fde": "0x61f91b0..0x61f9277",
            "role": "ObjectRegistry ctor(registry, default library "
                    "shared_ptr): zero the fields, initialise the map "
                    "header, seed libraries[0] with *default_lib_ptr "
                    "via _M_realloc_insert, then iterate the global "
                    "registrar map at 0x6509540 (before_begin first "
                    "node; per node: name string at node+0x08, "
                    "creator std::function at node+0x28; call "
                    "AddLibrary; next = *node) until null.",
            "calls": 1,
            "callers": callers(0x61F91B0),
            "excerpt": "reg-ctor-61f91b0.objdump.txt",
            "landing_pad": "ctor-landingpad-61f913e.objdump.txt",
        },
        "reg_getter": {
            "addr": 0x61F92B0, "fde": "0x61f92b0..0x61f93c5",
            "role": "ObjectRegistry singleton getter: function-local-"
                    "static; guard byte 0x65090f8, holder at "
                    "0x6509100 (16 bytes {object, control block}); "
                    "__cxa_guard_acquire/release; returns the "
                    "shared_ptr BY VALUE via a hidden out-pointer in "
                    "rdi (copies the holder's 16 bytes to (rdi), "
                    "returns rdi in rax). Init path: operator new "
                    "(0x10) holder, ObjectLibrary::Default 0x61f8b60, "
                    "operator new(0xd0) block, install control-block "
                    "vtable 0x64d8f00, counts 0x100000001, call the "
                    "ctor with the Default return.",
            "calls": 3,
            "callers": callers(0x61F92B0),
            "excerpt": "reg-getter-61f92b0.objdump.txt",
            "landing_pad": "getter-landingpad-61f9278.objdump.txt",
        },
        "clone": {
            "addr": 0x61F9400, "fde": "0x61f9400..0x61f963e",
            "role": "ObjectRegistry clone: create a NEW registry "
                    "whose +0x60 parent shared_ptr is the singleton "
                    "(copy the getter's returned shared_ptr into the "
                    "new object and bump its use count), otherwise "
                    "zero-initialised like the ctor (map header, "
                    "mutex). Takes the out shared_ptr in rdi, stores "
                    "{new object, new block} there, returns rdi.",
            "calls": 1,
            "callers": callers(0x61F9400),
            "excerpt": "clone-61f9400.objdump.txt",
            "landing_pad": "clone-landingpad-61f93c6.objdump.txt",
        },
        "ttl_register": {
            "addr": 0x62069F0, "fde": "0x62069f0..0x6206d29",
            "role": "TTL registration: register a hardcoded \"TTL\" "
                    "library into the singleton registry. Build a "
                    "stack string \"TTL\", a stack std::function "
                    "(functor 0x6208290, manager from GOT 0x64ee090, "
                    "invoker from GOT 0x64ee088), create the library "
                    "named \"TTL\", lock the singleton mutex +0x98, "
                    "append ONLY to the libraries vector (NOT the "
                    "names vector), unlock, invoke the creator with "
                    "(new library, EMPTY string), release the temp, "
                    "destroy the functor via manager op 3. The "
                    "creator 0x6208290 is a large unpinned function "
                    "(FDE 0x6208290..0x6208afa); it is cited by "
                    "contract, not excerpted. Referenced by an lea "
                    "at 0x6202df2 (function 0x6202da0, identity not "
                    "pinned).",
            "calls": 0,
            "lea_sites": leas(0x62069F0),
            "excerpt": "ttl-register-62069f0.objdump.txt",
        },
        "registrar_init": {
            "addr": 0x620B470, "fde": "0x620b470..0x620b57d",
            "role": "Static initializer: initialise the global "
                    "registrar unordered_map at 0x6509540 (buckets = "
                    "self+0x30, bucket_count 1, before_begin 0, "
                    "element_count 0, max_load_factor 1.0, "
                    "next_resize 0); construct the three build-info "
                    "globals via 0x5f204e0 (git SHA, git tag, build "
                    "date); register __cxa_atexit handlers for the "
                    "globals 0x65095a0/0x65095c0/0x6509580.",
            "calls": 0, "callers": [],
            "excerpt": "registrar-init-620b470.objdump.txt",
        },
        "by_contract": {
            "lib_default": {
                "addr": 0x61F8B60,
                "role": "ObjectLibrary::Default (pinned in #3983): "
                        "returns rax = the holder address 0x6509110 "
                        "(pointer to the singleton shared_ptr), NOT "
                        "the library object; 17 direct call sites.",
            },
            "ttl_creator": {
                "addr": 0x6208290,
                "fde": "0x6208290..0x6208afa",
                "role": "The TTL creator function invoked by the TTL "
                        "registration with (new library, empty "
                        "string); large function, not pinned here.",
            },
            "big_registry_method": {
                "addr": 0x5FF88C0,
                "fde": "0x5ff88c0..0x5ff9c50",
                "role": "Large registry method (0x1390 bytes) that "
                        "calls the getter (0x5ff88fc) and vec-insert "
                        "(0x5ff99d3), creates ObjectLibrary 0x90 "
                        "blocks and PatternEntry objects, and locks "
                        "the registry mutex at +0x98; not fully read "
                        "and not excerpted. Identity still open.",
            },
            "release_helpers": {
                "0x5d35070": "shared_ptr _M_release slow path "
                             "(654 calls + 36 jumps binary-wide)",
                "0x5d350c0": "shared_ptr _M_release variant "
                            "(1273 calls + 25 jumps binary-wide)",
            },
        },
        "relocations": reloc_rows,
        "relocation_ranges": [
            "0x64d8e80..0x64d8f48 (PatternEntry vtable + "
            "ObjectRegistry control-block vtable)",
            "0x64ecdc8..0x64ecdd0 (_Sp_make_shared_tag GOT slot)",
        ],
        "literals": [
            {"addr": 0x97FC20, "offset": 0x97FC20,
             "text": "St23_Sp_counted_ptr_inplaceIN7rocksdb14ObjectRegistryESaIvELN9__gnu_cxx12_Lock_policyE2EE"},
            {"addr": 0x97FBE0, "offset": 0x97FBE0,
             "text": "N7rocksdb13ObjectLibrary12PatternEntryE"},
            {"addr": 0x96C770, "offset": 0x96C770,
             "text": "St19_Sp_make_shared_tag"},
            {"addr": 0x97FC80, "offset": 0x97FC80,
             "text": "N7rocksdb24TablePropertiesCollectorE"},
            {"addr": 0x97FCC0, "offset": 0x97FCC0,
             "text": "N7rocksdb31TablePropertiesCollectorFactoryE"},
            {"addr": 0x965C68, "offset": 0x965C68,
             "text": "6a436150417120a3f9732d65a2a5c2b8d19b60fc"},
            {"addr": 0x44EED4, "offset": 0x44EED4,
             "text": "rocksdb_build_git_tag:v8.1.1"},
            {"addr": 0x95B628, "offset": 0x95B628,
             "text": "rocksdb_build_date:2023-04-06 16:38:52"},
            {"addr": 0x459B20, "offset": 0x459B20,
             "text": "<packed counts 0x100000001>"},
        ],
        "immediates": [
            {"where": "reg-getter init path 0x61f92b0",
             "text": "\"default\" is built from the immediates "
                     "\"defa\" + \"ult\" (length 7), not a .rodata "
                     "literal"},
            {"where": "TTL registration 0x62069f0",
             "text": "\"TTL\" is built from the immediates \"TT\" + "
                     "'L' (length 3), not a .rodata literal"},
        ],
        "census": {
            "targets": targets,
            "relocation_records": len(reloc_rows),
            "callers_tsv_rows": len(rows),
        },
        "model": {
            "module": "tools/objectregistry_lifecycle_115.py",
            "tests": "tests/test_objectregistry_lifecycle_115.py",
            "behaviour": "getter -> ctor seeding -> AddLibrary "
                         "register -> count/names/libraries -> clone "
                         "parent link -> dispose order, map-node "
                         "destroy, weak_ptr release, lock-guard unlock",
        },
        "tests": {
            "file": "tests/test_objectregistry_lifecycle_115.py",
            "count": 27,
        },
        "test_checks": 27,
        "open_unknowns": [
            "The 40 bytes at registry +0x70..0x98: zeroed by the ctor "
            "and the clone, never read or written by any pinned "
            "routine, trivially destructible. Possibly a second mutex "
            "or plain data; no pinned routine locks it.",
            "The identity of the big registry method 0x5ff88c0.."
            "0x5ff9c50 (calls the getter and vec-insert, locks +0x98, "
            "builds PatternEntry objects): not fully read.",
            "The TTL creator 0x6208290..0x6208afa: large function, "
            "cited by contract only.",
            "The clone's caller at 0x60bb8f0 (function 0x60bb890.."
            "0x60bb932) and the TTL lea site at 0x6202df2 (function "
            "0x6202da0..0x6202e78): identities not pinned.",
            "Which (name, creator) pairs populate the global "
            "registrar map at 0x6509540 before the first getter "
            "call: the map is empty after static init 0x620b470, "
            "and the populating static initializers are not pinned.",
        ],
    }
    (PACKET / "records.json").write_text(
        json.dumps(records, indent=1) + "\n")
    print("wrote records.json: %d census targets, %d relocations, "
          "%d callers.tsv rows" % (
              len(targets), len(reloc_rows), len(rows)))


if __name__ == "__main__":
    main()
