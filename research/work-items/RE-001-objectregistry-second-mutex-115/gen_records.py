"""Generate records.json for RE-001-objectregistry-second-mutex-115.

Reads the census outputs (lock-sites.tsv, destroy-sites.tsv,
disp-hits.tsv, marked-fdes.txt, relocations.txt) plus the window list,
and writes the packet's semantic records. No per-instruction mnemonic
list: instruction-level detail lives only in the verbatim excerpts.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-second-mutex-115/gen_records.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("ctor", 0x61F91B0, 0x61F9277, "ctor-61f91b0.objdump.txt", "#4015"),
    ("clone", 0x61F9400, 0x61F963E, "clone-61f9400.objdump.txt", "#4015"),
    ("dispose", 0x61F8760, 0x61F89DB, "dispose-61f8760.objdump.txt", "#4015"),
    ("add_library", 0x61F8DC0, 0x61F913D, "add-library-61f8dc0.objdump.txt", "#4015"),
    ("ttl_register", 0x62069F0, 0x6206D29, "ttl-register-62069f0.objdump.txt", "#4015"),
    ("big_method", 0x5FF88C0, 0x5FF9C50, "big-method-5ff88c0.objdump.txt", "#4028"),
    ("destroy_helper", 0x60D5170, 0x60D5200, "destroy-helper-60d5170.objdump.txt", "new"),
    ("lock70_a", 0x5F44C80, 0x5F44D56, "lock70-5f44c80.objdump.txt", "new"),
    ("lock70_b", 0x5F44DB0, 0x5F44E53, "lock70-5f44db0.objdump.txt", "new"),
    ("lock70_c", 0x606A450, 0x606A604, "lock70-606a450.objdump.txt", "new"),
    ("lock70_d", 0x606A650, 0x606A88E, "lock70-606a650.objdump.txt", "new"),
    ("lock70_e", 0x606A900, 0x606AA82, "lock70-606a900.objdump.txt", "new"),
]

# The three library-mutex lock sites (lea disp +0x98, then PLT lock).
LIBRARY_LOCKERS = [
    {"site": "0x61f8f09", "fde": "0x61f8dc0", "routine": "AddLibrary",
     "lea": "0x61f8ef0", "base": "rbp", "unlock": "0x61f8f4f"},
    {"site": "0x5ff8a28", "fde": "0x5ff88c0", "routine": "big registry method",
     "lea": "0x5ff8a20", "base": "rbx", "unlock": "0x5ff8a7b"},
    {"site": "0x6206b73", "fde": "0x62069f0", "routine": "TTL registration",
     "lea": "0x6206b5f", "base": "rbp", "unlock": "0x6206bb4"},
]

# The five +0x70 lock sites that are NOT the registry's (other classes).
FOREIGN_LOCK70 = [
    {"lock": "0x5f44c92", "unlock": None, "fde": "0x5f44c80",
     "base": "rdi", "identity": "TableCache-area routine; locks this+0x70, "
     "then indexes a vector at this+0x08/+0x58/+0x60"},
    {"lock": "0x5f44dc9", "unlock": "0x5f44e01", "fde": "0x5f44db0",
     "base": "rdi", "identity": "cache routine; locks this+0x70, bumps a "
     "refcount at +0x38 of its second argument"},
    {"lock": "0x606a4b1", "unlock": "0x606a4ce", "fde": "0x606a450",
     "base": "rbx", "identity": "list-hook helper; locks this+0x70 "
     "around _List_node_base::_M_hook"},
    {"lock": "0x606a6dc", "unlock": None, "fde": "0x606a650",
     "base": "rdi", "identity": "routine whose object carries a flag byte "
     "at +0x98 (not a mutex) and a mutex at +0x70"},
    {"lock": "0x606a9d7", "unlock": "0x606aa33", "fde": "0x606a900",
     "base": "rdi", "identity": "list-hook helper; locks this+0x70 "
     "around a 0x18-byte node allocation"},
]


def read_tsv(name):
    with open(os.path.join(HERE, name)) as fh:
        lines = fh.read().splitlines()
    header = lines[0].split("\t")
    rows = [dict(zip(header, l.split("\t"))) for l in lines[1:] if l]
    return rows


def main():
    lock_sites = read_tsv("lock-sites.tsv")
    destroy_sites = read_tsv("destroy-sites.tsv")
    disp_hits = read_tsv("disp-hits.tsv")
    marked = [l.strip() for l in open(os.path.join(HERE, "marked-fdes.txt"))
              if l.strip()]
    relocs = read_tsv("relocations.txt")

    from collections import Counter
    by_call = Counter(r["call"] for r in lock_sites)
    disp70 = [r for r in lock_sites if r["rdi_disp"] == "0x70"]
    disp98 = [r for r in lock_sites if r["rdi_disp"] == "0x98"]
    disp70_fdes = sorted({r["containing_fde"] for r in disp70})
    disp98_fdes = sorted({r["containing_fde"] for r in disp98})

    records = {
        "target": {
            "binary": "work/hl-node-115.bin",
            "node": 115,
            "sha256": DIGEST,
            "provenance": "provenance/artifacts.json "
                          "artifacts/node/115/hl-node",
        },
        "work_item": "RE-001-objectregistry-second-mutex-115",
        "task": "RE-001",
        "question": "What is the 40-byte region at ObjectRegistry "
                    "+0x70..0x98, and what is the complete lock "
                    "discipline of the registry's two mutexes?",
        "answer": "The region is the registry's second std::mutex, "
                  "objects_mutex_ (40-byte pthread_mutex_t, guards the "
                  "+0x30 managed_objects_ map). The +0x98 mutex is "
                  "library_mutex_ (guards libraries_). objects_mutex_ "
                  "is never locked, read, written or destroyed by any "
                  "code in this binary; the managed-object methods "
                  "that would lock it are absent.",
        "registry": {
            "object_size": 0xC0,
            "layout": [
                {"offset": 0, "size": 24,
                 "field": "vector<shared_ptr<ObjectLibrary>> libraries",
                 "note": "begin +0x00, end +0x08, capacity +0x10"},
                {"offset": 24, "size": 24,
                 "field": "vector<std::string> names "
                          "(upstream source name: plugins_)",
                 "note": "begin +0x18, end +0x20, capacity +0x28; "
                         "AddLibrary appends the name here"},
                {"offset": 48, "size": 48,
                 "field": "std::map<std::string, "
                          "std::weak_ptr<Customizable>> managed_objects_",
                 "note": "key-compare +0x30, RB header +0x38; 0x50-byte "
                         "nodes (key string + weak_ptr); guarded by "
                         "objects_mutex_ at +0x70 per the upstream source"},
                {"offset": 96, "size": 16,
                 "field": "shared_ptr<ObjectRegistry> parent",
                 "note": "null in the singleton; the clone stores the "
                         "singleton here"},
                {"offset": 112, "size": 40,
                 "field": "std::mutex objects_mutex_",
                 "note": "IDENTIFIED (was #4015's open unknown): 40-byte "
                         "pthread_mutex_t; zeroed by the ctor and the "
                         "clone with the same 16+16+8 pattern as the "
                         "+0x98 mutex; never locked, read or written by "
                         "any registry routine; never destroyed; guards "
                         "the +0x30 map per the upstream source"},
                {"offset": 152, "size": 40,
                 "field": "std::mutex library_mutex_",
                 "note": "IDENTIFIED: 40-byte pthread_mutex_t; zeroed "
                         "like objects_mutex_; locked by exactly the "
                         "three libraries_-mutating routines "
                         "(AddLibrary, big registry method, TTL "
                         "registration); never destroyed; guards "
                         "libraries_ per the upstream source"},
            ],
        },
        "objects_mutex": {
            "offset": 0x70,
            "size": 0x28,
            "type": "pthread_mutex_t (std::mutex)",
            "ctor_zeroing": ["movups +0x70", "movups +0x80", "movq +0x90"],
            "clone_zeroing": ["movups +0x80", "movups +0x90",
                              "movq +0x90 (block+0xa0)"],
            "lock_sites": [],
            "read_write_sites": [],
            "destroy_sites": [],
            "note": "Zero-initialized, never used. The managed-object "
                    "methods that would lock it (SetManagedObject, "
                    "GetManagedObject, ListManagedObjects) are absent "
                    "from this binary: no 'Object already exists: ' "
                    "string, no 'Registered Plugins:' string, no "
                    "disp-0x70 lock in any registry-referencing FDE. "
                    "The binary's only 'managed' string (file offset "
                    "0x95f620) is the unrelated RocksDB iterator error "
                    "'Managed iterator is not supported anymore.'.",
        },
        "library_mutex": {
            "offset": 0x98,
            "size": 0x28,
            "type": "pthread_mutex_t (std::mutex)",
            "ctor_zeroing": ["movups +0x98", "movups +0xa8", "movq +0xb8"],
            "clone_zeroing": ["movups +0x98", "movups +0xa8",
                              "movq +0xb8 (block+0xc8)"],
            "lockers": LIBRARY_LOCKERS,
            "note": "Locked by exactly three routines, all of which "
                    "mutate libraries_: AddLibrary, the big registry "
                    "method 0x5ff88c0, the TTL registration. Each locks "
                    "then unlocks around the vector append.",
        },
        "windows": [
            {"name": n, "fde": "%#x..%#x" % (s, e), "excerpt": x,
             "source": src}
            for n, s, e, x, src in WINDOWS
        ],
        "lock_census": {
            "plt_call_sites_total": len(lock_sites),
            "by_call": dict(by_call),
            "disp_0x70_sites": len(disp70),
            "disp_0x70_fdes": disp70_fdes,
            "disp_0x98_sites": len(disp98),
            "disp_0x98_fdes": disp98_fdes,
            "foreign_lock70": FOREIGN_LOCK70,
            "note": "The 8 disp-0x70 sites (5 lock, 3 unlock) sit in 5 "
                    "FDEs, all other classes' mutexes (see "
                    "foreign_lock70). The 28 disp-0x98 sites include "
                    "the 6 registry sites (3 lock + 3 unlock) and 22 "
                    "other classes' +0x98 mutexes (ObjectLibrary mu_ "
                    "and Env/Statistics-area mutexes); none of the 22 "
                    "is in a registry-marked FDE.",
        },
        "destroy_census": {
            "destroy_helper": "0x60d5170",
            "destroy_helper_fde": "0x60d5170..0x60d5200",
            "pthread_mutex_destroy_plt_sites": 1,
            "destroy_plt_site": "0x60d5189",
            "destroy_helper_callers": len(destroy_sites),
            "destroy_helper_disps": sorted(
                {r["rdi_disp"] for r in destroy_sites if r["rdi_disp"]}),
            "note": "The binary's only pthread_mutex_destroy call is "
                    "inside helper 0x60d5170. Its 74 callers never pass "
                    "a +0x70 or +0x98 displacement, and none is in a "
                    "registry-marked FDE. The registry dispose "
                    "0x61f8760 never calls the helper (verified in its "
                    "excerpt): neither registry mutex is ever destroyed.",
        },
        "init_census": {
            "pthread_mutex_init_plt_sites": 4,
            "sites": [
                {"site": "0x5fe2a3e", "fde": "0x5fe2860",
                 "note": "CompositeEnvWrapper holder initializer (#3950)"},
                {"site": "0x60d50dc", "fde": "0x60d50c0",
                 "note": "mutex-init wrapper with error reporting"},
                {"site": "0x63bf8d9", "fde": "0x63bf840",
                 "note": "lea disp +0x40, non-registry"},
                {"site": "0x63bfa21", "fde": "0x63bf970",
                 "note": "lea disp +0x40, non-registry"},
            ],
            "note": "No pthread_mutex_init targets a registry mutex: "
                    "both registry mutexes are zero-initialized by the "
                    "ctor/clone instead.",
        },
        "disp_census": {
            "registry_marked_fdes": len(marked),
            "disp_0x70_0x97_hits_in_marked_fdes": len(disp_hits),
            "resolved_false_positives": [
                "stack temporaries (%rsp-based, most hits)",
                "ObjectLibrary name-string SSO init at block+0x70 "
                "(TTL 0x6206ad7..0x6206b42, big method "
                "0x5ff8962..0x5ff89e4): ptr=SSO buffer, size=0, NUL",
                "Options-struct field copies in 0x611fb10 (r12 = 2nd "
                "argument, read before the NewInstance call at "
                "0x612073b)",
                "vtable indirect call *0x78(%rax) in 0x61c8370",
                "clone block+0x70 movups = object+0x60 (parent "
                "shared_ptr), not the +0x70 field",
                "dispose block+0x78 read = object+0x68 (parent control "
                "block), not the +0x70 field",
            ],
            "note": "After resolving every non-stack hit, no function "
                    "reads or writes registry+0x70..0x98 except the "
                    "ctor and clone zeroing it.",
        },
        "getter_calls": ["0x5ff88fc", "0x61f9420", "0x6206a3d"],
        "source_corroboration": {
            "note": "The member names and guard roles come from the "
                    "upstream object_registry.cc, which is stable "
                    "across the bracketing versions: RocksDB 7.8.3 "
                    "(electrs-librocksdb-sys 0.9.0-e3+7.8.3) and 9.10.0 "
                    "(ckb-librocksdb-sys 9.10.0) both show "
                    "objects_mutex_ guarding managed_objects_ and "
                    "library_mutex_ guarding libraries_. The 8.1.1 "
                    "header 404s on raw.githubusercontent.com, so the "
                    "8.1.1 declaration order itself is not directly "
                    "confirmed; the binary identification rests on "
                    "size (40 = pthread_mutex_t), identical zeroing, "
                    "identical dispose treatment, the +0x98 lockers "
                    "proving library_mutex_, and elimination for +0x70.",
            "versions_checked": ["7.8.3", "9.10.0"],
            "binary_target_version": "8.1.1 (build tag "
                                     "rocksdb_build_git_tag:v8.1.1)",
        },
        "absent_strings": [
            "Object already exists: ",
            "Registered Plugins:",
        ],
        "sole_managed_string": {
            "text": "Managed iterator is not supported anymore.",
            "file_offset": "0x95f620",
            "note": "The binary's only case-insensitive 'managed' "
                    "string is this unrelated RocksDB iterator error "
                    "message; it has nothing to do with the registry's "
                    "managed-object API.",
        },
        "relocations": {
            "rows": len(relocs),
            "mutex_plt_got": 7,
            "control_block_vtable_relative": 24,
            "note": "The vtable-region rows re-ship #4015's 20 RELATIVE "
                    "records plus the 4 R_X86_64_64 typeinfo-pointer "
                    "records in the same span.",
        },
        "corrections_to_4015": [
            "The +0x70..0x98 region is objects_mutex_, a second "
            "std::mutex (40-byte pthread_mutex_t) -- not 'possibly a "
            "second mutex or plain data'.",
            "The +0x98 field is library_mutex_, the mutex guarding "
            "libraries_ -- its locker set is exactly AddLibrary, the "
            "big registry method 0x5ff88c0, and the TTL registration.",
            "The +0x30 map is managed_objects_ "
            "(map<string, weak_ptr<Customizable>>), guarded by "
            "objects_mutex_.",
            "The +0x18 vector's upstream name is plugins_ "
            "(vector<string>); the binary shows AddLibrary appending "
            "the name there.",
            "Neither mutex is destroyed: the dispose never calls the "
            "mutex-destructor helper, and the binary's only "
            "pthread_mutex_destroy site is elsewhere.",
        ],
        "open_unknowns": [
            "The 8.1.1 header itself was not read (404 on the raw "
            "URL); the member names rest on the 7.8.3/9.10.0 bracket "
            "plus binary elimination.",
            "Whether the managed-object methods exist in the 8.1.1 "
            "source but were stripped at link time, or were never "
            "referenced: the binary cannot distinguish these.",
            "The exact identities of the five +0x70-locking classes "
            "(named by code area only).",
            "A hypothetical free function taking the registry as its "
            "second argument and locking +0x98 would escape the "
            "registry-marker filter; no such function exists in the "
            "upstream source (all locking sites are methods), so this "
            "is a source-backed exclusion, not a binary proof.",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json (%d lock sites, %d destroy sites, "
          "%d disp hits)" % (len(lock_sites), len(destroy_sites),
                             len(disp_hits)))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
