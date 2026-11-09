#!/usr/bin/env python3
"""Generate the semantic-record JSON for this packet.

Run from the repo root:
    python3 research/work-items/RE-001-encrypted-fs-factory-115/gen_records.py

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
    "work_item": "RE-001-encrypted-fs-factory-115",
    "question": (
        "Which host registers an option group against the provider map "
        "0x6505300 (one entry, 'provider'), what does it build, and what "
        "is the construction chain behind it? Resolves the open unknown "
        "left by #4395: the only non-initializer lea reference to the "
        "provider map is 0x5ff6763 inside FDE 0x5ff6690..0x5ff682e."
    ),
    "artifact": "artifacts/node/115/hl-node",
    "artifact_sha256": DIGEST,
    "resolves": {
        "pr": 4395,
        "open_unknown": (
            "Which host registers a group against the provider map "
            "0x6505300 -- the only non-initializer lea reference is "
            "0x5ff6763 in FDE 0x5ff6690..0x5ff682e; that host is not "
            "pinned in #4395."
        ),
        "answer": (
            "The host 0x5ff6690 is the EncryptedFileSystemImpl factory: "
            "it builds a 0x40-byte "
            "rocksdb::(anonymous namespace)::EncryptedFileSystemImpl "
            "(vtable 0x64cfca0), wraps the caller-supplied FileSystem "
            "shared_ptr (2nd arg) via the FileSystemWrapper ctor "
            "0x5fe7210, stores the caller-supplied BlockCipher "
            "shared_ptr (3rd arg) at +0x30/+0x38, and registers the "
            "group 'EncryptionProvider' with the provider map 0x6505300 "
            "(one entry, 'provider', type 22, verification 1, flags "
            "0x400, offset 0), so the cipher is configured through the "
            "'provider' option. The registered factory 0x5fe7a20 calls "
            "it with two empty shared_ptrs, so the registered "
            "'EncryptedFileSystem' starts blank and is configured later "
            "through the 'target' (wrapped FileSystem) and 'provider' "
            "(cipher) options."
        ),
    },
    "factory_0x5ff6690": {
        "address": "0x5ff6690",
        "fde": "0x5ff6690..0x5ff682e",
        "object": {
            "size_bytes": 64,
            "vtable": "0x64cfca0",
            "typeinfo": "*N7rocksdb12_GLOBAL__N_123EncryptedFileSystemImplE",
            "typeinfo_object": "0x64cf758",
        },
        "signature": (
            "(Status* out, shared_ptr<FileSystem> wrapped, "
            "shared_ptr<BlockCipher> cipher, out_slot)"
        ),
        "steps": [
            "operator new 0x40 bytes; the fresh object goes to rbx",
            "call FileSystemWrapper ctor 0x5fe7210 at 0x5ff66d1 with "
            "(rbx, rsi=wrapped shared_ptr)",
            "store vtable 0x64cfca0 at +0x00 (lea 0x5ff66d6)",
            "zero +0x38 (the cipher control-block slot) at 0x5ff66dd",
            "copy the cipher shared_ptr: ptr from (%rdx) to +0x30, "
            "control block from 0x8(%rdx); bump the use count -- plain "
            "addl when __libc_single_threaded (GOT 0x64ed290) is "
            "nonzero, else lock addl -- then store the control block "
            "at +0x38",
            "build the group name 'EncryptionProvider' (18 chars: "
            "16-byte literal 0x4539b0 'EncryptionProvid' plus immediate "
            "0x7265 'er') as a heap string",
            "call RegisterOptions 0x6099ce0 at 0x5ff677e with "
            "(object, name, options base object+0x30, map 0x6505300)",
            "free the heap name string when it is not the SSO buffer",
            "out-slot store: load the old object from (%rcx), store "
            "the new object, destroy the old one through its vtable "
            "slot 1 (indirect call *0x8(%rax)) when non-null",
            "write a 16-byte zero Status (kOk) into *out (rdi) and "
            "return rdi",
        ],
        "lock_path_note": (
            "In the lock-addl path the factory re-reads +0x38 and "
            "would release a stale control block via 0x5d350c0 "
            "(call 0x5ff67fb), but +0x38 was just zeroed, so that call "
            "is unreachable in this factory; it is the generic "
            "shared_ptr-assign shape."
        ),
        "e8_callers": ["0x5fe7a67"],
        "lea_references": [],
    },
    "wrapper_ctor_0x5fe7210": {
        "address": "0x5fe7210",
        "fde": "0x5fe7210..0x5fe72e8",
        "vtable": "0x64cf200",
        "typeinfo": "N7rocksdb17FileSystemWrapperE",
        "typeinfo_object": "0x64ced40",
        "signature": "(FileSystemWrapper* this, shared_ptr<FileSystem> wrapped)",
        "steps": [
            "call FileSystem ctor 0x5fe7080 at 0x5fe7232",
            "store vtable 0x64cf200 at +0x00 (lea base 0x64cf1f0 + 0x10)",
            "copy the wrapped FileSystem shared_ptr (16 bytes from "
            "*rsi) to +0x20/+0x28; bump the use count -- plain addl "
            "when single-threaded, else lock addl",
            "register the empty-named group '' with map 0x65051e0 and "
            "options base object+0x20 via RegisterOptions 0x6099ce0 "
            "at 0x5fe7292",
        ],
        "e8_callers": [
            "0x5d561b3", "0x5e023e0", "0x5f75028", "0x5fb1f3d",
            "0x5fe7758", "0x5ff66d1", "0x60072b8", "0x61edb28",
            "0x61f0398",
        ],
        "note": (
            "A shared ctor: 9 call sites binary-wide, so every "
            "FileSystemWrapper subclass (including the encrypted, "
            "read-only, counted and timed wrappers) runs this body."
        ),
    },
    "fs_ctor_0x5fe7080": {
        "address": "0x5fe7080",
        "fde": "0x5fe7080..0x5fe70ab",
        "vtable": "0x64cf008",
        "typeinfo": "N7rocksdb10FileSystemE",
        "typeinfo_object": "0x64ced28",
        "steps": [
            "store vtable 0x64cf008 at +0x00 (lea base 0x64ceff8 + 0x10)",
            "zero the Configurable group-vector triple at "
            "+0x08/+0x10/+0x18",
        ],
        "e8_callers": ["0x5fe7232", "0x5ffc351", "0x6002a9f", "0x6028a8a"],
    },
    "group_dtor_0x5fe70b0": {
        "address": "0x5fe70b0",
        "fde": "0x5fe70b0..0x5fe7135",
        "role": "Configurable/group-vector destructor (base-subobject dtor)",
        "steps": [
            "store the Configurable vtable 0x64d3430 at +0x00 "
            "(lea base 0x64d3420 + 0x10)",
            "walk the 0x30-byte group elements from +0x08 to +0x10; "
            "free each element name string with operator delete when "
            "it is heap-backed",
            "free the group-vector storage with operator delete[] "
            "when non-null",
        ],
    },
    "dtors": {
        "complete_0x5ff3000": {
            "fde": "0x5ff3000..0x5ff3045",
            "steps": [
                "reset the vptr to 0x64cfca0",
                "release the cipher control block at +0x38 via "
                "0x5d350c0 (call 0x5ff301b) when non-null",
                "reset the vptr to 0x64cf200 (FileSystemWrapper)",
                "release the wrapped-FileSystem control block at +0x28 "
                "via 0x5d350c0 (call 0x5ff3037) when non-null",
                "tail-jump to the group dtor 0x5fe70b0",
            ],
        },
        "deleting_0x5ff3050": {
            "fde": "0x5ff3050..0x5ff30a2",
            "steps": [
                "same releases as the complete dtor (calls 0x5ff306b "
                "and 0x5ff3087)",
                "call the group dtor 0x5fe70b0, then sized delete "
                "0x40 bytes",
            ],
        },
        "e8_callers": [],
        "note": (
            "No direct E8 callers: both dtors are reached only through "
            "vtable slots 0/1, as in #4395 for the CTR dtor."
        ),
    },
    "registered_factory_0x5fe7a20": {
        "address": "0x5fe7a20",
        "fde": "0x5fe7a20..0x5fe7cfc",
        "registry_name": "EncryptedFileSystem",
        "role": (
            "The factory registered for 'EncryptedFileSystem' by "
            "RegisterBuiltinFileSystems 0x5febf50; the sole E8 caller "
            "of the 0x5ff6690 factory."
        ),
        "steps": [
            "load the out slot from *(rdx) into rbp and the error "
            "string slot from *(rcx) into r12",
            "build two empty 16-byte stack shared_ptrs at 0x10(%rsp) "
            "and 0x20(%rsp) (null wrapped FileSystem, null cipher)",
            "call the factory 0x5ff6690 at 0x5fe7a67 with "
            "(stack Status at 0x00(%rsp), wrapped at 0x20(%rsp), "
            "cipher at 0x10(%rsp), out slot rbp)",
            "destroy the two stack shared_ptrs (use-count release "
            "when non-null)",
            "on kOk (Status code byte 0): return the object pointer "
            "now stored in the out slot (*rbp), freeing the Status "
            "message heap buffer when present",
            "on error (Status code nonzero): format the Status into "
            "a stack string via 0x61cfed0 and move-assign it into the "
            "string at *(rcx), then return the out-slot contents",
        ],
        "args_note": (
            "The caller's own rdi/rsi are never read in the excerpted "
            "body: the registered factory ignores its spec argument "
            "and creates a blank EncryptedFileSystemImpl, to be "
            "configured later through the 'target' and 'provider' "
            "options."
        ),
        "e8_callers": [],
        "lea_references": ["0x5fec0c6"],
    },
    "name_fn_0x5fef930": {
        "address": "0x5fef930",
        "fde": "0x5fef930..0x5fef93c",
        "vtable_slot": 14,
        "returns": "EncryptedFileSystem",
        "literal": "0x44470e",
        "note": (
            "The impl overrides the pure-virtual Name() slot 14; the "
            "FileSystemWrapper and FileSystem vtables carry 0x0 there."
        ),
    },
    "record_ctor_0x5fe7ee0": {
        "address": "0x5fe7ee0",
        "fde": "0x5fe7ee0..0x5fe808a",
        "role": "OptionTypeInfo record constructor for type-22 options",
        "signature": "(record*, offset=esi, verification=edx, flags=ecx)",
        "fields": {
            "record+0x00": "field offset (esi)",
            "record+0x18": "GOT callback pair (0x64ed8c8/0x64ed960 -> "
                            "0x5fd5460/0x5fd7470, the AsCustomSharedPtr "
                            "handlers shared with #4379)",
            "record+0xa8": "OptionType, hardcoded 0x16 (22)",
            "record+0xac": "OptionVerification (edx)",
            "record+0xb0": "flags (ecx with 0x400 OR-ed in: or $0x4,%ch)",
        },
        "call_site": "0x5feb7ca with (record, esi=0, edx=1, ecx=0x2000)",
        "e8_callers": ["0x5feb7ca"],
    },
    "static_init_0x5feb760": {
        "address": "0x5feb760",
        "fde": "0x5feb760..0x5feba2e",
        "role": (
            "Static initializer building the FileSystemWrapper option "
            "maps"
        ),
        "steps": [
            "zero the .bss map 0x6505220 and register its dtor "
            "0x5d36020 with __cxa_atexit (call 0x5feb7b6)",
            "build the 'target' record with the record ctor 0x5fe7ee0 "
            "at 0x5feb7ca (offset 0, verification 1, flags 0x2000)",
            "build the key string 'target' (6 chars: immediate "
            "0x67726174 'trag' + immediate 0x7465 'et')",
            "insert the record into map 0x65051e0 with 0x5d405b0 at "
            "0x5feb9cd",
            "register the map dtor 0x5d3f820 for 0x65051e0 with "
            "__cxa_atexit (tail-jump 0x5feba18)",
        ],
        "empty_map_note": (
            "Map 0x6505220 is zeroed and given an atexit dtor but no "
            "insert site exists binary-wide (only lea 0x5feb765); it "
            "holds no entries from this initializer."
        ),
    },
    "maps": {
        "0x6505300": {
            "group": "EncryptionProvider",
            "entries": [
                {
                    "key": "provider",
                    "key_literal": "0x4453a1",
                    "insert_site": "0x5ff7e23",
                    "atexit_site": "0x5ff7e5b",
                    "pack_record+0xa8": "0x100000016",
                    "type": 22,
                    "verification": 1,
                    "flags_record+0xb0": "0x400",
                    "offset_record+0x00": 0,
                },
            ],
            "options_base": "object+0x30 (the cipher shared_ptr)",
            "initializer": "0x5ff7c90 (pinned by #4389)",
        },
        "0x65051e0": {
            "group": "",
            "entries": [
                {
                    "key": "target",
                    "key_source": "immediates 0x67726174 + 0x7465",
                    "insert_site": "0x5feb9cd",
                    "atexit_site": "0x5feba18",
                    "pack_record+0xa8": "0x100000016",
                    "type": 22,
                    "verification": 1,
                    "flags_record+0xb0": "0x2400",
                    "offset_record+0x00": 0,
                },
            ],
            "options_base": "object+0x20 (the wrapped-FileSystem shared_ptr)",
            "initializer": "0x5feb760 (pinned here)",
            "note": (
                "Unlike the CompositeEnvWrapper 'target' (type 26 in "
                "#4379), the FileSystemWrapper 'target' is type 22: "
                "the record ctor 0x5fe7ee0 hardcodes type 0x16, and "
                "the flags gain 0x400 from the ctor's or $0x4,%ch on "
                "top of the caller's 0x2000."
            ),
        },
    },
    "vtables": {
        "0x64cfca0": {
            "typeinfo": "*N7rocksdb12_GLOBAL__N_123EncryptedFileSystemImplE",
            "typeinfo_object": "0x64cf758",
            "slots": 62,
        },
        "0x64cf200": {
            "typeinfo": "N7rocksdb17FileSystemWrapperE",
            "typeinfo_object": "0x64ced40",
            "slots": 62,
            "note": "slots 0/1 are pure virtual (0x0) in the abstract base",
        },
        "0x64cf008": {
            "typeinfo": "N7rocksdb10FileSystemE",
            "typeinfo_object": "0x64ced28",
            "slots": 62,
            "note": "slots 0/1 are pure virtual (0x0) in the abstract base",
        },
        "0x64d3430": {
            "typeinfo": "N7rocksdb12ConfigurableE",
            "typeinfo_object": "0x64d3410",
            "slots": 14,
            "note": (
                "The Configurable vtable as reached during destruction "
                "of the FileSystem classes; the FileSystem vtables "
                "extend it with their own virtuals at slots 14..61."
            ),
        },
        "slot_identities": {
            "0": "complete dtor",
            "1": "deleting dtor",
            "9": "ConfigureOptions entry 0x609d0e0 (#4334)",
            "10": "ConfigureOption core 0x60986b0 (#4328)",
            "12": "slot-12 serializer: FileSystem base 0x609de80 "
                  "(#4328); wrapper/impl override 0x5fe6910",
            "13": "GetOptionName 0x609d980 (#4334)",
            "14": "Name(): impl 0x5fef930 -> 'EncryptedFileSystem'; "
                  "base/wrapper pure virtual",
            "15": "GetId 0x5d32a30 (#4328)",
            "16": "name-match predicate: base/wrapper 0x5d2e770 "
                  "(#4349); impl overrides with 0x5ff0990",
            "17": "Inner: base 0x5d2ca00 (#4349); wrapper/impl "
                  "0x5fe55c0",
            "18": "NickName() 0x5d2ca10 (#4349)",
            "5": "wrapper/impl override 0x5fe7d00; FileSystem base "
                 "0x6095e70",
            "19-61": "FileSystem virtuals; roles open",
        },
    },
    "registry": {
        "builder": "0x5febf50",
        "builder_fde": "0x5febf50..0x5fec408",
        "role": (
            "RegisterBuiltinFileSystems: registers the builtin "
            "FileSystem factories into the ObjectLibrary passed in rdi "
            "(r13); each entry is a (factory, std::function manager) "
            "pair under a name string, inserted via 0x5febad0."
        ),
        "entries": [
            {"name": "TimedFS", "factory": "0x5fe74a0",
             "manager": "0x5fe56a0"},
            {"name": "ReadOnlyFilesystem", "factory": "0x5fe7720",
             "manager": "0x5fe56d0"},
            {"name": "EncryptedFileSystem", "factory": "0x5fe7a20",
             "manager": "0x5fe5700"},
            {"name": "CountedFileSystem", "factory": "0x5fe75e0",
             "manager": "0x5fe5730"},
            {"name": "MemoryFileSystem", "factory": "0x5fe58b0",
             "manager": "0x5fe5760"},
        ],
        "manager_0x5fe5700": {
            "address": "0x5fe5700",
            "fde": "0x5fe5700..0x5fe572d",
            "role": (
                "std::function manager for the captureless factory "
                "lambda"
            ),
            "ops": [
                "edx == 0: store the lambda typeinfo 0x64ceda8 into "
                "*rdi (typeinfo name: the RegisterBuiltinFileSystems "
                "lambda)",
                "edx == 1: store rsi into *rdi",
                "otherwise: return 0",
            ],
            "returns": "0 always (eax)",
        },
    },
    "cited_context": {
        "0x6099ce0": "RegisterOptions helper (pinned by #4372); 37 "
                     "sites binary-wide, 2 in this packet",
        "0x5d405b0": "map insert helper (pinned by #4379); the "
                     "'target' insert site is 0x5feb9cd",
        "0x5d3f820": "map dtor reached via __cxa_atexit (pinned by "
                     "#4379)",
        "0x5d350c0": "shared_ptr control-block release (pinned by "
                     "#4395); 5 sites in this packet",
        "0x61cfed0": "Status-to-string formatter (jump-table dispatch "
                     "on the Status code byte); the registered "
                     "factory's error path",
        "0x60986b0": "slot-10 ConfigureOption core (#4328)",
        "0x609d0e0": "slot-9 ConfigureOptions entry (#4334)",
    },
    "open_unknowns": [
        "The exact C++ type of the factory's out slot (raw T** vs "
        "unique_ptr<FileSystem>* out parameter) -- open.",
        "The registered factory's rdi/rsi roles: neither is read, so "
        "whether rdi is the spec string and rsi an options object is "
        "open.",
        "The paired second functions' full roles: the manager "
        "0x5fe5700 handles ops 0/1 only; clone/destroy handling for "
        "the captureless lambda lives elsewhere -- open.",
        "Why the registered factory creates a blank impl (null "
        "wrapped FileSystem, null cipher) instead of parsing its "
        "spec -- open; configuration is presumed to follow through "
        "the 'target'/'provider' options.",
        "The FileSystem vtable slots 19..61 (impl overrides at 21..26 "
        "and others) -- C++ names open.",
        "The impl slot-16 override 0x5ff0990, slot-5 override "
        "0x5fe7d00 and slot-12 override 0x5fe6910 -- bodies not "
        "pinned here.",
        "The empty map 0x6505220's purpose -- zeroed with an atexit "
        "dtor but no inserts binary-wide.",
        "The small host 0x5ffabd0's full dispatch (the non-'ROT13' "
        "path via 0x60bb890 / 0x5ffa710) -- still open from #4395.",
    ],
}

if __name__ == "__main__":
    (HERE / "records.json").write_text(
        json.dumps(RECORDS, indent=2) + "\n")
    print(f"wrote records.json ({len(RECORDS)} top-level keys)")
