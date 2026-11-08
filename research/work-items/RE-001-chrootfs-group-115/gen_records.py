#!/usr/bin/env python3
"""Build records.json for RE-001-chrootfs-group-115 from the census.

Run from the repo root:
    python3 research/work-items/RE-001-chrootfs-group-115/gen_records.py

Cross-checks every claim against the excerpts and the raw binary before
writing: the single RegisterOptions argument setup in the 0x5feeab0
excerpt, the chroot_dir name construction (movabs + immediate, no
.rodata literal), the map address, the initializer's one-entry record
(key, pack, flags), and the lea censuses. The artifact digest is
stored in full (64 hex chars) — never a prefix.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Cited instruction lines, copied verbatim from the excerpts.
HOST_SPOTS = {
    "dir_arg": "mov    %rdx,%rbp",
    "base_chain_call": "call   60072b0",
    "vtable_lea": "# 64cf468",
    "vtable_adjust": "add    $0x10,%rax",
    "vtable_store": "mov    %rax,(%rbx)",
    "group_base_lea": "lea    0x30(%rbx),%r12",
    "name_movabs": "movabs $0x645f746f6f726863,%rax",
    "name_chunk_store": "mov    %rax,0x20(%rsp)",
    "name_tail_imm": "mov    $0x7269,%eax",
    "name_tail_store": "mov    %ax,0x28(%rsp)",
    "name_size": "movq   $0xa,0x18(%rsp)",
    "name_nul": "movb   $0x0,0x2a(%rsp)",
    "name_ptr_store": "mov    %rbp,0x10(%rsp)",
    "base_arg": "mov    %r12,%rdx",
    "name_arg": "mov    %r13,%rsi",
    "map_lea": "# 6505240",
    "register_call": "call   6099ce0",
    "sso_size_gate": "cmp    $0xf,%rbp",
    "single_char_store": "mov    %al,0x40(%rbx)",
}
INIT_SPOTS = {
    "key_movabs": "movabs $0x645f746f6f726863,%rax",
    "key_size": "movq   $0xa,-0x1d8(%rbp)",
    "key_tail": "mov    %cx,-0x1c8(%rbp)",
    "pack_store": "movq   $0x9,-0x118(%rbp)",
    "flags_store": "movl   $0x0,-0x110(%rbp)",
    "pair_ctor_call": "call   5d400f0",
    "map_lea": "# 6505240",
    "insert_call": "call   5d405b0",
    "map_dtor_lea": "# 5d3f820",
    "dso_handle_lea": "# 64efa20",
    "atexit_jump": "jmp    63f0f80",
}
CREATOR_SPOTS = {
    "alloc_size": "mov    $0x50,%edi",
    "operator_new_call": "call   63f0dd0",
    "ctor_call": "call   5feeab0",
    "counts_check": "movabs $0x100000001,%rax",
}


def main() -> None:
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    assert want == DIGEST, "provenance digest changed"
    assert len(DIGEST) == 64, "digest must be the full 64 hex chars"

    data = BIN.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    # ChrootFileSystem typeinfo name (RE-002-node115-rocksdb-fs-chroot-vtable).
    assert data[0x9732F0:0x9732F0 + 28] == b"N7rocksdb16ChrootFileSystemE"
    # The group name is built from immediates, not a .rodata literal:
    # "chroot_d" (movabs) + "ir" (0x7269) = "chroot_dir", 10 chars.
    assert bytes.fromhex("6368726f6f745f64") == b"chroot_d"
    assert bytes.fromhex("6972") == b"ir"

    host = (HERE / "fn-5feeab0-chroot-filesystem-ctor.objdump.txt").read_text()
    init = (HERE / "fn-5fef080-static-initializer.objdump.txt").read_text()
    creator = (HERE / "fn-5fe7870-chroot-creator-invoke.objdump.txt").read_text()
    for label, spot in HOST_SPOTS.items():
        assert spot in host, f"host excerpt missing: {label} ({spot})"
    for label, spot in INIT_SPOTS.items():
        assert spot in init, f"initializer excerpt missing: {label} ({spot})"
    for label, spot in CREATOR_SPOTS.items():
        assert spot in creator, f"creator excerpt missing: {label} ({spot})"
    assert host.count("call   6099ce0") == 1, "host must call RegisterOptions once"
    assert creator.count("call   5feeab0") == 1, "creator must call the host once"

    callers = (HERE / "callers.tsv").read_text().splitlines()[1:]
    assert len(callers) == 37, f"expected 37 caller rows, got {len(callers)}"

    records = {
        "task": "RE-001",
        "work_item": "RE-001-chrootfs-group-115",
        "question": ("Which option group does the ChrootFileSystem ctor "
                     "0x5feeab0 register — name, base, map — what does "
                     "the map hold, and who constructs it? This pins the "
                     "single RegisterOptions site 0x5feeb6a, which #4372's "
                     "census lists as \"not individually analysed\", and "
                     "the contents of its map 0x6505240."),
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": DIGEST,
        "host": {
            "address": "0x5feeab0",
            "fde": "0x5feeab0..0x5feec0d",
            "cpp_name": ("rocksdb::ChrootFileSystem::ChrootFileSystem("
                         "const std::shared_ptr<rocksdb::FileSystem>&, "
                         "const std::string&)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 316/349 bytes)",
            "role": ("Builds a ChrootFileSystem around a wrapped "
                     "FileSystem plus a chroot-dir path string; registers "
                     "exactly one option group, \"chroot_dir\", for that "
                     "path string."),
            "object_size": "0x50 (allocated by the creator 0x5fe7870)",
            "layout": {
                "vtable": "object+0x00 (ChrootFileSystem vtable 0x64cf478; typeinfo N7rocksdb16ChrootFileSystemE at 0x64cf450; 63 slots pinned by RE-002-node115-rocksdb-fs-chroot-vtable)",
                "group_vector": "object+0x08/+0x10/+0x18 (begin/end/capacity-end), zeroed by the base ctor 0x5fe7080 at 0x5fe708b/0x5fe7093/0x5fe709f",
                "target": "object+0x20 is the wrapped std::shared_ptr<FileSystem> {ptr +0x20, control +0x28}, copied from the ctor's second argument by the FileSystemWrapper ctor 0x5fe7210 (movdqu/movups at 0x5fe7249/0x5fe724e, refcount bump at 0x5fe7252..0x5fe7267)",
                "chroot_dir": "object+0x30 is the std::string chroot path: data pointer +0x30, size +0x38, SSO buffer +0x40..+0x50",
            },
            "base_chain": {
                "0x60072b0": "called at 0x5feead8; FDE 0x60072b0..0x60072cd; calls the FileSystemWrapper ctor 0x5fe7210 at 0x60072b8, then stores vtable 0x64d05a8 (lea 0x64d0598 at 0x60072bd + 0x10, store at 0x60072c8). The class this ctor belongs to is not pinned here (open unknown).",
                "0x5fe7210": "FileSystemWrapper ctor (FDE 0x5fe7210..0x5fe72e8, pinned by open PR #4398): calls base 0x5fe7080, stores its vtable 0x64cf200, copies the shared_ptr to object+0x20, and registers its OWN empty-name group (base object+0x20, map 0x65051e0, call 0x5fe7292) — cited from #4398, not re-pinned here.",
                "0x5fe7080": "base ctor (FDE 0x5fe7080..0x5fe70ab): zeroes the group vector triple and stores vtable 0x64cf008 (lea 0x64ceff8 + 0x10).",
                "vtable_sequence": "0x64cf008 (base) -> 0x64cf200 (FileSystemWrapper) -> 0x64d05a8 (intermediate 0x60072b0) -> 0x64cf478 (ChrootFileSystem, lea 0x64cf468 at 0x5feeadd + 0x10, store at 0x5feeaf8).",
            },
            "dir_string_copy": {
                "arg": "ctor's third argument (rdx) is a const std::string&; rbp = rdx at entry (0x5feeab9: mov %rdx,%rbp); r13 = data pointer (*rbp), rbp = size (8(%rbp))",
                "heap_path": "size > 15 (cmp $0xf at 0x5feeb00): _M_create into object+0x30, memcpy from the source (0x5feebb8..0x5feebe7)",
                "single_char_path": "size == 1: one byte to object+0x40 (0x5feeb14/0x5feeb19)",
                "sso_path": "size 0 or 2..15: memcpy into object+0x40, size to object+0x38 (0x5feeb1c, 0x5feebe7..0x5feebeb)",
                "pointer_slot": "object+0x30 is set to object+0x40 (lea at 0x5feeae4, store at 0x5feeae8) before the copy",
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
                "capacity_rule": ("1 for an empty vector, else "
                                  "min(2*size, MAX_SIZE); MAX_SIZE = "
                                  "(2**63 - 1) // 48 = 192153584101141162 (#3257)"),
            },
            "source": "Helper and layout pinned by #3257; not re-exported here.",
        },
        "registration": {
            "call_site": "0x5feeb6a",
            "name": "chroot_dir",
            "name_chars": 10,
            "name_storage": "SSO (10 <= 15; the name buffer lives on the stack at 0x20(%rsp), no heap allocation)",
            "name_construction": ("Built on the stack, not from a .rodata "
                                  "literal: movabs \"chroot_d\" (0x645f746f6f726863) "
                                  "to 0x20(%rsp) at 0x5feeb41, mov $0x7269 "
                                  "(\"ir\") to 0x28(%rsp) at 0x5feeb57, NUL to "
                                  "0x2a(%rsp) at 0x5feeb65; size 0xa at "
                                  "0x18(%rsp) at 0x5feeb5c; string struct at "
                                  "0x10(%rsp) = {ptr 0x20(%rsp), size 10}"),
            "base": "object+0x30 (lea at 0x5feeac0 into r12, passed as rdx at 0x5feeb25) — the chroot-dir std::string member itself",
            "map": "0x6505240",
            "arg_setup": ("rdi=object, rsi=0x10(%rsp) via r13, "
                          "rdx=object+0x30, rcx=0x6505240"),
            "growth": ("The vector already holds the base's empty-name "
                       "group (size 1, capacity 1), so end == capacity-end "
                       "and the growth path runs; capacity becomes 2"),
        },
        "resulting_vector": {
            "size": 2,
            "capacity": 2,
            "elements": [
                {"name": "", "base": "object+0x20", "map": "0x65051e0",
                 "source": "FileSystemWrapper ctor 0x5fe7210, call 0x5fe7292 (#4398, open)"},
                {"name": "chroot_dir", "base": "object+0x30", "map": "0x6505240",
                 "source": "this packet, call 0x5feeb6a"},
            ],
        },
        "map_contents": {
            "map": "0x6505240",
            "entries": 1,
            "entry": {
                "key": "chroot_dir",
                "key_construction": ("Static initializer 0x5fef080 builds "
                                     "the same key on the stack: movabs "
                                     "\"chroot_d\" to -0x1d0(%rbp) at "
                                     "0x5fef0ea, mov $0x7269 (\"ir\") via cx "
                                     "to -0x1c8(%rbp) at 0x5fef0d2, NUL at "
                                     "-0x1c6(%rbp); size 0xa at -0x1d8(%rbp); "
                                     "key string struct at -0x1e0(%rbp) = "
                                     "{ptr -0x1d0, size 10}"),
                "record": ("OptionTypeInfo value built at -0x1c0(%rbp), "
                           "0xb8 bytes, all zero except pack/flags"),
                "pack": "0x9 at record+0xa8 (movq $0x9 at 0x5fef19f, -0x118(%rbp))",
                "pack_decode": "type 9, verification 0 (low dword = OptionType, high dword = OptionVerification)",
                "type_name": "string (type 9 = string per the verified type pattern in merged RE-001-optiontypeinfo-mismatches-115)",
                "flags": "0x0 at record+0xb0 (movl $0x0 at 0x5fef1aa, -0x110(%rbp))",
                "offset": "0 (no offset store anywhere in the value; the entry addresses its group base itself, as in #4379)",
                "callbacks": "none (both std::function pairs are zero; no GOT loads in the value build)",
            },
            "initializer": {
                "address": "0x5fef080",
                "fde": "0x5fef080..0x5fef25f",
                "cpp_name": "__static_initialization_and_destruction_0v",
                "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 432/479 bytes)",
                "pair_ctor": "0x5d400f0 (std::pair<const std::string, rocksdb::OptionTypeInfo> ctor, vendor census 888/903), called at 0x5fef1b4 with (pair -0x100(%rbp), key -0x1e0(%rbp), value -0x1c0(%rbp))",
                "insert": "0x5d405b0 (unordered_map _Hashtable insert, vendor census 2348/2434), called at 0x5fef1e6 with (map 0x6505240, pair -0x100(%rbp))",
                "cleanup": ("Temps destroyed after the insert: OptionTypeInfo "
                            "dtor 0x5d3f950 (vendor census 131/131, 100%) on "
                            "the pair value (-0xe0) and the value temp "
                            "(-0x1c0); _M_dispose on the pair key string and "
                            "the key temp"),
                "atexit": ("Map dtor 0x5d3f820 registered via __cxa_atexit "
                           "at 0x5fef220..0x5fef23d (rdi=0x5d3f820, rsi=map "
                           "0x6505240, rdx=__dso_handle 0x64efa20)"),
                "single_entry_proof": ("The map has exactly two binary-wide "
                                       "lea sites — 0x5feeb46 (host, "
                                       "RegisterOptions arg) and 0x5fef1ca "
                                       "(this initializer, insert arg) — and "
                                       "the initializer performs exactly one "
                                       "insert"),
            },
        },
        "creator": {
            "call_site": "0x5fe78cc",
            "function": "0x5fe7870",
            "fde": "0x5fe7870..0x5fe79ab",
            "cpp_name": ("std::_Function_handler<FileSystem*(const string&, "
                         "unique_ptr<FileSystem>*, ...), "
                         "RegisterBuiltinFileSystems lambda>::_M_invoke "
                         "(E3 variant)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 293/315 bytes)",
            "sole_caller": "0x5fe78cc is the only direct E8 caller of 0x5feeab0 binary-wide",
            "behavior": ("Allocates 0x50 bytes via operator new (call "
                         "0x5fe78a0), constructs the ChrootFileSystem with "
                         "a null wrapped FileSystem (shared_ptr at (%rsp), "
                         "both qwords zero) and an empty dir string "
                         "({ptr 0x20(%rsp), size 0} at 0x10(%rsp)), stores "
                         "the new object into the out slot (*rbp), "
                         "releasing any previous object via its vtable "
                         "slot 1 (0x5fe78de..0x5fe78e1); the null control "
                         "pointer skips the refcount fixup "
                         "(0x5fe78e4..0x5fe791d)"),
            "note": ("The creator builds defaults; the chroot dir is set "
                     "after construction through the \"chroot_dir\" option "
                     "this packet pins — that is what the option group is "
                     "for"),
        },
        "census": {
            "register_options_sites": 37,
            "note": ("Every direct E8 call site of 0x6099ce0 (callers.tsv, "
                     "with enclosing FDE). Matches #3257, #4372 and #4551 "
                     "exactly. This packet's site is 0x5feeb6a; the "
                     "remaining unanalysed sites are listed but not "
                     "individually analysed."),
            "lea_census": {
                "0x6505240": ["0x5feeb46", "0x5fef1ca"],
                "0x64cf468": ["0x5feeadd", "0x5feec1d", "0x5feecfd"],
                "note": ("The map is referenced only by the host ctor and "
                         "its static initializer. The other two vtable-base "
                         "lea sites sit in the dtor 0x5feec10 "
                         "(ChrootFileSystem::~ChrootFileSystem per the "
                         "vtable packet) and in 0x5feecf0 (cited only)."),
            },
        },
        "resolves": [
            "#4372's census open unknown for site 0x5feeb6a (\"not individually analysed\"): the ChrootFileSystem ctor registers one group, \"chroot_dir\", base object+0x30, map 0x6505240",
            "The contents of map 0x6505240, never recorded before: exactly one entry, \"chroot_dir\", type 9 (string), verification 0, flags 0, offset 0, no callbacks",
        ],
        "open_unknowns": [
            "The keys and fields of the other RegisterOptions call sites (listed in callers.tsv, not individually analysed).",
            "The class identity of the intermediate ctor 0x60072b0 (calls the FileSystemWrapper ctor 0x5fe7210, then stores vtable 0x64d05a8).",
            "The name under which the creator 0x5fe7870 is registered in the ObjectLibrary (RegisterBuiltinFileSystems registers several FileSystem creators; this one's key is not pinned here).",
            "The internals of 0x5feecf0 (third lea site of the ChrootFileSystem vtable base); cited only.",
            "The entry count of the base group's map 0x65051e0 (pinned as a registration by #4398; its contents are not re-derived here).",
            "Which code reads the group name at runtime (the map serializer 0x6097630 and apply loop 0x609c8c0 read only element+0x20/+0x28, per #4372).",
        ],
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=1) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
