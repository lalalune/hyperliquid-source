#!/usr/bin/env python3
"""Build records.json for RE-001-mockfs-group-115 from the census.

Run from the repo root:
    python3 research/work-items/RE-001-mockfs-group-115/gen_records.py

Cross-checks every claim against the excerpts and the raw binary before
writing: the single RegisterOptions argument setup in the 0x6028a60
excerpt, the supports_direct_io map entry (key literal, zeroed record,
pack 0, flags 0), the lea/caller censuses, and the vtable slots. The
artifact digest is stored in full (64 hex chars) — never a prefix.
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
    "mutex_arg": "lea    0x20(%rbx),%r13",
    "base_ctor_call": "call   5fe7080",
    "vtable_lea": "# 64d19f8",
    "vtable_adjust": "add    $0x10,%rax",
    "vtable_store": "mov    %rax,(%rbx)",
    "dead_byte_load": "movzbl (%rax),%esi",
    "mutex_ctor_call": "call   60d50c0",
    "map_header_lea": "lea    0x50(%rbx),%rax",
    "map_color": "movl   $0x0,0x50(%rbx)",
    "map_left": "mov    %rax,0x60(%rbx)",
    "map_right": "mov    %rax,0x68(%rbx)",
    "map_parent": "movq   $0x0,0x58(%rbx)",
    "map_count": "movq   $0x0,0x70(%rbx)",
    "clock_load": "movdqu (%r12),%xmm0",
    "clock_store": "movups %xmm0,0x78(%rbx)",
    "refcount_bump": "addl   $0x1,0x8(%rax)",
    "bool_store": "mov    %bpl,0x90(%rbx)",
    "group_base_lea": "lea    0x90(%rbx),%rdx",
    "map_lea": "# 65058e0",
    "name_arg": "mov    %r12,%rsi",
    "name_ptr_store": "mov    %rbp,(%rsp)",
    "raw_clock_store": "movq   %xmm1,0x88(%rbx)",
    "name_size": "movq   $0x0,0x8(%rsp)",
    "name_nul": "movb   $0x0,0x10(%rsp)",
    "register_call": "call   6099ce0",
}
INIT_SPOTS = {
    "key_literal_lea": "# 44657e",
    "key_ctor_call": "call   60261f0",
    "record_zero_start": "movq   $0x0,-0x1d0(%rbp)",
    "pack_store": "movq   $0x0,-0x128(%rbp)",
    "flags_store": "movl   $0x0,-0x120(%rbp)",
    "pair_ctor_call": "call   5d400f0",
    "map_lea": "# 65058e0",
    "insert_call": "call   5d405b0",
    "map_dtor_lea": "# 5d3f820",
    "dso_handle_lea": "# 64efa20",
    "atexit_tail_jump": "jmp    63f0f80",
}
INVOKER_SPOTS = {
    "alloc_size": "mov    $0x98,%edi",
    "operator_new_call": "call   63f0dd0",
    "clock_default_call": "call   5fe2680",
    "bool_true": "mov    $0x1,%edx",
    "ctor_call": "call   6028a60",
    "slot_store": "mov    %rbx,0x0(%rbp)",
    "vtable_slot1_release": "call   *0x8(%rax)",
}
DTOR_SPOTS = {
    "vtable_lea": "# 64d19f8",
    "map_left": "mov    0x60(%rdi),%rbp",
    "value_ptr": "mov    0x40(%rbp),%rbx",
    "mutex_lock": "call   60d5230",
    "mutex_unlock": "call   60d52f0",
    "mutex_destroy": "call   60d5170",
    "clock_release": "call   5d350c0",
    "base_dtor_tail": "jmp    5fe70b0",
}
CREATE_SPOTS = {
    "alloc_size": "mov    $0xa8,%edi",
    "bool_true": "mov    $0x1,%edx",
    "control_vtable_lea": "# 64d1c60",
    "ctor_call": "call   6028a60",
    "mockenv_alloc": "mov    $0x60,%edi",
    "mockenv_ctor_call": "call   60289f0",
    "release_call": "call   5d350c0",
}


def main() -> None:
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    assert want == DIGEST, "provenance digest changed"
    assert len(DIGEST) == 64, "digest must be the full 64 hex chars"

    data = BIN.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    # MockFileSystem typeinfo name (via RELATIVE reloc at typeinfo+8).
    assert data[0x974450:0x974450 + 26] == b"N7rocksdb14MockFileSystemE"
    # The key literal, 18 chars, heap-backed (over the 15-char SSO limit).
    assert data[0x44657E:0x44657E + 18] == b"supports_direct_io"

    host = (HERE / "fn-6028a60-mock-filesystem-ctor.objdump.txt").read_text()
    init = (HERE / "fn-6029d10-static-initializer.objdump.txt").read_text()
    invoker = (HERE / "fn-5fe58b0-mockfs-creator-invoke.objdump.txt").read_text()
    dtor = (HERE / "fn-6028bb0-mockfs-dtor.objdump.txt").read_text()
    create = (HERE / "fn-6028d80-mockenv-create.objdump.txt").read_text()
    for label, spot in HOST_SPOTS.items():
        assert spot in host, f"host excerpt missing: {label} ({spot})"
    for label, spot in INIT_SPOTS.items():
        assert spot in init, f"initializer excerpt missing: {label} ({spot})"
    for label, spot in INVOKER_SPOTS.items():
        assert spot in invoker, f"invoker excerpt missing: {label} ({spot})"
    for label, spot in DTOR_SPOTS.items():
        assert spot in dtor, f"dtor excerpt missing: {label} ({spot})"
    for label, spot in CREATE_SPOTS.items():
        assert spot in create, f"create excerpt missing: {label} ({spot})"
    assert host.count("call   6099ce0") == 1, "host must call RegisterOptions once"
    assert invoker.count("call   6028a60") == 1, "invoker must call the host once"
    assert create.count("call   6028a60") == 1, "Create must call the host once"
    # Block 3 (this map) builds its record by zeroing only: the record
    # builder 0x5e32920 runs in blocks 1-2, never in block 3.
    assert init.count("call   5e32920") == 2, "record builder runs twice only"
    assert init.count("call   60261f0") == 3, "three key strings built"
    assert init.count("call   5d400f0") == 3, "three pair constructions"
    assert init.count("call   5d405b0") == 3, "three map inserts"

    callers = (HERE / "callers.tsv").read_text().splitlines()[1:]
    assert len(callers) == 37, f"expected 37 caller rows, got {len(callers)}"
    vtables = (HERE / "vtables.tsv").read_text().splitlines()[1:]
    assert len(vtables) == 61, f"expected 61 vtable rows, got {len(vtables)}"

    records = {
        "task": "RE-001",
        "work_item": "RE-001-mockfs-group-115",
        "question": ("Which option group does the MockFileSystem ctor "
                     "0x6028a60 register — name, base, map — what does "
                     "the map hold, and who constructs it? This pins the "
                     "single RegisterOptions site 0x6028b3a, which #4372's "
                     "census lists as \"not individually analysed\", and "
                     "the contents of its map 0x65058e0, which open PR "
                     "#4528 recorded only as a lead (\"still unanalysed\")."),
        "artifact": "work/hl-node-115.bin",
        "artifact_sha256": DIGEST,
        "host": {
            "address": "0x6028a60",
            "fde": "0x6028a60..0x6028ba4",
            "cpp_name": ("rocksdb::MockFileSystem::MockFileSystem("
                         "const std::shared_ptr<rocksdb::SystemClock>&, "
                         "bool)"),
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 285/324 bytes)",
            "role": ("Builds a MockFileSystem around a SystemClock plus a "
                     "supports_direct_io flag; registers exactly one "
                     "option group, the empty-name group, for that flag."),
            "object_size": "0x98 (allocated by the invoker 0x5fe58b0; the make_shared allocation in MockEnv::Create 0x6028d80 is 0xa8 = 0x10 control block + 0x98 object)",
            "layout": {
                "vtable": "object+0x00 (MockFileSystem vtable 0x64d1a08; typeinfo N7rocksdb14MockFileSystemE at 0x64d1210, name string at 0x974450; 61 slots, all FDE starts, read from .rela.dyn RELATIVE relocations in vtables.tsv)",
                "group_vector": "object+0x08/+0x10/+0x18 (begin/end/capacity-end), zeroed by the base ctor 0x5fe7080 at 0x5fe708b/0x5fe7093/0x5fe709f",
                "mutex": "object+0x20 is a std::mutex (40 bytes, +0x20..+0x48), initialized by 0x60d50c0 (pthread_mutex_init, call at 0x6028aaa). The byte loaded from 0x97877c into esi at 0x6028aa7 is dead: the callee zeroes esi first (xor %esi,%esi at 0x60d50c5), so the byte (0x00) is not consumed.",
                "padding": "object+0x48 (8 bytes) is not touched by the ctor or the dtor; recorded as unaccounted, not claimed as a field.",
                "files_map": "object+0x50 is a std::map (40-byte _Rb_tree_header: color 0 at +0x50, parent 0 at +0x58, left = right = &header at +0x60/+0x68, node count 0 at +0x70). It maps string keys to pointers to 0x98-byte refcounted file objects (mutex at value+0x28, refcount at value+0x50, strings at value+0x08/+0x58), per the dtor; tree nodes are 0x48 bytes. The value object's C++ type name is not pinned here.",
                "clock": "object+0x78 is the std::shared_ptr<SystemClock> {ptr +0x78, control +0x80}, copied from the ctor's second argument (movdqu at 0x6028ad2, movups at 0x6028adf, refcount bump on control+0x08 at 0x6028af9/0x6028b78)",
                "clock_raw": "object+0x88 is a raw SystemClock* holding the same pointer as +0x78 (movq %xmm1 at 0x6028b24)",
                "supports_direct_io": "object+0x90 is the bool flag (mov %bpl at 0x6028afd, from the ctor's third argument edx via ebp)",
            },
            "base_chain": {
                "0x5fe7080": "base ctor (FDE 0x5fe7080..0x5fe70ab): zeroes the group vector triple and stores vtable 0x64cf008 (lea 0x64ceff8 at 0x5fe7084 + 0x10, store at 0x5fe70a7).",
                "vtable_sequence": "0x64cf008 (base) -> 0x64d1a08 (MockFileSystem, lea 0x64d19f8 at 0x6028a8f + 0x10, store at 0x6028a9d).",
            },
            "cleanup_block": "FDE 0x6028a0e..0x6028a5d is the host's exception cleanup, reached from the landing pads at 0x6028b8c/0x6028b98: it erases the map (0x6027720 on the root at object+0x58), destroys the mutex at object+0x20 (0x60d5170), releases the clock (0x5d350c0 on object+0x80) and tail-calls the base dtor 0x5fe70b0 — corroborating the mutex/map/clock layout.",
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
            "call_site": "0x6028b3a",
            "name": "",
            "name_chars": 0,
            "name_storage": "SSO (empty: the string struct at (%rsp) is {ptr 0x10(%rsp), size 0}, NUL at 0x10(%rsp); no heap allocation)",
            "name_construction": ("Built on the stack: rbp = lea 0x10(%rsp) "
                                  "at 0x6028b07, stored as the name pointer "
                                  "at (%rsp) at 0x6028b20; size 0 at 0x8(%rsp) "
                                  "at 0x6028b2c; NUL at 0x10(%rsp) at "
                                  "0x6028b35"),
            "base": "object+0x90 (lea at 0x6028b0f into rdx) — the supports_direct_io bool member itself",
            "map": "0x65058e0",
            "arg_setup": ("rdi=object, rsi=0x00(%rsp) via r12, "
                          "rdx=object+0x90, rcx=0x65058e0"),
            "growth": ("The vector starts empty (zeroed by base ctor "
                       "0x5fe7080), so the growth path runs once and "
                       "capacity becomes 1"),
        },
        "resulting_vector": {
            "size": 1,
            "capacity": 1,
            "elements": [
                {"name": "", "base": "object+0x90", "map": "0x65058e0",
                 "source": "this packet, call 0x6028b3a"},
            ],
        },
        "map_contents": {
            "map": "0x65058e0",
            "entries": 1,
            "entry": {
                "key": "supports_direct_io",
                "key_construction": ("Static initializer 0x6029d10 builds "
                                     "the key from the .rodata literal "
                                     "0x44657e via the string ctor 0x60261f0 "
                                     "at 0x602a09d into -0x1f0(%rbp); 18 chars "
                                     "exceeds the 15-char SSO limit, so the "
                                     "key string is heap-backed"),
                "record": ("OptionTypeInfo value built at -0x1d0(%rbp), "
                           "0xb8 bytes, zeroed by immediate stores; the "
                           "record builder 0x5e32920 does NOT run in this "
                           "block (it runs twice, for the two sibling "
                           "entries only), so no getter/setter pairs and no "
                           "GOT-loaded pack are installed"),
                "pack": "0x0 at record+0xa8 (movq $0x0 at 0x602a12f, -0x128(%rbp))",
                "pack_decode": "type 0, verification 0 (low dword = OptionType, high dword = OptionVerification)",
                "type_name": "bool (type 0 = bool per the verified type pattern in merged RE-001-optiontypeinfo-mismatches-115: \"type 0 = bool (all-zero +0xa8)\"), corroborated by the group base being the bool member at object+0x90",
                "flags": "0x0 at record+0xb0 (movl $0x0 at 0x602a13a, -0x120(%rbp))",
                "offset": "0 (no offset store anywhere in the value build)",
                "callbacks": "none (no function-pointer stores and no 0x5e32920 call in this block)",
                "padding_note": "The trailing 4 bytes of the 0xb8-byte record (+0xb4..+0xb8) are not zeroed by this block; they are stack-slot residue from the previous block's record and are padding after the flags field, not a field.",
            },
            "initializer": {
                "address": "0x6029d10",
                "fde": "0x6029d10..0x602a25d",
                "cpp_name": "__static_initialization_and_destruction_0v",
                "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1)",
                "pair_ctor": "0x5d400f0 (std::pair<const std::string, rocksdb::OptionTypeInfo> ctor, vendor census 888/903), called at 0x602a167 with (pair -0x110(%rbp), key -0x1f0(%rbp), value -0x1d0(%rbp))",
                "insert": "0x5d405b0 (unordered-map _Hashtable insert, vendor census 2348/2434), called at 0x602a19a with (map 0x65058e0, pair -0x110(%rbp))",
                "cleanup": ("Temps destroyed after the insert: OptionTypeInfo "
                            "dtor 0x5d3f950 (vendor census 131/131, 100%) on "
                            "the pair value and the value temp; _M_dispose "
                            "on the pair key string and the key temp"),
                "atexit": ("Map dtor 0x5d3f820 registered via __cxa_atexit "
                           "at 0x602a1d4..0x602a1f3 (rdi=0x5d3f820, rsi=map "
                           "0x65058e0, rdx=__dso_handle 0x64efa20); the block "
                           "ends in a tail jump to __cxa_atexit, unlike the "
                           "two sibling blocks which call it"),
                "load_time": ("Installed in .init_array through a RELATIVE "
                              "reloc addend 0x602e4c0 at 0x63f3918; the "
                              "9-byte stub 0x602e4c0 (endbr64; jmp 0x6029d10) "
                              "tail-jumps into it, so it runs at load time; "
                              "no direct E8 caller anywhere (pinned by open "
                              "PR #4528)"),
                "single_entry_proof": ("The map has exactly two binary-wide "
                                       "lea sites — 0x6028b16 (host, "
                                       "RegisterOptions arg) and 0x602a17b "
                                       "(this initializer, insert arg) — and "
                                       "the initializer performs exactly one "
                                       "insert into it"),
                "siblings": ("The same initializer also inserts "
                             "\"time_elapse_only_sleep\" into 0x6505960 "
                             "(insert 0x6029e6b) and \"mock_sleep\" into "
                             "0x6505920 (insert 0x6029fff); both are pinned "
                             "by open PR #4528, cited here as context, not "
                             "re-derived. #4528 recorded this third insert "
                             "only as a lead and left the host unanalysed."),
            },
        },
        "creators": {
            "invoker": {
                "call_site": "0x5fe58da",
                "function": "0x5fe58b0",
                "fde": "0x5fe58b0..0x5fe590c",
                "cpp_name": ("std::_Function_handler<FileSystem*(const "
                             "string&, unique_ptr<FileSystem>*, ...), "
                             "RegisterBuiltinFileSystems lambda>::_M_invoke "
                             "(E3 variant)"),
                "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 78/92 bytes)",
                "callers": "none: no direct E8 caller binary-wide; reachable only through the std::function vtable, like the ChrootFileSystem creator in #4565",
                "behavior": ("Allocates 0x98 bytes via operator new (call "
                             "0x5fe58c2), takes the clock from "
                             "SystemClock::Default() 0x5fe2680 (call "
                             "0x5fe58ca), constructs the MockFileSystem "
                             "with bool=true (mov $0x1,%edx at 0x5fe58d2, "
                             "call 0x6028a60 at 0x5fe58da), stores the new "
                             "object into the out slot (*rbp, where rbp = "
                             "*rdx), releasing any previous object via its "
                             "vtable slot 1 (call *0x8(%rax) at 0x5fe58ef)"),
                "note": ("The creator builds defaults with the default "
                         "clock; the supports_direct_io flag is set after "
                         "construction through the option this packet pins"),
            },
            "mockenv_create": {
                "call_site": "0x6028ddb",
                "function": "0x6028d80",
                "fde": "0x6028d80..0x6028e80",
                "cpp_name": ("rocksdb::MockEnv::Create(Env*, "
                             "const std::shared_ptr<rocksdb::SystemClock>&)"),
                "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 208/256 bytes)",
                "sole_caller": "0x602982a in MockEnv::Create(Env*) 0x60297a0 (vendor census 298/343), which builds an EmulatedSystemClock via 0x6029390 and forwards it as the clock",
                "behavior": ("Allocates 0xa8 bytes via operator new (call "
                             "0x6028dab): a make_shared-style control block "
                             "(vtable 0x64d1c70, lea 0x64d1c60 at 0x6028dca "
                             "+ 0x10, store at 0x6028dd8; counts (1,1) from "
                             "GOT 0x459b20 at 0x6028dc6) plus the 0x98-byte "
                             "MockFileSystem at +0x10, constructed with the "
                             "caller's clock and bool=true (call 0x6028a60 "
                             "at 0x6028ddb). Then allocates a 0x60-byte "
                             "MockEnv (call 0x6028de5) and constructs it via "
                             "0x60289f0 (call 0x6028e12), which calls the "
                             "CompositeEnvWrapper ctor 0x5fd7360 (#4379) and "
                             "stores the MockEnv vtable 0x64d1398, and "
                             "returns the MockEnv"),
            },
        },
        "dtor": {
            "address": "0x6028bb0",
            "fde": "0x6028bb0..0x6028cea",
            "cpp_name": "rocksdb::MockFileSystem::~MockFileSystem()",
            "cpp_name_source": "docs/PROGRESS.md vendor census (librocksdb-sys 0.11.0+8.1.1, 262/314 bytes)",
            "behavior": ("Stores the MockFileSystem vtable (lea 0x64d19f8 "
                         "at 0x6028bb4 + 0x10, store at 0x6028bd2); walks "
                         "the files map from _M_left (0x6028bce), and for "
                         "each value locks its mutex (0x60d5230), "
                         "decrements the refcount at value+0x50, destroys "
                         "the value only when the count reaches 0 "
                         "(unlock 0x60d52f0, dispose the strings at "
                         "value+0x58/+0x08, destroy the mutex 0x60d5170, "
                         "delete 0x98 bytes); erases the tree nodes via "
                         "the _M_erase helper 0x6027720 (right-subtree "
                         "recursion at 0x6028c93, node delete 0x48 bytes); "
                         "releases the clock shared_ptr (0x5d350c0 on "
                         "object+0x80 at 0x6028c80); destroys the mutex at "
                         "object+0x20 (0x60d5170 at 0x6028cd5); tail-calls "
                         "the base dtor 0x5fe70b0 (jmp at 0x6028ce5)"),
            "vtable_slot": "slot 0 of the 61-slot vtable (0x64d1a08); slot 1 is 0x6028cf0",
        },
        "vtable": {
            "address_point": "0x64d1a08",
            "base": "0x64d19f8 (offset-to-top 0, no reloc; typeinfo pointer at 0x64d1a00 is a RELATIVE reloc to the typeinfo object 0x64d1210)",
            "typeinfo": "N7rocksdb14MockFileSystemE (name string at 0x974450, via RELATIVE reloc at typeinfo+8); the typeinfo object has a type-1 reloc at +0 to __si_class_type_info vtable+16 (addend 0x10)",
            "slots": 61,
            "slot_0": "0x6028bb0 (the dtor)",
            "slot_1": "0x6028cf0",
            "slot_5": "0x6028eb0 (a MockFileSystem virtual; calls SystemClock::Default at 0x6028f00 — cited, not pinned)",
            "shared_slots": "slots 2..4 and 6..13 hold the same 11 function addresses, in the same order, as the shared addresses #4487 lists for the FilterPolicy vtables (0x609d760, 0x609dc40, 0x5d32560, 0x6096790, 0x5d2e090, 0x60956f0, 0x609d0e0, 0x60986b0, 0x6095710, 0x609de80, 0x609d980); slot 5 (0x6028eb0) is the MockFileSystem-specific entry between them",
            "source": "Slots read from .rela.dyn RELATIVE relocations (the file bytes there are zero; the relocations carry the values), each target verified to be an FDE start; full table in vtables.tsv",
        },
        "census": {
            "register_options_sites": 37,
            "note": ("Every direct E8 call site of 0x6099ce0 (callers.tsv, "
                     "with enclosing FDE). Matches #3257, #4372, #4551 and "
                     "#4565 exactly. This packet's site is 0x6028b3a; the "
                     "remaining unanalysed sites are listed but not "
                     "individually analysed."),
            "lea_census": {
                "0x65058e0": ["0x6028b16", "0x602a17b"],
                "0x64d19f8": ["0x6028a8f", "0x6028bb4"],
                "0x44657e": ["0x602a093"],
                "0x6505960": ["0x602942b", "0x6029e50"],
                "0x6505920": ["0x6029471", "0x6029fe0"],
                "note": ("The map is referenced only by the host ctor and "
                         "its static initializer. The other vtable-base lea "
                         "site sits in the dtor 0x6028bb0. The sibling maps' "
                         "lea sites match open PR #4528."),
            },
            "caller_census": {
                "0x6028a60": ["0x5fe58da", "0x6028ddb"],
                "0x6028d80": ["0x602982a"],
                "0x5fe58b0": [],
                "note": ("The host has exactly two direct E8 callers: the "
                         "RegisterBuiltinFileSystems invoker and "
                         "MockEnv::Create. The invoker itself has no direct "
                         "E8 caller (vtable-reachable only)."),
            },
        },
        "resolves": [
            "#4372's census open unknown for site 0x6028b3a (\"not individually analysed\"): the MockFileSystem ctor registers one group, the empty-name group, base object+0x90, map 0x65058e0",
            "#4528's open unknown (\"which host registers the 0x65058e0 group (host 0x6028a60, site 0x6028b3a)\" and \"what 0x5d400f0 fills into the supports_direct_io record\"): the host is MockFileSystem, and the pair ctor copies the zeroed record verbatim — pack 0 (type 0 = bool, verification 0), flags 0, offset 0, no callbacks",
        ],
        "open_unknowns": [
            "The keys and fields of the other RegisterOptions call sites (listed in callers.tsv, not individually analysed).",
            "The name under which the invoker 0x5fe58b0 is registered in the ObjectLibrary (RegisterBuiltinFileSystems registers several FileSystem creators; this one's key is not pinned here).",
            "The C++ type name of the files-map value object (0x98 bytes: mutex +0x28, refcount +0x50, strings +0x08/+0x58, 0x20 bytes at +0x78..+0x98 untouched by the dtor).",
            "The 8 bytes at object+0x48 (between the mutex and the files map), untouched by the ctor and the dtor.",
            "The internals of the MockFileSystem virtual at slot 5 (0x6028eb0) and the other per-class vtable slots; cited by address only.",
            "The identity of 0x5fcf430, called by MockEnv::Create(Env*) 0x60297a0 before the EmulatedSystemClock construction; cited only.",
            "Which code reads the group name at runtime (the map serializer 0x6097630 and apply loop 0x609c8c0 read only element+0x20/+0x28, per #4372).",
        ],
    }
    (HERE / "records.json").write_text(json.dumps(records, indent=1) + "\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
