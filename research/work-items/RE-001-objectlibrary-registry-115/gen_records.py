"""Generate records.json for the RE-001-objectlibrary-registry-115
packet from the census outputs and the verbatim excerpts.

Usage (from the repository root):
    python3 research/work-items/RE-001-objectlibrary-registry-115/gen_records.py

The JSON holds semantic records only: the registry / map / node /
PatternEntry layouts, the vtable maps (with the boundary to the
neighbouring ObjectRegistry control-block vtable), caller counts,
relocation rows, string literals and open unknowns.
Instruction-level detail lives only in the verbatim objdump
excerpts. No windows are re-shipped from earlier PRs.
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = [
    0x61F8B60, 0x61F8700, 0x5FD1DA0, 0x5FD1C60, 0x5FD17C0,
    0x5FD24C0, 0x5FD20D0, 0x5FD27C0,
    0x5FEFC70, 0x5FEFD00, 0x5FF7900, 0x5FEFD50, 0x5FEFF70,
    0x5FF7820,
    0x5FF2030, 0x5FF2150, 0x61F8670, 0x61F8430, 0x61F8280, 0x61F8120,
    0x5FCC700, 0x5FCD840, 0x5FCC7E0, 0x5FCC7F0,
    0x5FCC6B0, 0x5FCD7F0, 0x5FCC7C0, 0x5FCC7D0,
    0x5FCC6A0, 0x5FCC830,
]


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def va_to_file_off(data, va):
    """Translate a virtual address to a file offset via LOADs."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    raise SystemExit("no LOAD segment covers %#x" % va)


def relative_records():
    """offset -> addend for every R_X86_64_RELATIVE record."""
    out = subprocess.run(["readelf", "-r", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    rel = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            rel[int(parts[0], 16)] = int(parts[3], 16)
    return rel


def census_counts():
    """(calls, jumps, leas) per target, parsed from callers.tsv."""
    counts = {}
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        _site, target, _caller, kind = line.split("\t")
        target = int(target, 16)
        entry = counts.setdefault(target, {"calls": 0, "jumps": 0, "leas": 0})
        entry[{"call": "calls", "tail jump": "jumps",
               "lea": "leas"}[kind]] += 1
    return counts


def qword_hits(data):
    """Raw-binary qword hits per target (8-byte strides)."""
    hits = {t: 0 for t in TARGETS}
    for off in range(0, len(data) - 7, 8):
        val = struct.unpack_from("<Q", data, off)[0]
        if val in hits:
            hits[val] += 1
    return hits


def main():
    data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    counts = census_counts()
    for addr in TARGETS:
        counts.setdefault(addr, {"calls": 0, "jumps": 0, "leas": 0})
    hits = qword_hits(data)
    rel = relative_records()
    rel_counts = {}
    for addr in TARGETS:
        rel_counts[addr] = sum(1 for a in rel.values() if a == addr)
    reloc_rows = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        parts = line.split()
        reloc_rows.append({"offset": int(parts[0], 16),
                           "addend": int(parts[3], 16)})

    def vtable_map(base, nslots):
        return ["0x%x" % rel.get(base + i * 8, 0) for i in range(nslots)]

    node_env_map = vtable_map(0x64CDE68, 4)
    node_clock_map = vtable_map(0x64CDE98, 4)
    env_ptr_cb_map = vtable_map(0x64CDEC8, 5)
    cb_map = vtable_map(0x64D00F0, 5)
    pattern_map = vtable_map(0x64D8ED0, 4)
    objreg_cb_map = vtable_map(0x64D8F00, 5)

    def typeinfo_name(header):
        ti = rel.get(header + 8)
        name_ptr = rel.get(ti + 8) if ti else None
        if name_ptr is None:
            return None
        off = va_to_file_off(data, name_ptr)
        end = data.index(b"\x00", off)
        return data[off:end].decode()

    literals = []
    for addr, text in [
            (0x44A397, "Environment"),
            (0x438369, "SystemClock"),
            (0x447686, "MockEnv"),
            (0x43E762, "CompositeEnv"),
            (0x4372AE, "TimeEmulatedSystemClock"),
            (0x4376FD, "")]:
        off = va_to_file_off(data, addr)
        raw = data[off:off + len(text) + 1]
        assert raw == text.encode() + b"\x00", "%#x literal mismatch" % addr
        literals.append({"addr": addr, "offset": off, "text": text})
    off = va_to_file_off(data, 0x459B20)
    assert data[off:off + 8] == struct.pack("<Q", 0x100000001)
    literals.append({"addr": 0x459B20, "offset": off,
                     "text": "<packed counts 0x100000001>"})

    census = {}
    for addr in sorted(TARGETS):
        census["0x%x" % addr] = {
            "calls": counts[addr]["calls"],
            "jumps": counts[addr]["jumps"],
            "leas": counts[addr]["leas"],
            "qwords": hits[addr],
            "relative": rel_counts[addr],
        }

    records = {
        "target": {"artifact": "work/hl-node-115.bin",
                   "sha256": digest, "node": 115},
        "work_item": "RE-001-objectlibrary-registry-115",
        "task": "RE-001",
        "question": (
            "Pin node #115's ObjectLibrary registry end-to-end: the "
            "Default getter 0x61f8b60, the registry count 0x61f8700, "
            "the unordered-map find-or-insert 0x5fd1da0 with its "
            "rehash 0x5fd1c60 and vector-insert 0x5fd17c0, the "
            "registration entry points insert 0x5fd24c0 / "
            "default-init 0x5fd20d0 / register 0x5fd27c0, the "
            "control-block teardown (D1/D0/_M_dispose/_M_destroy/"
            "_M_get_deleter) with the map destroy 0x5ff7820, the "
            "PatternEntry vtable and its matcher 0x61f8670 with the "
            "string matcher 0x61f8430 and per-element matcher "
            "0x61f8280, and the FactoryEntry node vtables for Env "
            "and SystemClock. This answers the open unknown carried "
            "by PR #3948 about the role of the \"Environment\" "
            "string: every insert() registration lands under the "
            "single map key \"Environment\"; only default-init uses "
            "the map key \"SystemClock\"."),
        "registry": {
            "size": 0x80,
            "holder_addr": 0x6509110,
            "guard_addr": 0x6509108,
            "control_block_size": 0x90,
            "fresh_counts": 0x100000001,
            "fields": [
                {"offset": 0x00, "what": "mutex (+0x00..0x28)"},
                {"offset": 0x28, "what": "std::unordered_map "
                 "{buckets, bucket_count, before_begin, "
                 "element_count, max_load_factor, next_resize, "
                 "single_bucket}"},
                {"offset": 0x60, "what": "std::string name "
                 "\"default\" (SSO, 7 chars)"},
            ],
            "map_fields": [
                {"offset": 0x00, "what": "buckets pointer "
                 "(initially &obj+0x58, the single bucket)"},
                {"offset": 0x08, "what": "bucket_count (1)"},
                {"offset": 0x10, "what": "before_begin (0)"},
                {"offset": 0x18, "what": "element_count (0)"},
                {"offset": 0x20, "what": "max_load_factor (1.0f, "
                 "immediate 0x3f800000)"},
                {"offset": 0x28, "what": "next_resize (0)"},
                {"offset": 0x30, "what": "single_bucket (0)"},
            ],
            "map_node": {
                "size": 0x48,
                "fields": [
                    {"offset": 0x00, "what": "next node"},
                    {"offset": 0x08, "what": "std::string key (0x20)"},
                    {"offset": 0x28, "what": "std::vector<"
                     "FactoryEntry*> {begin, end, capacity}"},
                    {"offset": 0x40, "what": "stored hash"},
                ],
            },
        },
        "getter": {
            "addr": 0x61F8B60, "fde": "0x61f8b60..0x61f8d12",
            "role": "ObjectLibrary::Default(): function-local-static "
                    "singleton. Guard byte 0x6509108, holder at "
                    "0x6509110 (16 bytes: object ptr, control-block "
                    "ptr); __cxa_guard_acquire/release; allocates a "
                    "0x10-byte holder and a 0x90-byte make_shared "
                    "block; control-block vtable 0x64d00f0, packed "
                    "counts 0x100000001 loaded from the global at "
                    "0x459b20; object at control+0x10. Fast path "
                    "returns the holder address; callers dereference "
                    "[0] for the object.",
            "calls": counts[0x61F8B60]["calls"],
            "callers": ["0x5fd210c (default-init 0x5fd20d0)",
                        "0x5fd27f4 (register 0x5fd27c0)",
                        "0x5fec460", "0x6006b3d", "0x6075c00",
                        "0x6093a80", "0x6138a40", "0x613c3cd",
                        "0x61968d0", "0x61a5bb0", "0x61c1255",
                        "0x61ccfd0", "0x61cd8d0", "0x61e7f70",
                        "0x61f3290", "0x61f933d", "0x61fc100"],
            "excerpt": "getter-61f8b60.objdump.txt",
        },
        "count": {
            "addr": 0x61F8700, "fde": "0x61f8700..0x61f8760",
            "signature": "(registry, out_ptr)",
            "role": "Locks the registry mutex (lock failure throws "
                    "system_error); *out = map.element_count "
                    "(registry+0x40); walks the before_begin chain "
                    "summing (node+0x30 - node+0x28)/8 per node "
                    "(value-vector lengths); unlocks; returns the "
                    "total. So *out is the number of distinct map "
                    "keys and the return is the total registered "
                    "entries. After register() + default-init(): "
                    "*out = 2, return = 3.",
            "calls": counts[0x61F8700]["calls"],
            "callers": ["0x5fd2310 (default-init)",
                        "0x5fd28ff (register)",
                        "0x5fec369", "0x613875c", "0x61963b5",
                        "0x61ccbfc", "0x61f2e0c", "0x62088e1"],
            "excerpt": "count-61f8700.objdump.txt",
        },
        "find_or_insert": {
            "addr": 0x5FD1DA0, "fde": "0x5fd1da0..0x5fd1ffa",
            "cold_fde": "0x5fd1ffa..0x5fd20c4",
            "signature": "(map, key_string)",
            "role": "_Hash_bytes(key.data, key.len, 0xc70f6907); "
                    "bucket = hash % bucket_count; walks the bucket "
                    "chain comparing stored hash, then key length, "
                    "then memcmp; on a match returns &node+0x28 (the "
                    "value vector); on a miss allocates a 0x48-byte "
                    "node, move-constructs the key string into "
                    "node+0x08, zeroes node+0x28..+0x40, calls "
                    "_M_need_rehash and rehashes via 0x5fd1c60 if "
                    "needed, links the node into the bucket (or "
                    "before_begin if the bucket was empty), "
                    "element_count++, stores the hash at node+0x40, "
                    "returns &node+0x28. The cold FDE is the "
                    "exception landing pad: it destroys the "
                    "partially built node, the key string and the "
                    "std::function at rsp+0x40, then _Unwind_Resume.",
            "calls": counts[0x5FD1DA0]["calls"],
            "callers": ["0x5fd22b4 (default-init)",
                        "0x5fd2618 (insert)",
                        "0x5febc61", "0x5ff82fa", "0x6005e79",
                        "0x6075e13", "0x6093cf9", "0x6137b87",
                        "0x613818f", "0x613c18f", "0x6194e60",
                        "0x6196324", "0x61a596f", "0x61c0ee1",
                        "0x61cb96e", "0x61cbfa3", "0x61cdb49",
                        "0x61e81fa", "0x61f123e", "0x61fc377",
                        "0x62084bb", "0x620886f"],
            "excerpt": "find-or-insert-5fd1da0.objdump.txt",
            "cold_excerpt": "find-or-insert-cold-5fd1ffa.objdump.txt",
        },
        "rehash": {
            "addr": 0x5FD1C60, "fde": "0x5fd1c60..0x5fd1d9d",
            "role": "_Hashtable::_M_rehash_aux: allocates a new "
                    "bucket array (count*8, memset 0), re-links "
                    "every node by hash % new_count, frees the old "
                    "buckets unless they were the single bucket.",
            "calls": counts[0x5FD1C60]["calls"],
            "callers": ["0x5fd1f28 (find-or-insert)"],
            "excerpt": "rehash-5fd1c60.objdump.txt",
        },
        "vector_insert": {
            "addr": 0x5FD17C0, "fde": "0x5fd17c0..0x5fd1962",
            "role": "std::vector<T*>::insert(vec, pos, &value) for "
                    "8-byte elements: size check vs max "
                    "0xfffffffffffffff (throw path at 0x5fd1956); "
                    "growth doubling (new_cap = 2*size, overflow to "
                    "max 0x7ffffffffffffff8); moves the value OUT of "
                    "the source slot (the source is zeroed); shifts "
                    "the tail; memcpy; frees the old buffer. Callers "
                    "use it as push_back (pos = end).",
            "calls": counts[0x5FD17C0]["calls"],
            "callers": ["0x5fd2350 (default-init slow path)",
                        "0x5fd2688 (insert slow path)",
                        "0x5febd28", "0x5ff83c6", "0x6005f68",
                        "0x6075f30", "0x6093e18", "0x6137c38",
                        "0x6138798", "0x613c256", "0x6194f48",
                        "0x6196628", "0x61a5a38", "0x61c0fa8",
                        "0x61cba58", "0x61cce0b", "0x61cdc68",
                        "0x61e8318", "0x61f1328", "0x61fc498",
                        "0x6208917", "0x6208990"],
            "excerpt": "vector-insert-5fd17c0.objdump.txt",
        },
        "insert": {
            "addr": 0x5FD24C0, "fde": "0x5fd24c0..0x5fd2748",
            "signature": "(registry, key_string, std::function)",
            "role": "Clones the function (manager op 2 into a stack "
                    "temp when the manager is non-null); allocates a "
                    "0x30-byte FactoryEntry node (vtable A 0x64cde68) "
                    "and a 0x70-byte PatternEntry (vtable 0x64d8ed0); "
                    "entry.pattern = key string; entry+0x28 = pattern "
                    "length; entry+0x48 byte = 1; both vectors zeroed; "
                    "entry+0x50 = 0; node = {vtable, entry*, "
                    "std::function}. Locks the registry mutex; builds "
                    "the key \"Environment\" (literal 0x44a397) and "
                    "calls find-or-insert; appends the node* to the "
                    "returned vector (fast path inline, slow path via "
                    "vector-insert 0x5fd17c0); unlocks (tail-jump "
                    "pthread_mutex_unlock on the fast path). After a "
                    "successful vector-insert the moved-from source "
                    "slot is null, so the trailing node-vtable-slot-1 "
                    "dispatch is not reached on the success path — "
                    "recorded as observed, dead on success.",
            "calls": counts[0x5FD24C0]["calls"],
            "callers": ["0x5fd2848 (register)",
                        "0x5fd28c3 (register)"],
            "excerpt": "insert-5fd24c0.objdump.txt",
        },
        "default_init": {
            "addr": 0x5FD20D0, "fde": "0x5fd20d0..0x5fd241d",
            "role": "Same node+entry construction INLINE (node "
                    "vtable B 0x64cde98); pattern "
                    "\"TimeEmulatedSystemClock\" (literal 0x4372ae), "
                    "invoker 0x5fcd550 (mode-0) / manager 0x5fcc630; "
                    "map key \"SystemClock\" (literal 0x438369); "
                    "locks, find-or-insert, append (fast/slow paths "
                    "as insert), unlock, calls count(registry, "
                    "rsp+0x10), destroys temps, returns. "
                    "Null-registry throws system_error(1); lock "
                    "failure throws. Taken by address (lea at "
                    "0x5fd47c1) from the create host "
                    "0x5fd46c0..0x5fd4c2e as a pthread_once "
                    "initializer with guard 0x6504b68, so it runs "
                    "exactly once.",
            "calls": counts[0x5FD20D0]["calls"],
            "leas": counts[0x5FD20D0]["leas"],
            "lea_sites": ["0x5fd47c1 (host 0x5fd46c0..0x5fd4c2e)"],
            "excerpt": "default-init-5fd20d0.objdump.txt",
        },
        "register": {
            "addr": 0x5FD27C0, "fde": "0x5fd27c0..0x5fd297f",
            "role": "Calls the getter, registers TWO entries via "
                    "insert 0x5fd24c0: pattern \"MockEnv\" (0x447686) "
                    "with invoker 0x5fcd5b0 (mode-1) / manager "
                    "0x5fcc5d0, and pattern \"CompositeEnv\" "
                    "(0x43e762) with invoker 0x5fcf450 / manager "
                    "0x5fcc600; then calls count(registry, rsp+0x08); "
                    "destroys the empty temp string (literal "
                    "0x4376fd = \"\"); returns. Taken by address "
                    "(lea at 0x5fd358e and 0x5fd3c3a) from two hosts "
                    "(0x5fd34b0..0x5fd38f6 and 0x5fd39b0..0x5fd3cf6) "
                    "as a pthread_once initializer with the shared "
                    "guard 0x6504bb8, so it runs exactly once.",
            "calls": counts[0x5FD27C0]["calls"],
            "leas": counts[0x5FD27C0]["leas"],
            "lea_sites": ["0x5fd358e (host 0x5fd34b0..0x5fd38f6)",
                          "0x5fd3c3a (host 0x5fd39b0..0x5fd3cf6)"],
            "excerpt": "register-5fd27c0.objdump.txt",
        },
        "environment_key_answer": {
            "key": "Environment",
            "literal_addr": 0x44A397,
            "role": "insert() hardcodes the map key \"Environment\". "
                    "ALL entries registered through insert() live "
                    "under the single map key \"Environment\"; the "
                    "per-entry pattern strings (\"MockEnv\", "
                    "\"CompositeEnv\", \"SystemClock\", "
                    "\"SliceTransform\", ...) are stored in the "
                    "PatternEntry objects, not as map keys. "
                    "default-init is the exception: it uses the map "
                    "key \"SystemClock\". After default-init + "
                    "register, the map has 2 keys (\"SystemClock\", "
                    "\"Environment\") and count returns 3 total "
                    "entries with *out = 2. This answers the open "
                    "unknown carried by PR #3948.",
        },
        "control_block": {
            "vtable": 0x64D00F0,
            "typeinfo": typeinfo_name(0x64D00E0),
            "slots": [
                {"slot": 0, "addr": int(cb_map[0], 16), "name": "D1",
                 "fde": "0x5fefc70..0x5fefc75",
                 "role": "Trivial (endbr64; ret).",
                 "excerpt": "cb-d1-5fefc70.objdump.txt"},
                {"slot": 1, "addr": int(cb_map[1], 16), "name": "D0",
                 "fde": "0x5fefd00..0x5fefd0e",
                 "role": "operator delete 0x90.",
                 "excerpt": "cb-d0-5fefd00.objdump.txt"},
                {"slot": 2, "addr": int(cb_map[2], 16),
                 "name": "_M_dispose", "fde": "0x5ff7900..0x5ff7952",
                 "role": "Destroys the ObjectLibrary: name string "
                         "via inlined _M_dispose (free the heap "
                         "buffer with size capacity+1), map destroy "
                         "via 0x5ff7820(obj+0x28), frees the bucket "
                         "array if buckets != &single_bucket.",
                 "excerpt": "cb-dispose-5ff7900.objdump.txt"},
                {"slot": 3, "addr": int(cb_map[3], 16),
                 "name": "_M_destroy", "fde": "0x5fefd50..0x5fefd5e",
                 "role": "operator delete 0x90.",
                 "excerpt": "cb-destroy-5fefd50.objdump.txt"},
                {"slot": 4, "addr": int(cb_map[4], 16),
                 "name": "_M_get_deleter",
                 "fde": "0x5feff70..0x5feffb7",
                 "role": "Compares the arg type_info to GOT "
                         "0x64ecdc8 (RELATIVE -> 0x96cb48, the "
                         "_Sp_make_shared_tag typeinfo) or its name "
                         "string 0x96c770 (\"St19_Sp_make_shared_tag"
                         "\"); returns this+0x10 on match, null "
                         "otherwise; a name starting with '*' returns "
                         "null; otherwise strcmp.",
                 "excerpt": "cb-getdeleter-5feff70.objdump.txt"},
            ],
        },
        "map_destroy": {
            "addr": 0x5FF7820, "fde": "0x5ff7820..0x5ff78ff",
            "role": "Takes the map (obj+0x28); walks the before_begin "
                    "chain; per node walks the value vector "
                    "[node+0x28, node+0x30), calls each element's "
                    "vtable slot 1 (FactoryEntry-node D0) via "
                    "call *0x8(%rax); frees the vector buffer; "
                    "destroys the node key string (SSO check vs "
                    "node+0x18); operator delete(node, 0x48).",
            "calls": counts[0x5FF7820]["calls"],
            "callers": ["0x5ff7930 (cb _M_dispose)",
                        "0x5ff8888", "0x61f8b01", "0x61f8d75",
                        "0x620699a"],
            "excerpt": "map-destroy-5ff7820.objdump.txt",
        },
        "pattern_entry": {
            "size": 0x70,
            "vtable": 0x64D8ED0,
            "typeinfo": typeinfo_name(0x64D8EC0),
            "fields": [
                {"offset": 0x00, "what": "vtable pointer"},
                {"offset": 0x08, "what": "std::string pattern (0x20)"},
                {"offset": 0x28, "what": "size_t pattern-length copy"},
                {"offset": 0x30, "what": "std::vector<std::string> "
                 "sub-patterns (0x20-byte elements)"},
                {"offset": 0x48, "what": "bool byte (1)"},
                {"offset": 0x50, "what": "pointer (0)"},
                {"offset": 0x58, "what": "std::vector<0x28-byte> "
                 "sub-pattern elements: string at +0x00, mode "
                 "at +0x20"},
            ],
            "slots": [
                {"slot": 0, "addr": int(pattern_map[0], 16), "name": "D2",
                 "fde": "0x5ff2030..0x5ff2145",
                 "role": "Installs the vtable; destroys the +0x58 "
                         "vector elements (string-destroy per "
                         "0x28-byte element), frees its buffer; "
                         "destroys the +0x30 vector elements (plain "
                         "strings), frees its buffer; destroys the "
                         "pattern string at +0x08 (SSO check vs "
                         "+0x18); returns.",
                 "calls": counts[0x5FF2030]["calls"],
                 "excerpt": "pattern-d2-5ff2030.objdump.txt"},
                {"slot": 1, "addr": int(pattern_map[1], 16), "name": "D0",
                 "fde": "0x5ff2150..0x5ff225f",
                 "role": "Same as D2, plus operator delete(obj, "
                         "0x70). Reached only through the vtable.",
                 "excerpt": "pattern-d0-5ff2150.objdump.txt"},
                {"slot": 2, "addr": int(pattern_map[2], 16),
                 "name": "Matches", "fde": "0x61f8670..0x61f86f2",
                 "role": "Calls str-match 0x61f8430(entry, &pattern, "
                         "entry+0x28, arg, arg_len); if false, walks "
                         "the +0x30 vector calling str-match per "
                         "element; returns 1 on the first match, "
                         "else 0. Reached only through the vtable.",
                 "excerpt": "pattern-match-61f8670.objdump.txt"},
                {"slot": 3, "addr": int(pattern_map[3], 16),
                 "name": "pattern accessor",
                 "fde": "0x61f8120..0x61f8129",
                 "role": "mov 0x8(%rdi),%rax; ret — returns "
                         "&pattern. Reached only through the vtable.",
                 "excerpt": "pattern-accessor-61f8120.objdump.txt"},
            ],
            "vtable_boundary": "The PatternEntry vtable has exactly "
                "4 slots. The qwords that follow (0x64d8ef0 offset-to-"
                "top 0, 0x64d8ef8 typeinfo) are the header of the "
                "NEXT vtable in .data.rel.ro, the "
                "_Sp_counted_ptr_inplace<ObjectRegistry> control-block "
                "vtable at 0x64d8f00 (5 slots: D1 0x61f8130, D0 "
                "0x61f8140 delete 0xd0, _M_dispose 0x61f8760, "
                "_M_destroy 0x61f8170 delete 0xd0, _M_get_deleter "
                "0x61f8180). Its dispose destroys a 0xc0-byte "
                "ObjectRegistry, a different class; it is recorded "
                "here as the boundary and is a follow-up work item, "
                "not part of this packet.",
        },
        "str_match": {
            "addr": 0x61F8430, "fde": "0x61f8430..0x61f8670",
            "signature": "(entry, pattern_string, pattern_len, "
                         "query_string, query_len)",
            "role": "Empty +0x58 vector: exact match only (lengths "
                    "equal and memcmp equal; the +0x48 flag is NOT "
                    "checked). Equal lengths with a non-empty vector: "
                    "exact match, and the +0x48 flag must be set. "
                    "Otherwise the query must start with the pattern "
                    "(query_len >= entry+0x50 + pattern_len; first "
                    "min(query_len, pattern_len) bytes equal; "
                    "query_len >= pattern_len), then every +0x58 "
                    "element must match in sequence through "
                    "elem-match 0x61f8280, and the tail decides by "
                    "the last element's mode: mode 2 requires the "
                    "position to reach the end of the query; modes "
                    "3/4 require the remainder (after an optional "
                    "'-') to be digits / dotted digits with at "
                    "least one digit; any other mode accepts.",
            "calls": counts[0x61F8430]["calls"],
            "callers": ["0x61f869a (pattern Matches)",
                        "0x61f86d1 (pattern Matches, sub-pattern loop)"],
            "excerpt": "str-match-61f8430.objdump.txt",
        },
        "elem_match": {
            "addr": 0x61F8280, "fde": "0x61f8280..0x61f842b",
            "signature": "(entry, pos, query_string, query_len, mode, "
                         "element)",
            "role": "Returns the new position, or -1 on failure. "
                    "Mode 2: the element string must occur AT pos; "
                    "returns pos + len. Mode 0/1: std::string::find "
                    "from pos+1, so the element may occur anywhere "
                    "later; returns found + len. Mode 3: like 0/1, "
                    "but the gap between pos and the found position "
                    "(after an optional '-') must be all digits. "
                    "Mode 4: like 3, but the gap may contain at most "
                    "one '.' and must hold at least one digit. The "
                    "mode governing element i+1 (and the tail after "
                    "the last element) is stored in element i's "
                    "+0x20 field; element 0 is governed by the "
                    "initial mode 2.",
            "calls": counts[0x61F8280]["calls"],
            "callers": ["0x61f8526 (str-match)"],
            "excerpt": "elem-match-61f8280.objdump.txt",
        },
        "factory_nodes": {
            "size": 0x30,
            "fields": [
                {"offset": 0x00, "what": "vtable pointer"},
                {"offset": 0x08, "what": "PatternEntry*"},
                {"offset": 0x10, "what": "std::function {functor 16B, "
                 "manager +0x20, invoker +0x28}"},
            ],
            "env_vtable": {
                "header": "0x64cde58", "vtable": "0x64cde68",
                "typeinfo": typeinfo_name(0x64CDE58),
                "slots": [
                    {"slot": 0, "addr": int(node_env_map[0], 16),
                     "name": "D2", "fde": "0x5fcc700..0x5fcc742",
                     "role": "Installs the Env-node vtable, destroys "
                             "the function via manager op 3, tail-jumps "
                             "to the entry-vtable slot 1 (D0).",
                     "excerpt": "node-env-d2-5fcc700.objdump.txt"},
                    {"slot": 1, "addr": int(node_env_map[1], 16),
                     "name": "D0", "fde": "0x5fcd840..0x5fcd88a",
                     "role": "Same as D2, plus operator delete(node, "
                             "0x30).",
                     "excerpt": "node-env-d0-5fcd840.objdump.txt"},
                    {"slot": 2, "addr": int(node_env_map[2], 16),
                     "name": "forwarder",
                     "fde": "0x5fcc7e0..0x5fcc7ee",
                     "role": "Forwards to the entry's vtable slot 2 "
                             "(Matches).",
                     "excerpt": "node-env-fwd2-5fcc7e0.objdump.txt"},
                    {"slot": 3, "addr": int(node_env_map[3], 16),
                     "name": "forwarder",
                     "fde": "0x5fcc7f0..0x5fcc7fe",
                     "role": "Forwards to the entry's vtable slot 3 "
                             "(pattern accessor).",
                     "excerpt": "node-env-fwd3-5fcc7f0.objdump.txt"},
                ],
                "used_by": "insert() for MockEnv / CompositeEnv "
                           "(Env factories).",
            },
            "clock_vtable": {
                "header": "0x64cde88", "vtable": "0x64cde98",
                "typeinfo": typeinfo_name(0x64CDE88),
                "slots": [
                    {"slot": 0, "addr": int(node_clock_map[0], 16),
                     "name": "D2", "fde": "0x5fcc6b0..0x5fcc6f2",
                     "role": "Installs the SystemClock-node vtable, "
                             "destroys the function, tail-jumps to "
                             "the entry D0.",
                     "excerpt": "node-clock-d2-5fcc6b0.objdump.txt"},
                    {"slot": 1, "addr": int(node_clock_map[1], 16),
                     "name": "D0", "fde": "0x5fcd7f0..0x5fcd83a",
                     "role": "Same as D2, plus operator delete(node, "
                             "0x30).",
                     "excerpt": "node-clock-d0-5fcd7f0.objdump.txt"},
                    {"slot": 2, "addr": int(node_clock_map[2], 16),
                     "name": "forwarder",
                     "fde": "0x5fcc7c0..0x5fcc7ce",
                     "role": "Forwards to the entry's vtable slot 2.",
                     "excerpt": "node-clock-fwd2-5fcc7c0.objdump.txt"},
                    {"slot": 3, "addr": int(node_clock_map[3], 16),
                     "name": "forwarder",
                     "fde": "0x5fcc7d0..0x5fcc7de",
                     "role": "Forwards to the entry's vtable slot 3.",
                     "excerpt": "node-clock-fwd3-5fcc7d0.objdump.txt"},
                ],
                "used_by": "default-init() for "
                           "TimeEmulatedSystemClock.",
            },
            "env_ptr_cb_vtable": {
                "header": "0x64cdeb8", "vtable": "0x64cdec8",
                "typeinfo": typeinfo_name(0x64CDEB8),
                "slots": [
                    {"slot": 0, "addr": int(env_ptr_cb_map[0], 16),
                     "name": "D1", "fde": "0x5fcc6a0..0x5fcc6a5",
                     "role": "Trivial (ret).",
                     "excerpt": "node-envptr-d1-5fcc6a0.objdump.txt"},
                    {"slot": 1, "addr": int(env_ptr_cb_map[1], 16),
                     "name": "D0", "fde": "0x5fcc830..0x5fcc83e",
                     "role": "operator delete 0x18.",
                     "excerpt": "node-envptr-d0-5fcc830.objdump.txt"},
                    {"slot": 2, "addr": int(env_ptr_cb_map[2], 16),
                     "role": "dispose; cited from the RELATIVE "
                             "record, not excerpted."},
                    {"slot": 3, "addr": int(env_ptr_cb_map[3], 16),
                     "role": "destroy; cited from the RELATIVE "
                             "record, not excerpted."},
                    {"slot": 4, "addr": int(env_ptr_cb_map[4], 16),
                     "role": "get_deleter; cited from the RELATIVE "
                             "record, not excerpted."},
                ],
                "note": "The _Sp_counted_ptr<Env*> control block "
                        "vtable follows the two FactoryEntry node "
                        "vtables in .data.rel.ro; only its D1/D0 "
                        "are excerpted here.",
            },
        },
        "object_registry_cb_vtable": {
            "header": "0x64d8ef0", "vtable": "0x64d8f00",
            "typeinfo": typeinfo_name(0x64D8EF0),
            "slots": [
                {"slot": 0, "addr": int(objreg_cb_map[0], 16),
                 "name": "D1", "fde": "0x61f8130..0x61f8135",
                 "role": "Trivial (ret). Cited only; the function "
                         "is not excerpted in this packet."},
                {"slot": 1, "addr": int(objreg_cb_map[1], 16),
                 "name": "D0", "fde": "0x61f8140..0x61f814e",
                 "role": "operator delete 0xd0. Cited only."},
                {"slot": 2, "addr": int(objreg_cb_map[2], 16),
                 "name": "_M_dispose", "fde": "0x61f8760..0x61f89db",
                 "role": "Destroys a 0xc0-byte ObjectRegistry: "
                         "releases the shared_ptr at +0x78, walks "
                         "the linked list at +0x50 of 0x50-byte "
                         "nodes (recursive destroy 0x61f81d0), "
                         "destroys the vector<string> at +0x28, "
                         "releases the vector<shared_ptr> at +0x10. "
                         "Cited only; a follow-up work item."},
                {"slot": 3, "addr": int(objreg_cb_map[3], 16),
                 "name": "_M_destroy", "fde": "0x61f8170..0x61f817e",
                 "role": "operator delete 0xd0. Cited only."},
                {"slot": 4, "addr": int(objreg_cb_map[4], 16),
                 "name": "_M_get_deleter",
                 "fde": "0x61f8180..0x61f81c7",
                 "role": "Same _Sp_make_shared_tag shape as the "
                         "ObjectLibrary control-block get-deleter. "
                         "Cited only."},
            ],
        },
        "relocations": reloc_rows,
        "relocation_ranges": [
            {"range": "0x64cde58..0x64cded8",
             "what": "FactoryEntry<Env> + FactoryEntry<SystemClock> "
                     "+ _Sp_counted_ptr<Env*> vtables",
             "count": 13},
            {"range": "0x64d00e0..0x64d0118",
             "what": "_Sp_counted_ptr_inplace<ObjectLibrary> "
                     "control-block vtable", "count": 6},
            {"range": "0x64d8ec0..0x64d8f28",
             "what": "PatternEntry vtable + "
                     "_Sp_counted_ptr_inplace<ObjectRegistry> "
                     "control-block vtable", "count": 11},
            {"range": "0x64ecdc8..0x64ecdd0",
             "what": "_Sp_make_shared_tag typeinfo GOT slot",
             "count": 1},
        ],
        "literals": literals,
        "immediates": [
            {"where": "find-or-insert 0x5fd1da6",
             "value": 0xC70F6907, "what": "_Hash_bytes seed"},
            {"where": "getter 0x61f8c55",
             "value": 0x3F800000, "what": "max_load_factor 1.0f"},
            {"where": "vector-insert 0x5fd1956",
             "value": 0xFFFFFFFFFFFFFFF, "what": "vector max size"},
        ],
        "census": {
            "targets": census,
            "callers_tsv_rows": sum(
                1 for _ in (PACKET / "callers.tsv").read_text()
                .splitlines()) - 1,
            "relocation_records": len(reloc_rows),
        },
        "model": "tools/objectlibrary_registry_115.py",
        "tests": "tests/test_objectlibrary_registry_115.py",
        "test_checks": 23,
        "open_unknowns": [
            "The ObjectRegistry class (0xc0-byte object; control-"
            "block vtable 0x64d8f00, dispose 0x61f8760, recursive "
            "destroy 0x61f81d0, string-dispose 0x61f814e) is a "
            "different class from ObjectLibrary; its functions are "
            "cited as the vtable boundary, not excerpted. A "
            "follow-up work item.",
            "The _Sp_counted_ptr<Env*> control-block dispose "
            "(0x5fcc790), destroy (0x5fcc840) and get-deleter "
            "(0x5fcc7b0) are cited from RELATIVE records, not "
            "excerpted.",
            "The mode field's lagged semantics (element i's +0x20 "
            "governs element i+1 and the tail) is recorded as "
            "observed; whether the source attaches the mode to the "
            "following segment or the parse assigns it that way is "
            "not established.",
            "The two register hosts (0x5fd34b0..0x5fd38f6 and "
            "0x5fd39b0..0x5fd3cf6) and the default-init host "
            "(0x5fd46c0..0x5fd4c2e) are identified by FDE range "
            "only; their names are not established.",
            "The find-or-insert cold FDE (0x5fd1ffa..0x5fd20c4) "
            "shares code with another frame (the rsp+0xa8-canary "
            "portion); recorded as observed.",
            "The registry's read-only find path (0x61c9d70) does not "
            "call find-or-insert in the census; its exact lookup "
            "shape is not pinned here.",
            "The exact _Prime_rehash_policy prime selection is "
            "modelled from the libstdc++ policy as observed in "
            "find-or-insert's _M_need_rehash call; the rehash "
            "function itself (0x5fd1c60) is pinned exactly.",
            "The hash function is libstdc++ _Hash_bytes with seed "
            "0xc70f6907; the model substitutes a deterministic "
            "stand-in hash and pins placement/lookup, not hash "
            "values.",
        ],
    }
    with open(PACKET / "records.json", "w") as handle:
        json.dump(records, handle, indent=2)
        handle.write("\n")
    print("wrote records.json")
    print("targets in census:", len(census))
    print("relocations:", len(reloc_rows))
    print("literals:", len(literals))


if __name__ == "__main__":
    sys.exit(main())
