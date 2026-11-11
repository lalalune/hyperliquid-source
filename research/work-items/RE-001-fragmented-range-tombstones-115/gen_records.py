"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-range-tombstones-115/gen_records.py

Everything derived here comes from the digest-verified binary
(work/hl-node-115.bin) or the repo catalogue (research/byte-windows.json);
the semantic claims are hand-written below from the disassembly and
checked by verify.py. No per-instruction mnemonic list is emitted:
instruction-level detail lives only in the verbatim excerpts.
"""

import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, HERE)
import census as census_mod

# --- ELF helpers -------------------------------------------------------

def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        typ = struct.unpack_from("<I", data, off)[0]
        poff = struct.unpack_from("<Q", data, off + 8)[0]
        pva = struct.unpack_from("<Q", data, off + 16)[0]
        pfilesz = struct.unpack_from("<Q", data, off + 32)[0]
        segs.append((typ, poff, pva, pfilesz))
    return segs


def va2off(segs, va):
    for typ, poff, pva, pfilesz in segs:
        if typ == 1 and pva <= va < pva + pfilesz:
            return poff + (va - pva)
    return None


def cstr_at_va(data, segs, va):
    off = va2off(segs, va)
    if off is None:
        return None
    end = data.index(b"\0", off)
    return data[off:end].decode(errors="replace")


def load_relocs(data):
    rel = {}
    rela_off, rela_size = 0x6BE8, 0x163CC8
    for k in range(rela_size // 24):
        ro, info, add = struct.unpack_from("<QQq", data, rela_off + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            rel[ro] = add
    return rel


def reloc_val(data, segs, rel, va):
    if va in rel:
        return rel[va]
    off = va2off(segs, va)
    if off is None:
        return None
    return struct.unpack_from("<Q", data, off)[0]


def resolve_vtable(data, segs, rel, base):
    """Return (typeinfo_name, [(stored_offset, target), ...]).

    Stored pointer = base + 0x10; entries are listed at offsets from
    the stored pointer, the convention the call sites use.
    """
    ti = reloc_val(data, segs, rel, base + 8)
    name = cstr_at_va(data, segs, reloc_val(data, segs, rel, ti + 8))
    slots = []
    k = 0
    while True:
        f = reloc_val(data, segs, rel, base + 0x10 + k * 8)
        if f is None or f == 0:
            break
        slots.append((hex(k * 8), hex(f)))
        k += 1
        if k > 32:
            break
    return name, slots


def load_fdes():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", BIN],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]{8} .*FDE .*pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)", line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def containing(fdes, va):
    import bisect
    starts = [f[0] for f in fdes]
    i = bisect.bisect_right(starts, va) - 1
    if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
        return fdes[i]
    return None


def catalogue_label(by_start, va):
    ws = by_start.get(va)
    if not ws:
        return None
    return ws[0].get("label") or ws[0].get("id")


# --- roles --------------------------------------------------------------

HOST_CALLER_ROLES = {
    0x5E83A0B: "DBImplSecondary::RecoverLogFiles: rebuild on recovery",
    0x5E8AAAB: "DBImpl::SwitchMemtable: rebuild when a memtable turns immutable",
    0x5ED1BCD: "FlushJob::MemPurge: rebuild on memtable purge",
}

SORT_FDE_ROLES = {
    0x5F061B0: "_Sp_counted_ptr_inplace<FragmentedRangeTombstoneListCache>::_M_dispose: sort the cache index on shared_ptr dispose",
    0x5F0A3D0: "this host: sort the old cache index on rebuild",
    0x5F0A9C0: "NewRangeTombstoneIteratorInternal (#3674): sort the old cache index on lazy-build install",
    0x5F0B080: "unique_ptr<FragmentedRangeTombstoneList>::~unique_ptr: sort the cache index on list destruction",
    0x5F10D40: "MemTable::~MemTable: sort the cache index on memtable destruction",
}

CACHE_CTOR_ROLES = {
    0x5F0A536: "this host: build the fresh cache from the temp iterator",
    0x5F0AC12: "NewRangeTombstoneIteratorInternal (#3674): lazy-build the cache",
    0x5F29367: "CompactionRangeDelAggregator::NewIterator: build a compaction cache",
    0x6109F07: "BlockBasedTable::ReadRangeDelBlock: build a table-reader cache",
}


def main():
    data = open(os.path.join(ROOT, BIN), "rb").read()
    assert __import__("hashlib").sha256(data).hexdigest() == DIGEST
    segs = load_segments(data)
    rel = load_relocs(data)
    fdes = load_fdes()
    cat = json.load(open(os.path.join(ROOT, "research/byte-windows.json")))
    by_start = {}
    for w in cat["windows"]:
        by_start.setdefault(w["start"], []).append(w)

    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, BIN))

    # Vtables.
    vtables = {}
    for key, base in (("memtable_iterator", 0x64CC638),
                      ("key_comparator", 0x64CC600),
                      ("internal_key_comparator", 0x64C8FE8)):
        name, entries = resolve_vtable(data, segs, rel, base)
        vtables[key] = {
            "base": hex(base),
            "stored_pointer": hex(base + 0x10),
            "typeinfo_name": name,
            "slots": [{"offset": o, "target": t} for o, t in entries],
        }

    # Callers with roles.
    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        for v in calls[t]:
            f = containing(fdes, v)
            if t == 0x5F0A3D0:
                role = HOST_CALLER_ROLES[v]
            elif t in (0x5F053D0, 0x5F05120):
                if t == 0x5F053D0 and v == 0x5F055B9:
                    role = "self-recursion on the right partition inside __introsort_loop"
                else:
                    role = SORT_FDE_ROLES[f[0]]
                    if t == 0x5F05120:
                        role += " (final insertion sort)"
            elif t == 0x5F37410:
                role = CACHE_CTOR_ROLES[v]
            elif t == 0x5F04F80:
                role = "heapsort fallback (__make_heap/__sort_heap) inside __introsort_loop"
            elif t == 0x5F059B0:
                if v == 0x5F05A41:
                    role = "self-recursion on the +0x18 child"
                else:
                    role = SORT_FDE_ROLES[f[0]].replace("sort the cache index", "release the +0x60 node tree")
                    if f[0] == 0x5F0A3D0:
                        role = "this host: release the old cache +0x60 node tree"
            elif t == 0x5F36C70:
                role = "cache ctor: fragment the tombstones (main path)" if v == 0x5F3799F else "cache ctor: fragment the tombstones (null-list path)"
            elif t == 0x60B21F0:
                lab = catalogue_label(by_start, f[0])
                if lab:
                    short = lab.split(": ", 1)[-1][:100]
                    role = "default ReadOptions construction in " + short
                else:
                    role = "default ReadOptions construction in FDE %#x (no catalogue row)" % f[0]
            else:
                role = ""
            rows.append({
                "site": hex(v),
                "kind": "direct_call",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": role,
            })
        for v in tails[t]:
            f = containing(fdes, v)
            rows.append({
                "site": hex(v),
                "kind": "tail_jump",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": "",
            })
        callers[hex(t)] = rows

    # callers.tsv: target, site, kind, containing FDE, role.
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde\trole\n")
        for t in census_mod.TARGETS:
            for row in callers[hex(t)]:
                fh.write("%s\t%s\t%s\t%s..%s\t%s\n" % (
                    hex(t), row["site"], row["kind"],
                    row["containing_fde"][0], row["containing_fde"][1],
                    row["role"]))

    # vtables.tsv
    with open(os.path.join(HERE, "vtables.tsv"), "w") as fh:
        fh.write("vtable\tstored_pointer\ttypeinfo_name\tslot_offset\ttarget\n")
        for key, vt in vtables.items():
            for s in vt["slots"]:
                fh.write("%s\t%s\t%s\t%s\t%s\n" % (
                    key, vt["stored_pointer"], vt["typeinfo_name"],
                    s["offset"], s["target"]))

    # relocations.txt
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("No R_X86_64_RELATIVE entry in .rela.dyn has an addend equal to any packet window start.\n")
        fh.write("The iterator vtables 0x64cc638+0x10 / 0x64cc600+0x10 / 0x64c8fe8+0x10 are RIP-relative leas in the host excerpt; their typeinfo names and slot targets resolve through R_X86_64_RELATIVE entries (see vtables.tsv and records.json).\n")
        fh.write("The MemTableIterator vtable (stored 0x64cc648) has 24 slots, stored+0x00..+0xb8; the KeyComparator vtable (stored 0x64cc610) has 5 slots, stored+0x00..+0x20; the InternalKeyComparator vtable (stored 0x64c8ff8) has 3 slots, stored+0x00..+0x10.\n")
        fh.write("No other relocation in the packet points at a window: the ReadOptions temp, the cache scratch and the stack canary are stack slots (no relocation).\n")

    records = build_records(calls, tails, hits, slots, callers, vtables)
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json, callers.tsv, relocations.txt, vtables.tsv")
    return 0


def build_records(calls, tails, hits, slots, callers, vtables):
    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    return {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "windows": [
            {"address": "0x5f0a3d0", "name": "rocksdb::MemTable::ConstructFragmentedRangeTombstones", "fde": "0x5f0a3d0..0x5f0a909", "size_bytes": 0x539, "catalogue": "librocksdb-sys 0.11.0+8.1.1: 1238/1337 (92.60%)", "excerpt": "host-5f0a3d0.objdump.txt"},
            {"address": "0x60b21f0", "name": "rocksdb::ReadOptions::ReadOptions", "fde": "0x60b21f0..0x60b2262", "size_bytes": 0x72, "catalogue": "librocksdb-sys 0.11.0+8.1.1: 114/114 (100.00%)", "excerpt": "readopts-60b21f0.objdump.txt"},
            {"address": "0x5f053d0", "name": "std::__introsort_loop (16-byte entries, by shape)", "fde": "0x5f053d0..0x5f05678", "size_bytes": 0x2a8, "catalogue": None, "excerpt": "introsort-5f053d0.objdump.txt"},
            {"address": "0x5f05120", "name": "std::__insertion_sort (16-byte entries, by shape)", "fde": "0x5f05120..0x5f051f5", "size_bytes": 0xd5, "catalogue": None, "excerpt": "insertion-5f05120.objdump.txt"},
            {"address": "0x5f04f80", "name": "std::__adjust_heap (16-byte entries, by shape)", "fde": "0x5f04f80..0x5f0511d", "size_bytes": 0x19d, "catalogue": None, "excerpt": "adjust-heap-5f04f80.objdump.txt"},
            {"address": "0x5f37410", "name": "FragmentedRangeTombstoneListCache constructor (by shape; re-shipped from #3674)", "fde": "0x5f37410..0x5f37e31", "size_bytes": 0xa21, "catalogue": None, "excerpt": "cache-ctor-5f37410.objdump.txt"},
            {"address": "0x61bd0c0", "name": "rocksdb::Cleanable::Cleanable (re-shipped from #3674)", "fde": "0x61bd0c0..0x61bd0d4", "size_bytes": 0x14, "catalogue": "78/81", "excerpt": "cleanable-ctor-61bd0c0.objdump.txt"},
            {"address": "0x61bd0e0", "name": "rocksdb::Cleanable::DoCleanup (re-shipped from #3674)", "fde": "0x61bd0e0..0x61bd131", "size_bytes": 0x51, "catalogue": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical copies", "excerpt": "cleanable-dtor-61bd0e0.objdump.txt"},
            {"address": "0x5f059b0", "name": "node-tree list release (by shape; re-shipped from #3674)", "fde": "0x5f059b0..0x5f05b79", "size_bytes": 0x1c9, "catalogue": None, "excerpt": "list-release-5f059b0.objdump.txt"},
        ],
        "host": {
            "name": "rocksdb::MemTable::ConstructFragmentedRangeTombstones",
            "arguments": ["rdi = owner (MemTable)"],
            "early_return": "owner+0xa60 != 0: return at once (stack-canary check, no rebuild); the flag means the fragmented cache is already built",
            "iterator_build": {
                "alloc": "operator new(0x80) for the temp iterator",
                "cleanable": "Cleanable ctor 0x61bd0c0 at iterator+0x8 (head fn +0x8 = 0, chain link +0x20 = 0)",
                "fields": {
                    "+0x00": "vtable 0x64cc638+0x10 (rocksdb::MemTableIterator, 24 slots)",
                    "+0x08": "Cleanable (see cleanable_ctor)",
                    "+0x28": "0 (qword)",
                    "+0x30": "owner+0xc58 (a pointer)",
                    "+0x38": "vtable 0x64cc600+0x10 (rocksdb::MemTable::KeyComparator, 5 slots)",
                    "+0x40": "vtable 0x64c8fe8+0x10 (rocksdb::InternalKeyComparator, 3 slots)",
                    "+0x48": "owner+0x10 (the user comparator pointer)",
                    "+0x50": "(owner+0xa58)->vtable slot 0x90(obj, 0, 0): the rep iterator",
                    "+0x58": "0 (u16)",
                    "+0x5a": "owner+0x31 ^ 1 (byte)",
                    "+0x60": "owner+0x6c (qword)",
                    "+0x68": "0 (qword)",
                    "+0x6c": "0 (u16)",
                    "+0x70": "0 (qword)",
                    "+0x78": "owner+0x60 (qword)",
                },
                "note": "the build is field-wise in the host (the MemTableIterator ctor is inlined); the comparator subobject at +0x38 is a MemTable::KeyComparator whose InternalKeyComparator member sits at +0x40 with its user_comparator_ at +0x48",
            },
            "readopts": "a ReadOptions temp is default-constructed on the stack at rsp+0x30 by 0x60b21f0 (see readopts); the host then reads temp+0x48 as a function pointer and invokes it as fn(temp+0x38, temp+0x38, 3) when non-null — the ctor zeroes +0x48 and no store in this flow rewrites it, so the call never fires here (see unknowns)",
            "rep_iterator_call": "(owner+0xa58)->vtable slot 0x90 with (obj, 0, 0); the result is stored at iterator+0x50",
            "cache_build": "operator new(0xe8) for the cache; cache ctor 0x5f37410(cache, &iterator, iterator+0x8, 0, scratch) where scratch is a 0x20-byte zeroed stack vector<size_t> at rsp+0x10 (begin rsp+0x10, end rsp+0x18, capacity rsp+0x20); after the ctor the temp iterator is destroyed via its vtable slot 1 (0x5f058e0) and the scratch heap array is freed with operator delete[](begin, capacity - begin)",
            "install": "old = owner+0xce0; owner+0xce0 = new cache; the old cache (when non-null) is torn down (see teardown)",
            "teardown": {
                "not_ready": "old+0xb8 == 0: the +0xc0 array is freed without invoking its entries (operator delete[](begin, +0xd0 - begin) when begin != 0), then the common tail runs (DoCleanup, +0x80 list, +0x60 tree, buffers, delete old)",
                "ready": "old+0xb8 != 0: the ready flag is cleared; the +0xc0 index vector is sorted by (first, second) with std::sort (__introsort_loop 0x5f053d0, then __insertion_sort 0x5f05120 plus the host's inlined unguarded insertion loop), adjacent duplicates are compacted in place, and every surviving entry is invoked as entry[1](entry[0]); then the +0x98 head cleanup fn is called as fn(+0xa0, +0xa8), each 0x20-byte node of the +0xb0 chain is called as fn(+0x8, +0x10) and freed (0x20 bytes), +0x98/+0xb0 are zeroed, and the common tail runs",
                "common_tail": "operator delete[](old+0xc0 array, size +0xd0 - +0xc0) when begin != 0; DoCleanup(old+0x98) via 0x61bd0e0 (no-op after the ready path zeroed it); walk the +0x80 list (0x30-byte nodes: free each node's +0x10 buffer with size +0x20 + 1 unless it equals &node+0x20, then delete the node, 0x30 bytes); walk the +0x60 list (0x28-byte nodes: release each node+0x18 via 0x5f059b0, then delete the node, 0x28 bytes); free the +0x30 buffer (size +0x40 - +0x30), the +0x18 buffer (size +0x28 - +0x18) and the +0x0 buffer (size +0x10 - +0x0), each when non-null; operator delete(old, 0xe8)",
                "note": "unlike #3674's host, where this teardown is defensive (the mutex is held, so old is null), the old cache here is LIVE: re-fragmenting a memtable whose cache already exists really replaces it, so the sort/dedup/invoke sequence runs on real entries",
            },
            "landing_pads": "the five endbr64 stubs at 0x5f0a8cd..0x5f0a8fd each save %rax to %rbx and jump to 0x5f0a31a/0x5f0a33a/0x5f0a353/0x5f0a382/0x5f0a3a4 in the preceding FDE (a shared rethrow block); not decoded",
            "callers": "DBImplSecondary::RecoverLogFiles (0x5e82cc0), DBImpl::SwitchMemtable (0x5e8a890), FlushJob::MemPurge (0x5ed01f0)",
        },
        "readopts": {
            "name": "rocksdb::ReadOptions::ReadOptions",
            "init_map": {
                "+0x00..+0x0f": "0 (movups)",
                "+0x10": "0 (qword)",
                "+0x18..+0x27": "0 (movups)",
                "+0x28..+0x2b": "0 (dword)",
                "+0x2c": "0x101 (qword: bytes +0x2c = 1, +0x2d = 1, rest 0)",
                "+0x34..+0x35": "0 (u16)",
                "+0x38..+0x47": "0 (movups)",
                "+0x48": "0 (qword)",
                "+0x50": "0 (qword)",
                "+0x58..+0x67": "0 (movups)",
                "+0x68..+0x77": "0 (movups)",
                "+0x78": "-1 (qword)",
                "+0x80": "0 (byte)",
                "+0x84": "4 (dword)",
                "+0x88": "0x0100 (u16)",
            },
            "span_bytes": "0x8a (writes +0x00..+0x89)",
            "field_names": "open: the per-field source names are not pinned (see unknowns); the byte-level init map above is exact",
            "callers": "61 direct call sites (see census); the host's site is 0x5f0a43d",
        },
        "introsort_loop": {
            "name": "std::__introsort_loop (libstdc++ std::sort internals, by shape)",
            "arguments": ["rdi = first (16-byte entries)", "rsi = last", "rdx = depth limit (2*floor(log2(n)), or -2 when n == 0)"],
            "threshold": "range <= 0x100 bytes (16 entries): return at once; the caller finishes with __insertion_sort",
            "depth_zero": "depth == 0: heapsort fallback — __make_heap loop via __adjust_heap 0x5f04f80, then __sort_heap loop via __adjust_heap",
            "partition": "median-of-three pivot (first, middle, last by (first, second)), __unguarded_partition, recurse on the right partition (tail call to self), loop on the left",
            "comparator": "lexicographic on (first qword, second qword), unsigned (jb/jae); equal first qwords fall through to the second qword",
        },
        "insertion_sort": {
            "name": "std::__insertion_sort (libstdc++ std::sort internals, by shape)",
            "arguments": ["rdi = first (16-byte entries)", "rsi = last"],
            "algorithm": "classic insertion sort: for each entry past the first, shift the sorted prefix right while the predecessor is greater by (first, second), then insert",
            "comparator": "same lexicographic (first, second) unsigned order as __introsort_loop",
        },
        "adjust_heap": {
            "name": "std::__adjust_heap (libstdc++ std::sort internals, by shape)",
            "arguments": ["rdi = first (16-byte entries)", "rsi = hole index", "rdx = length (entries)", "rcx = value first qword", "r8 = value second qword"],
            "algorithm": "sift the hole down: repeatedly move the larger child (by (first, second)) into the hole, then sift the value back up from the hole's parent chain; the two call sites are the __make_heap build loop and the __sort_heap extraction loop inside __introsort_loop",
            "comparator": "same lexicographic (first, second) unsigned order",
        },
        "final_insertion_sort": {
            "name": "std::__final_insertion_sort (inlined in the host; by shape)",
            "algorithm": "if the range is > 16 entries: __insertion_sort(first, first + 16), then an unguarded insertion loop for the remaining entries (inlined at 0x5f0a704..0x5f0a759); otherwise __insertion_sort(first, last)",
        },
        "dedup": {
            "name": "adjacent-duplicate compaction (inlined in the host at 0x5f0a823..0x5f0a8c6)",
            "algorithm": "the sorted vector is walked with a write cursor; an entry equal to the previous kept entry in both qwords is skipped, otherwise it is copied forward; the vector end (+0xc8) is updated to the compacted end",
        },
        "cache_ctor": {
            "name": "FragmentedRangeTombstoneListCache constructor (by shape; re-shipped from #3674)",
            "arguments": ["rdi = cache (0xe8, operator new)", "rsi = &iterator (pointer to the 0x80 iterator*)", "rdx = iterator+8 (its Cleanable)", "ecx = arg4 (0 in the host)", "r8 = a 0x20-byte stack scratch (vector<size_t>: begin, end, capacity; zeroed by the host; the finalize fills it as a heap range, freed by the host after the install)"],
            "callers": "4 direct call sites: this host, NewRangeTombstoneIteratorInternal (#3674), CompactionRangeDelAggregator::NewIterator (0x5f29140), BlockBasedTable::ReadRangeDelBlock (0x6109c40)",
            "finalize": "FragmentedRangeTombstoneList::FragmentTombstones(unique_ptr<InternalIteratorBase<Slice>>, const InternalKeyComparator&, bool, const vector<size_t>&) at 0x5f36c70 (catalogue), called from the cache ctor at 0x5f3799f (main path) and 0x5f37ad1 (null-list path); it sets cache+0xb8 = 1 (the ready flag) and builds the fragmented tombstones; its internals are by contract in this packet (see unknowns)",
            "zero_init": {"+0x00..+0x10": "0", "+0x10..+0x40": "0", "+0x40": "0 (qword)", "+0x48": "0 (dword)", "+0x58": "0 (dword)", "+0x60": "0", "+0x68/+0x70": "&cache+0x58", "+0x78": "0", "+0x80..+0x90": "(cache+0x80, cache+0x80)", "+0x90": "0", "+0x98": "Cleanable (ctor 0x61bd0c0)", "+0xb8": "0 (byte)", "+0xc0..+0xd0": "0", "+0xd8..+0xe8": "0"},
            "iteration": "when *iterator == 0, the null-list path finalizes at once (0x5f37aa8); otherwise a stack iterator (vtable 0x64cca10+0x10, Cleanable at its +0x8) walks the list via vtable slots 0x10 (Valid), 0x18 (Next), 0x50 (key), 0x60 (size), 0x38 and 0x90, counting entries at cache+0xd8 and summing sizes at cache+0xe0; the loop at 0x5f37900 builds the sorted index vector (begin +0xc0, end +0xc8, capacity +0xd0)",
        },
        "cleanable_ctor": {
            "name": "rocksdb::Cleanable::Cleanable (re-shipped from #3674)",
            "fields": "head fn at +0x0 = 0, chain link at +0x18 = 0; arg1 (+0x8) and arg2 (+0x10) are left unwritten by the ctor",
        },
        "cleanable_dtor": {
            "name": "rocksdb::Cleanable::DoCleanup (re-shipped from #3674)",
            "algorithm": "run the head fn as fn(arg1, arg2) when non-null, then walk the +0x18 chain running each 0x20-byte node's fn(arg1, arg2) and freeing the node (0x20 bytes)",
        },
        "list_release": {
            "name": "node-tree list release (by shape; re-shipped from #3674)",
            "algorithm": "recursively release a tree of 0x28-byte nodes (+0x18 child first, then the node, then the +0x10 sibling)",
        },
        "finalize": {
            "name": "rocksdb::FragmentedRangeTombstoneList::FragmentTombstones",
            "catalogue": "librocksdb-sys 0.11.0+8.1.1",
            "contract": "FragmentTombstones(unique_ptr<InternalIteratorBase<Slice>>, const InternalKeyComparator&, bool, const vector<size_t>&): sets the cache ready flag +0xb8 = 1, walks the iterator (SeekToFirst slot 0x18, Valid slot 0x10, key slot 0x50, seq = (key last qword >> 8), slot 0x90, size slot 0x60, slot 0x98), allocates 0x40-byte tombstone nodes (operator new(0x40); +0x20/+0x28 pointers, +0x30 = seq, +0x38 = 0x0f) and fills the index; called only from the cache ctor (2 sites). Internals are by contract in this packet (see unknowns).",
        },
        "vtables": vtables,
        "census": census,
        "callers": callers,
        "packet_internal_sites": {
            "0x61bd0c0": [{"site": "0x5f0a449", "kind": "direct_call", "containing_fde": ["0x5f0a3d0", "0x5f0a909"], "role": "this host: Cleanable ctor at iterator+0x8"}],
            "0x61bd0e0": [{"site": "0x5f0a5b8", "kind": "direct_call", "containing_fde": ["0x5f0a3d0", "0x5f0a909"], "role": "this host: DoCleanup(old+0x98) in the common teardown tail"}],
        },
        "generic_helper_counts": {
            "0x61bd0c0": "103 direct call sites binary-wide (not enumerated; see census.py note)",
            "0x61bd0e0": "223 direct calls + 32 tail jumps binary-wide (not enumerated; see census.py note)",
        },
        "vendor_attribution": {
            "0x5f0a3d0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb8MemTable34ConstructFragmentedRangeTombstonesEv, 1238/1337 (92.60%)",
            "0x60b21f0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb11ReadOptionsC1Ev, 114/114 (100.00%)",
            "0x5f36c70": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb28FragmentedRangeTombstoneList18FragmentTombstonesESt10unique_ptrINS_20InternalIteratorBaseINS_5SliceEEESt14default_deleteIS4_EERKNS_21InternalKeyComparatorEbRKSt6vectorImSaImEE",
            "0x61bd0e0": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical copies of 2 build functions, e.g. _ZN7rocksdb9Cleanable9DoCleanupEv",
            "0x5f04f80/0x5f053d0/0x5f05120": "no catalogue row; identified by shape as libstdc++ std::sort internals (__adjust_heap / __introsort_loop / __insertion_sort) from the depth-limit, threshold and call structure",
        },
        "unknowns": [
            "the owner+0xa60 flag's setter (which store marks the cache already built)",
            "the owner (MemTable) fields the iterator build copies (+0x10, +0x31, +0x60, +0x6c, +0xa58, +0xc58) beyond the shard table at +0xd10/+0xd18: the +0xa58 object's identity (its vtable slot 0x90 is the rep-iterator factory, called with (obj, 0, 0)) and the +0xc58 pointer's role",
            "the ReadOptions per-field source names for the pinned init map (+0x2c = 0x101, +0x78 = -1, +0x84 = 4, +0x88 = 0x0100) and the +0x48 slot's source-level identity: it is read as a function pointer and invoked as fn(temp+0x38, temp+0x38, 3) when non-null, but the ctor zeroes it and no store in this flow rewrites it, so the call never fires here",
            "the +0xc0 index entries' semantic identity: observed as 16-byte (arg, fn) pairs, sorted lexicographically, deduplicated, and invoked as fn(arg) on teardown; which producer registers them is open (the finalize 0x5f36c70 is by contract)",
            "the FragmentTombstones finalize 0x5f36c70 internals: the 0x40-byte tombstone node layout beyond (+0x20/+0x28 pointers, +0x30 seq, +0x38 = 0x0f), which store populates cache+0x8/+0x20, and the exact contents of the vector<size_t> scratch",
            "the cache ctor's stack-iterator vtable 0x64cca10+0x10 slot identities beyond the walked slots",
            "the host's landing-pad stubs (shared rethrow block in the preceding FDE) and the LSDA call-site tables are not decoded",
            "the 0x5f32900 contract (applied by the caller to the returned iterator; 4 call sites, not a window) — carried over from #3674",
            "the sibling teardown FDEs 0x5f061b0 (_M_dispose), 0x5f0b080 (unique_ptr dtor) and 0x5f10d40 (MemTable dtor) share this teardown code; their entry conditions are not pinned here",
        ],
    }


if __name__ == "__main__":
    sys.exit(main())
