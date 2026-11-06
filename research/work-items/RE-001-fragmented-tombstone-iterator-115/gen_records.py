"""Generate records.json, callers.tsv, relocations.txt and vtables.tsv.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-iterator-115/gen_records.py

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
        # A vtable slot is a R_X86_64_RELATIVE entry; the qword after
        # the last slot is the next vtable's offset-to-top (no reloc),
        # so stop when the slot VA has no RELATIVE entry. This is what
        # keeps the Comparator vtables at 29 slots instead of reading
        # into the following vtable's header.
        if base + 0x10 + k * 8 not in rel:
            break
        f = reloc_val(data, segs, rel, base + 0x10 + k * 8)
        if f is None or f == 0:
            break
        slots.append((hex(k * 8), hex(f)))
        k += 1
        if k > 64:
            break
    return name, slots


def resolve_slot_owner(data, segs, rel, slot_va):
    """Find the vtable that owns a RELATIVE slot.

    Walks back from the slot in 8-byte steps (up to 32 slots) looking
    for a candidate base B where the qword at B is a small
    offset-to-top (0 or a small negative, stored raw) and the qword
    at B+8 resolves (via reloc) to a typeinfo object whose name
    string is printable ASCII. Returns (base, typeinfo_name,
    slot_index) or None.
    """
    for k in range(32):
        base = slot_va - 0x10 - k * 8
        off = va2off(segs, base)
        if off is None:
            continue
        top = struct.unpack_from("<q", data, off)[0]
        if top != 0 and not (-64 <= top < 0):
            continue
        ti = reloc_val(data, segs, rel, base + 8)
        if ti is None:
            continue
        name_va = reloc_val(data, segs, rel, ti + 8)
        if name_va is None:
            continue
        name = cstr_at_va(data, segs, name_va)
        if not name or len(name) < 3 or len(name) > 200:
            continue
        if not all(32 <= ord(c) < 127 for c in name):
            continue
        return base, name, k
    return None


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

MAXSEQ_ROLES = {
    0x5F0D1E5: "MemTable lookup path (no catalogue row; calls NewRangeTombstoneIterator 0x5f0b050 and MaxCoveringTombstoneSeqnum)",
    0x5F0E09C: "MemTable Get path (no catalogue row; calls GetFromTable 0x5f0ce10 and MaxCoveringTombstoneSeqnum)",
    0x5F3D5AA: "TableCache::UpdateRangeTombstoneSeqnums: the max covering seqnum for the key",
    0x5F4055E: "TableCache::Get: the max covering seqnum for the key",
}

SEEK_COVERING_ROLES = {
    0x5F320B5: "Seek: position at the covering tombstone for the key",
    0x5F32920: "MaxCoveringTombstoneSeqnum: position before reading the covering seqnum",
}

SEEKFORPREV_COVERING_ROLES = {
    0x5F32505: "SeekForPrev: position at the covering tombstone for the key",
}

SCAN_FORWARD_TAIL_ROLES = {
    0x5F31F63: "SeekToTopFirst: scan forward to the first visible tombstone",
    0x5F320BE: "Seek: scan forward to the first visible tombstone",
    0x5F325F3: "TopNext: scan forward to the next visible tombstone",
}

SEEK_TOP_FIRST_TAIL_ROLES = {
    0x5F25FF0: "TruncatedRangeDelIterator::SeekToFirst forwards to the fragmented iterator's SeekToTopFirst",
}

SCAN_BACKWARD_TAIL_ROLES = {
    0x5F323C4: "SeekToTopLast: scan backward to the first visible tombstone",
    0x5F3250E: "SeekForPrev: scan backward to the first visible tombstone",
    0x5F327D4: "TopPrev: scan backward to the previous visible tombstone",
}

SEEK_TOP_LAST_TAIL_ROLES = {
    0x5F26020: "TruncatedRangeDelIterator::SeekToLast forwards to the fragmented iterator's SeekToTopLast",
}

TOPNEXT_ROLES = {
    0x5F25DEE: "TruncatedRangeDelIterator::SeekInternalKey: advance to the next top tombstone",
    0x5F26534: "RangeDelAggregator::StripeRep::IsRangeOverlapped: advance to the next top tombstone",
    0x5F2BE17: "ForwardRangeDelIterator::ShouldDelete: advance to the next top tombstone",
    0x5F2C01A: "ForwardRangeDelIterator::ShouldDelete: advance to the next top tombstone (second site)",
    0x617A3BB: "MergingIterator path (no catalogue row; drives a TruncatedRangeDelIterator): advance to the next top tombstone",
    0x617C547: "range-del aggregation path (no catalogue row): advance to the next top tombstone",
    0x6180A1F: "MergingIterator path (no catalogue row): advance to the next top tombstone",
    0x6182033: "MergingIterator path (no catalogue row; calls TruncatedRangeDelIterator::Seek): advance to the next top tombstone",
}

TOPPREV_ROLES = {
    0x5F29EBE: "ReverseRangeDelIterator::ShouldDelete: step back to the previous top tombstone",
    0x5F2A0C8: "ReverseRangeDelIterator::ShouldDelete: step back to the previous top tombstone (second site)",
    0x617750B: "MergingIterator reverse path (no catalogue row; calls TruncatedRangeDelIterator::SeekForPrev): step back to the previous top tombstone",
    0x617976F: "range-del aggregation reverse path (no catalogue row): step back to the previous top tombstone",
}

ROLE_MAPS = {
    0x5F32900: MAXSEQ_ROLES,
    0x5F316D0: SEEK_COVERING_ROLES,
    0x5F31980: SEEKFORPREV_COVERING_ROLES,
    0x5F31C80: SCAN_FORWARD_TAIL_ROLES,
    0x5F31EB0: SEEK_TOP_FIRST_TAIL_ROLES,
    0x5F320F0: SCAN_BACKWARD_TAIL_ROLES,
    0x5F32310: SEEK_TOP_LAST_TAIL_ROLES,
    0x5F32540: TOPNEXT_ROLES,
    0x5F32720: TOPPREV_ROLES,
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
    for key, base in (("fragmented_range_tombstone_iterator", 0x64CCAE0),
                      ("memtable_iterator", 0x64CC638),
                      ("bytewise_comparator", 0x64D7028),
                      ("reverse_bytewise_comparator", 0x64D7148)):
        name, entries = resolve_vtable(data, segs, rel, base)
        vtables[key] = {
            "base": hex(base),
            "stored_pointer": hex(base + 0x10),
            "typeinfo_name": name,
            "slots": [{"offset": o, "target": t} for o, t in entries],
        }

    # Vtable-slot owners for every RELATIVE slot pointing at a target.
    # The .got section spans 0x64df458..0x64ee158 (readelf -S); a slot
    # in that range is a GOT entry, not a vtable slot.
    slot_owners = {}
    for t in census_mod.TARGETS:
        owners = []
        for s in slots[t]:
            if 0x64DF458 <= s < 0x64EE158:
                owners.append({"slot": hex(s), "kind": "got_slot"})
                continue
            got = resolve_slot_owner(data, segs, rel, s)
            if got is None:
                owners.append({"slot": hex(s), "kind": "unresolved"})
            else:
                base, name, k = got
                owners.append({"slot": hex(s), "kind": "vtable_slot",
                               "vtable_base": hex(base),
                               "typeinfo_name": name,
                               "slot_index": k,
                               "slot_offset": hex(k * 8)})
        slot_owners[hex(t)] = owners

    # Callers with roles.
    callers = {}
    for t in census_mod.TARGETS:
        rows = []
        roles = ROLE_MAPS.get(t, {})
        for v in calls[t]:
            f = containing(fdes, v)
            if f is None:
                raise SystemExit("census site without containing FDE: %#x -> %#x" % (t, v))
            if t == 0x5EAA060:
                lab = catalogue_label(by_start, f[0])
                if lab:
                    role = "shared AppendInternalKey call in " + lab.split(": ", 1)[-1][:100]
                else:
                    role = "shared AppendInternalKey call in FDE %#x (no catalogue row)" % f[0]
            else:
                role = roles.get(v, "")
                if not role:
                    raise SystemExit("missing role for site %#x -> %#x" % (t, v))
            rows.append({
                "site": hex(v),
                "kind": "direct_call",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": role,
            })
        for v in tails[t]:
            f = containing(fdes, v)
            if f is None:
                raise SystemExit("census tail without containing FDE: %#x -> %#x" % (t, v))
            role = roles.get(v, "")
            if not role:
                raise SystemExit("missing role for tail %#x -> %#x" % (t, v))
            rows.append({
                "site": hex(v),
                "kind": "tail_jump",
                "containing_fde": [hex(f[0]), hex(f[1])],
                "role": role,
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
        fh.write("No R_X86_64_RELATIVE entry in .rela.dyn has an addend equal to any packet window start, except the vtable slots that reference the windows (see below) and the GOT slots.\n")
        fh.write("The FragmentedRangeTombstoneIterator vtable (base 0x64ccae0, stored 0x64ccaf0) has 24 slots, stored+0x00..+0xb8; the MemTableIterator vtable (base 0x64cc638, stored 0x64cc648) has 24 slots; the BytewiseComparatorImpl vtable (base 0x64d7028, stored 0x64d7038) has 29 slots, stored+0x00..+0xe0; the ReverseBytewiseComparatorImpl vtable (base 0x64d7148, stored 0x64d7158) has 29 slots. Typeinfo names and every slot target are in vtables.tsv and records.json.\n")
        fh.write("Comparator GOT slots (R_X86_64_RELATIVE): 0x64ecfa8 -> 0x5d48400 (the builtin CompareTimestamp, returns 0), 0x64ecfb0 -> 0x5d48410 (the CompareWithoutTimestamp fast-path thunk). The neighbouring GOT slot 0x64ecfa0 -> 0x5d44c70 (catalogue: FSRandomAccessFileWrapper::Read) is unrelated to the comparator dispatch; it is not referenced by any family function.\n")
        fh.write("The Bytewise/Reverse typeinfo name strings begin with a literal '*' byte (the stored string is '*N7rocksdb12_GLOBAL__N_1...'), unlike the iterator typeinfo names, which start directly with 'N7rocksdb'. That '*' is the literal first byte of the name string in the binary, not a transcription artifact.\n")
        fh.write("No other relocation in the packet points at a window: the iterator is 0xc8 bytes, the fragment 0x30 bytes, the key cache is an inline std::string at +0xa8, and the seq/key arrays are heap ranges reached through the list pointer at +0x68 (no relocation).\n")

    records = build_records(calls, tails, hits, slots, callers, vtables, slot_owners, by_start)
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json, callers.tsv, relocations.txt, vtables.tsv")
    return 0

def build_records(calls, tails, hits, slots, callers, vtables, slot_owners, by_start):
    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    windows = [
        ("0x5f32900", "rocksdb::FragmentedRangeTombstoneIterator::MaxCoveringTombstoneSeqnum", "0x5f32900..0x5f32a0a", 0x10A, "maxseq-5f32900.objdump.txt"),
        ("0x5f316d0", "rocksdb::FragmentedRangeTombstoneIterator::SeekToCoveringTombstone", "0x5f316d0..0x5f31973", 0x2A3, "seek-covering-5f316d0.objdump.txt"),
        ("0x5f31980", "rocksdb::FragmentedRangeTombstoneIterator::SeekForPrevToCoveringTombstone", "0x5f31980..0x5f31c7d", 0x2FD, "seekforprev-covering-5f31980.objdump.txt"),
        ("0x5f31c80", "rocksdb::FragmentedRangeTombstoneIterator::ScanForwardToVisibleTombstone", "0x5f31c80..0x5f31ead", 0x22D, "scan-forward-5f31c80.objdump.txt"),
        ("0x5f31eb0", "rocksdb::FragmentedRangeTombstoneIterator::SeekToTopFirst", "0x5f31eb0..0x5f32099", 0x1E9, "seek-top-first-5f31eb0.objdump.txt"),
        ("0x5f320a0", "rocksdb::FragmentedRangeTombstoneIterator::Seek", "0x5f320a0..0x5f320e1", 0x41, "seek-5f320a0.objdump.txt"),
        ("0x5f320f0", "rocksdb::FragmentedRangeTombstoneIterator::ScanBackwardToVisibleTombstone", "0x5f320f0..0x5f3230b", 0x21B, "scan-backward-5f320f0.objdump.txt"),
        ("0x5f32310", "rocksdb::FragmentedRangeTombstoneIterator::SeekToTopLast", "0x5f32310..0x5f324ea", 0x1DA, "seek-top-last-5f32310.objdump.txt"),
        ("0x5f324f0", "rocksdb::FragmentedRangeTombstoneIterator::SeekForPrev", "0x5f324f0..0x5f32531", 0x41, "seekforprev-5f324f0.objdump.txt"),
        ("0x5f32540", "rocksdb::FragmentedRangeTombstoneIterator::TopNext", "0x5f32540..0x5f32719", 0x1D9, "topnext-5f32540.objdump.txt"),
        ("0x5f32720", "rocksdb::FragmentedRangeTombstoneIterator::TopPrev", "0x5f32720..0x5f328fa", 0x1DA, "topprev-5f32720.objdump.txt"),
        ("0x5f32a10", "rocksdb::FragmentedRangeTombstoneIterator::~FragmentedRangeTombstoneIterator (D1)", "0x5f32a10..0x5f32b7d", 0x16D, "dtor-d1-5f32a10.objdump.txt"),
        ("0x5f32b80", "rocksdb::FragmentedRangeTombstoneIterator::~FragmentedRangeTombstoneIterator (D0)", "0x5f32b80..0x5f32cfd", 0x17D, "dtor-d0-5f32b80.objdump.txt"),
        ("0x5f2e8f0", "rocksdb::FragmentedRangeTombstoneIterator::Valid (by shape; no catalogue row)", "0x5f2e8f0..0x5f2e90e", 0x1E, "valid-5f2e8f0.objdump.txt"),
        ("0x5f2e8d0", "rocksdb::FragmentedRangeTombstoneIterator::SeekToFirst (by shape; no catalogue row)", "0x5f2e8d0..0x5f2e8e9", 0x19, "seektofirst-5f2e8d0.objdump.txt"),
        ("0x5f2ee70", "rocksdb::FragmentedRangeTombstoneIterator::SeekToLast", "0x5f2ee70..0x5f2ee92", 0x22, "seektolast-5f2ee70.objdump.txt"),
        ("0x5f2eea0", "rocksdb::FragmentedRangeTombstoneIterator::Next", "0x5f2eea0..0x5f2eee4", 0x44, "next-5f2eea0.objdump.txt"),
        ("0x5f2eef0", "rocksdb::FragmentedRangeTombstoneIterator::Prev", "0x5f2eef0..0x5f2ef60", 0x70, "prev-5f2eef0.objdump.txt"),
        ("0x5eba980", "rocksdb::FragmentedRangeTombstoneIterator::key", "0x5eba980..0x5ebaa54", 0xD4, "key-5eba980.objdump.txt"),
        ("0x5eba910", "rocksdb::FragmentedRangeTombstoneIterator::value (by shape; no catalogue row)", "0x5eba910..0x5eba924", 0x14, "value-endkey-5eba910.objdump.txt"),
        ("0x5df7ce0", "rocksdb::InternalIteratorBase<Slice>::NextAndGetResult (shared impl)", "0x5df7ce0..0x5df7d24", 0x44, "nextandgetresult-5df7ce0.objdump.txt"),
        ("0x5df7650", "shared base-class accessor: key() minus the 8-byte internal-key trailer (by shape; no catalogue row; C++ name open)", "0x5df7650..0x5df7667", 0x17, "slot11-userkey-5df7650.objdump.txt"),
        ("0x5f2e7b0", "rocksdb::FragmentedRangeTombstoneIterator::status (by shape; no catalogue row)", "0x5f2e7b0..0x5f2e7cc", 0x1C, "status-5f2e7b0.objdump.txt"),
        ("0x5df7670", "shared bool getter (returns 1; by shape; no catalogue row; C++ name open)", "0x5df7670..0x5df767a", 0x0A, "ret1-a-5df7670.objdump.txt"),
        ("0x5df7680", "shared bool getter (returns 1; by shape; no catalogue row; C++ name open)", "0x5df7680..0x5df768a", 0x0A, "ret1-b-5df7680.objdump.txt"),
        ("0x5df7690", "shared bool getter (returns 0; by shape; no catalogue row; C++ name open)", "0x5df7690..0x5df7697", 0x07, "ret0-a-5df7690.objdump.txt"),
        ("0x5d485b0", "shared void no-op (by shape; no catalogue row; C++ name open)", "0x5d485b0..0x5d485b5", 0x05, "voidret-5d485b0.objdump.txt"),
        ("0x5f2e790", "bool getter (returns 0; by shape; no catalogue row; C++ name open)", "0x5f2e790..0x5f2e797", 0x07, "ret0-b-5f2e790.objdump.txt"),
        ("0x5f2e7a0", "bool getter (returns 1; by shape; no catalogue row; C++ name open)", "0x5f2e7a0..0x5f2e7aa", 0x0A, "ret1-c-5f2e7a0.objdump.txt"),
        ("0x5df7800", "shared Status builder (one of 2 identical copies of 7 build functions, e.g. Checkpoint::CreateCheckpoint; role open)", "0x5df7800..0x5df7871", 0x71, "status-builder-5df7800.objdump.txt"),
        ("0x5df76d0", "shared void no-op (by shape; no catalogue row; C++ name open)", "0x5df76d0..0x5df76d5", 0x05, "voidret-b-5df76d0.objdump.txt"),
        ("0x5df76e0", "shared void no-op (by shape; no catalogue row; C++ name open)", "0x5df76e0..0x5df76e5", 0x05, "voidret-c-5df76e0.objdump.txt"),
        ("0x5df7640", "shared bool getter (returns 0; by shape; no catalogue row; C++ name open)", "0x5df7640..0x5df7647", 0x07, "ret0-c-5df7640.objdump.txt"),
    ]
    window_recs = []
    for addr, name, fde, size, excerpt in windows:
        lab = catalogue_label(by_start, int(addr, 16))
        window_recs.append({
            "address": addr, "name": name, "fde": fde,
            "size_bytes": size, "catalogue": lab, "excerpt": excerpt,
        })
    return {
        "task": "RE-001",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "windows": window_recs,
        "layout": {
            "iterator_size_bytes": 0xC8,
            "fields": {
                "+0x00": "vtable 0x64ccae0+0x10 (rocksdb::FragmentedRangeTombstoneIterator, 24 slots)",
                "+0x08": "Cleanable subobject (ctor 0x61bd0c0, by contract from #3674)",
                "+0x28": "comparator+0x8",
                "+0x30": "comparator+0x8",
                "+0x38": "comparator (the icmp pointer)",
                "+0x40": "comparator+0x8 (P: the user-comparator object; the seek/scan code calls P->vtable[0xc8] and P->vtable[0xd0])",
                "+0x48": "second shared_ptr ptr (null from both ctors; released by the dtor when non-null; what sets it is open)",
                "+0x50": "second shared_ptr ctrl (null from both ctors)",
                "+0x58": "cache shared_ptr ptr (null in ctor A; the shared_ptr copy in ctor B)",
                "+0x60": "cache shared_ptr ctrl (null in ctor A; bumped on copy in ctor B)",
                "+0x68": "list (ctor A) or cache object (ctor B) pointer",
                "+0x70": "read seq (the upper bound for the descending seqnum search)",
                "+0x78": "arg6 (u64; the visibility threshold: a tombstone is visible when its seqnum >= arg6)",
                "+0x80": "upper_bound Slice* (an empty slice is treated as null)",
                "+0x88": "current fragment pointer (list+0x8 = frag end when invalid)",
                "+0x90": "current seqnum pointer (an index into the seq array)",
                "+0x98": "shadow copy of +0x88 (key() cache invalidation)",
                "+0xa0": "shadow copy of +0x90 (key() cache invalidation)",
                "+0xa8": "cached-key std::string data pointer (initially &this+0xb8, the inline buffer)",
                "+0xb0": "cached-key std::string size (initially 0)",
                "+0xb8": "cached-key std::string inline buffer (16 bytes; first byte cleared on rebuild)",
            },
            "fragment_size_bytes": 0x30,
            "fragment_fields": {
                "+0x00": "start-key Slice (ptr, len)",
                "+0x10": "end-key Slice (ptr, len)",
                "+0x20": "seq_idx_begin (index into the seq array)",
                "+0x28": "seq_idx_end (index into the seq array)",
            },
            "list_fields": {
                "+0x00": "frag_begin",
                "+0x08": "frag_end",
                "+0x10": "unknown (not read by this family)",
                "+0x18": "seq-array base (pointer)",
                "+0x20": "seq-array end (pointer)",
                "+0x28": "unknown (not read by this family)",
                "+0x30": "key-array base (16-byte Slice entries, one per seqnum index)",
            },
            "seqnum_order": "the seq array is sorted DESCENDING within each fragment's [seq_idx_begin, seq_idx_end) range; the search finds the first element <= read seq (this+0x70)",
        },
        "constructors": {
            "note": "by contract from open PR #3674 (same binary); not re-shipped as excerpts here. The layout above is cross-checked against the destructor and the seek/scan windows in this packet.",
            "ctor_a": {
                "address": "0x5f31380", "name": "rocksdb::FragmentedRangeTombstoneIterator::FragmentedRangeTombstoneIterator(list, comparator, seq, slice, arg6)",
                "arguments": ["rdi = this (0xc8)", "rsi = list", "rdx = comparator", "rcx = seq (arg4)", "r8 = slice (arg5)", "r9 = arg6"],
                "initial_position": "frag = list+0x8 (frag end), seq = list+0x18 (seq base); the shadow matches, so a fresh iterator is invalid and key() returns the empty cached string",
                "shared_ptr": "the cache shared_ptr at +0x58/+0x60 is null",
            },
            "ctor_b": {
                "address": "0x5f315a0", "name": "rocksdb::FragmentedRangeTombstoneIterator::FragmentedRangeTombstoneIterator(shared_ptr<Cache>, comparator, seq, slice, arg6)",
                "arguments": ["rdi = this (0xc8)", "rsi = shared_ptr<Cache>", "rdx = comparator", "rcx = seq (arg4)", "r8 = slice (arg5)", "r9 = arg6"],
                "initial_position": "frag = cache+0x8 (frag end), seq = cache+0x20 (seq end); the shadow matches, so a fresh iterator is invalid",
                "shared_ptr": "the shared_ptr copy lands at +0x58 (ptr) / +0x60 (ctrl); the use count at ctrl+0x8 is bumped (lock addl iff the global byte at 0x64ed290 is 0, else plain addl); +0x68 = the cache object pointer",
            },
        },
        "vtable": {
            "base": "0x64ccae0", "stored_pointer": "0x64ccaf0",
            "typeinfo_name": "N7rocksdb32FragmentedRangeTombstoneIteratorE",
            "slot_count": 24,
            "slots": [
                {"offset": "+0x00", "target": "0x5f32a10", "role": "~FragmentedRangeTombstoneIterator (D1)"},
                {"offset": "+0x08", "target": "0x5f32b80", "role": "~FragmentedRangeTombstoneIterator (D0)"},
                {"offset": "+0x10", "target": "0x5f2e8f0", "role": "Valid"},
                {"offset": "+0x18", "target": "0x5f2e8d0", "role": "SeekToFirst"},
                {"offset": "+0x20", "target": "0x5f2ee70", "role": "SeekToLast"},
                {"offset": "+0x28", "target": "0x5f320a0", "role": "Seek"},
                {"offset": "+0x30", "target": "0x5f324f0", "role": "SeekForPrev"},
                {"offset": "+0x38", "target": "0x5f2eea0", "role": "Next"},
                {"offset": "+0x40", "target": "0x5df7ce0", "role": "NextAndGetResult (shared InternalIteratorBase<Slice> impl)"},
                {"offset": "+0x48", "target": "0x5f2eef0", "role": "Prev"},
                {"offset": "+0x50", "target": "0x5eba980", "role": "key"},
                {"offset": "+0x58", "target": "0x5df7650", "role": "shared base-class accessor: key() minus the 8-byte trailer (C++ name open)"},
                {"offset": "+0x60", "target": "0x5eba910", "role": "value (the fragment end key)"},
                {"offset": "+0x68", "target": "0x5f2e7b0", "role": "status (OK Status, 16-byte zero)"},
                {"offset": "+0x70", "target": "0x5df7670", "role": "shared bool getter, returns 1 (C++ name open)"},
                {"offset": "+0x78", "target": "0x5df7680", "role": "shared bool getter, returns 1 (C++ name open)"},
                {"offset": "+0x80", "target": "0x5df7690", "role": "shared bool getter, returns 0 (C++ name open)"},
                {"offset": "+0x88", "target": "0x5d485b0", "role": "shared void no-op (C++ name open)"},
                {"offset": "+0x90", "target": "0x5f2e790", "role": "bool getter, returns 0 (C++ name open)"},
                {"offset": "+0x98", "target": "0x5f2e7a0", "role": "bool getter, returns 1 (C++ name open)"},
                {"offset": "+0xa0", "target": "0x5df7800", "role": "shared Status builder (catalogue: one of 2 identical copies of 7 build functions; role open)"},
                {"offset": "+0xa8", "target": "0x5df76d0", "role": "shared void no-op (C++ name open)"},
                {"offset": "+0xb0", "target": "0x5df76e0", "role": "shared void no-op (C++ name open)"},
                {"offset": "+0xb8", "target": "0x5df7640", "role": "shared bool getter, returns 0 (C++ name open)"},
            ],
            "shared_with_memtable_iterator": "slots [11], [14], [15], [16], [17], [20], [21], [22], [23] are the same function addresses in the MemTableIterator vtable (base 0x64cc638, stored 0x64cc648, typeinfo N7rocksdb16MemTableIteratorE); MemTableIterator differs at [8] (own NextAndGetResult 0x5f08790), [10] (own key 0x5f05e10), [12] (own value 0x5f05e80), [13] (own status 0x5f05680), [18] (0x5f04e00), [19] (0x5f04e10)",
            "seek_seekforprev_twin": "Seek (0x5f320a0) and SeekForPrev (0x5f324f0) are the same 65-byte shape with different callees (SeekToCoveringTombstone + ScanForward vs SeekForPrevToCoveringTombstone + ScanBackward); the catalogue lists them as one of 2 identical copies of 2 build functions",
        },
        "comparator_dispatch": {
            "P": "this+0x40 = icmp+0x8 (the user-comparator object); the seek/scan code calls P->vtable[0xc8] and P->vtable[0xd0]",
            "slot_0xc8": {"offset": 25, "name": "CompareTimestamp (best-supported reading)", "args": "(entry_slice, upper_bound_slice)", "builtin_impl": "0x5d48400 (xor eax,eax; ret — returns 0)", "reading": "for timestamp-less comparators it returns 0, so the upper-bound binary search over the key array consumes 0 entries and the clamp is a no-op; confirmed in both the Bytewise and Reverse vtables (slot 25 = 0x5d48400 in both)"},
            "slot_0xd0": {"offset": 26, "name": "CompareWithoutTimestamp (catalogue-confirmed)", "args": "(a_slice, a_has_ts, b_slice, b_has_ts)", "bytewise_impl": "0x61bdc40 (plain memcmp lexicographic compare ignoring the two bool flags)", "reverse_impl": "0x61bdc90 (negated memcmp with reversed length tiebreak)", "catalogue": "BytewiseComparatorImpl::CompareWithoutTimestamp, ReverseBytewiseComparatorImpl::CompareWithoutTimestamp"},
            "got_slots": {"0x64ecfa8": "0x5d48400 (the builtin CompareTimestamp)", "0x64ecfb0": "0x5d48410 (the CompareWithoutTimestamp fast-path thunk)"},
            "fast_paths": "the seek/scan code compares the resolved slot-0xd0 pointer against *(0x64ecfb0): when equal it calls Q->vtable[0x10] directly (Q = *(P+0x20)) instead of the virtual call; the slot-0xc8 code compares against *(0x64ecfa8): when the impl is the ret-0 builtin the key-array binary search short-circuits before any comparison (the base pointer never moves, consumed = 0), so the clamp never fires",
            "thunk_0x5d48410": "forwards to *(P+0x20)->vtable[0x10] with (slice, slice); it matches NO vtable slot in this binary (only the GOT slot 0x64ecfb0), so the slot-0xd0 inline fast path is the only way it is reached; the identity of Q->vtable[0x10] is open",
            "got_slot_0x64ecfa0": "-> 0x5d44c70 (catalogue: FSRandomAccessFileWrapper::Read); a neighbouring GOT slot, NOT part of the comparator dispatch — no family function references it",
            "open": "the identity of P's +0x20 subobject Q; how icmp+0x8 holds a Comparator* when InternalKeyComparator is 8 bytes; the exact C++ name of slot 0xc8 (CompareTimestamp is the best-supported reading, from the ret-0 default and the CompareWithoutTimestamp neighbour)",
        },
        "seq_search": {
            "name": "descending-seqnum binary search (shared by SeekToCoveringTombstone, SeekForPrevToCoveringTombstone, ScanForward, ScanBackward, SeekToTopFirst, SeekToTopLast, TopNext, TopPrev)",
            "algorithm": "binary search over the fragment's [seq_idx_begin, seq_idx_end) range of the seq array (descending) for the FIRST element <= read seq (this+0x70); returns the range end when no element is <= read seq; the search is the same shape in all eight functions (mid = base + (n/2); compare read seq against *mid: read_seq >= *mid (jae) keeps the left half (count = half), else the base advances past mid)",
            "model": "first_seq_le(read_seq, begin, end) in tools/fragmented_tombstone_iterator_115.py",
        },
        "upper_bound_clamp": {
            "name": "upper-bound clamp via comparator slot 0xc8 (shared by the same eight functions)",
            "algorithm": "when the upper_bound Slice* (this+0x80) is non-null and its length is non-zero, binary-search the key array (list+0x30, 16-byte Slice entries, one per seqnum index) over the fragment's [seq_idx_begin, seq_idx_end) range for the first entry with CompareTimestamp(entry, upper_bound) <= 0; the loop goes left when the comparison is <= 0 and right when it is > 0, so it assumes the key array is sorted with the comparison decreasing in the entry index; let consumed = that entry's index within the range; if the current seq offset (seq_ptr - (seq_base + begin*8)) / 8 >= consumed, keep the position; else set seq_ptr = seq_base + (begin + consumed)*8",
            "builtin_noop": "with the builtin comparators (slot 0xc8 = 0x5d48400, always 0) the search short-circuits before any comparison (the base pointer never moves, consumed = 0), so the clamp never fires; a timestamped comparator (slot 0xc8 returning a real ordering) makes the clamp cut the visible seq window at the first key-array entry whose timestamp comparison is <= 0, skipping the leading entries past the upper bound",
            "open": "the semantic identity of the key-array entries (per-seqnum 16-byte key slices; end keys vs timestamp keys is open)",
        },
        "methods": {
            "max_covering_tombstone_seqnum": {
                "address": "0x5f32900", "name": "rocksdb::FragmentedRangeTombstoneIterator::MaxCoveringTombstoneSeqnum(const Slice&)",
                "arguments": ["rdi = this", "rsi = key Slice*"],
                "algorithm": "call SeekToCoveringTombstone(key); check Valid() (devirtualized: the code compares the vtable slot 0x10 pointer against 0x5f2e8f0 and calls it only when different); if invalid, return 0; if the seq pointer is at the fragment's seq-range end, return 0; compare the key against the fragment start key via slot 0xd0 (CompareWithoutTimestamp); if the fragment start key > key, return 0; else return *(this+0x90), the covering seqnum",
                "callers": "4 direct call sites: two MemTable lookup/Get paths (0x5f0d050, 0x5f0d740), TableCache::UpdateRangeTombstoneSeqnums, TableCache::Get",
            },
            "seek_to_covering_tombstone": {
                "address": "0x5f316d0", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekToCoveringTombstone(const Slice&)",
                "arguments": ["rdi = this", "rsi = key Slice*"],
                "algorithm": "phase 1: binary search over the fragments by end key via slot 0xd0 (compare(key, 1, frag+0x10, 1)) for the FIRST fragment with end_key > key; phase 2: the descending-seqnum search over that fragment's range for the first seq <= read seq; phase 3: the upper-bound clamp; empty list -> the end position (frag = frag_end, seq = seq_end)",
                "note": "does NOT update the shadow (+0x98/+0xa0); it writes +0x88/+0x90 with plain qword stores",
            },
            "seek_for_prev_to_covering_tombstone": {
                "address": "0x5f31980", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekForPrevToCoveringTombstone(const Slice&)",
                "arguments": ["rdi = this", "rsi = key Slice*"],
                "algorithm": "phase 1: binary search over the fragments by START key via slot 0xd0 (compare(key, 1, frag+0x00, 1)) for the FIRST fragment with start_key > key, then step back one fragment (the last fragment with start_key <= key); phase 2: the descending-seqnum search over that fragment's range; phase 3: the upper-bound clamp; empty list -> frag = list begin (= frag end), seq = seq end; no covering fragment (first fragment starts after the key) -> frag = frag_end, seq = seq_base (list+0x18)",
                "note": "the phase-1 comparison uses the fragment BASE (&frag+0x00, the start key), where SeekToCoveringTombstone uses &frag+0x10 (the end key); the two searches are otherwise the same shape",
            },
            "scan_forward_to_visible_tombstone": {
                "address": "0x5f31c80", "name": "rocksdb::FragmentedRangeTombstoneIterator::ScanForwardToVisibleTombstone()",
                "algorithm": "loop: if the fragment is the end, return; if the seq pointer is at the fragment's seq-range end, advance to the next fragment (re-run the descending-seqnum search on the new fragment, then the upper-bound clamp; at the last fragment -> the end position (frag = frag_end, seq = seq_end)); if *seq >= arg6 (this+0x78), the tombstone is visible: return; else advance to the next fragment the same way",
                "note": "the visibility threshold is arg6: tombstones with seqnum < arg6 are skipped forward; the seq search after each advance re-pins the first seq <= read seq",
            },
            "scan_backward_to_visible_tombstone": {
                "address": "0x5f320f0", "name": "rocksdb::FragmentedRangeTombstoneIterator::ScanBackwardToVisibleTombstone()",
                "algorithm": "the backward mirror of ScanForward: loop: if the fragment is the end, return; if the seq pointer is at the fragment's seq-range end, step back to the previous fragment (re-run the descending-seqnum search on the previous fragment, then the upper-bound clamp; at the first fragment -> the end position (frag = frag_end, seq = seq_end)); if *seq >= arg6, visible: return; else step back the same way",
            },
            "seek_to_top_first": {
                "address": "0x5f31eb0", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekToTopFirst()",
                "algorithm": "empty list -> the end position; else frag = first fragment, the descending-seqnum search over its range, the upper-bound clamp, then tail-jump to ScanForwardToVisibleTombstone",
            },
            "seek_to_top_last": {
                "address": "0x5f32310", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekToTopLast()",
                "algorithm": "empty list -> the end position; else frag = last fragment (frag_end - 0x30), the descending-seqnum search over its range, the upper-bound clamp, then tail-jump to ScanBackwardToVisibleTombstone",
            },
            "seek": {
                "address": "0x5f320a0", "name": "rocksdb::FragmentedRangeTombstoneIterator::Seek(const Slice&)",
                "algorithm": "empty list -> the end position (frag = frag_end, seq = seq_end); else call SeekToCoveringTombstone(key), then tail-jump to ScanForwardToVisibleTombstone",
            },
            "seek_for_prev": {
                "address": "0x5f324f0", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekForPrev(const Slice&)",
                "algorithm": "empty list -> the end position (frag = frag_end, seq = seq_end); else call SeekForPrevToCoveringTombstone(key), then tail-jump to ScanBackwardToVisibleTombstone; byte-identical shape to Seek except the callee and the scan direction",
            },
            "top_next": {
                "address": "0x5f32540", "name": "rocksdb::FragmentedRangeTombstoneIterator::TopNext()",
                "algorithm": "frag += 0x30 (one fragment); if the new fragment is the end, return (the seq pointer is left as-is; Valid() is false so it is not read); else the descending-seqnum search over the new fragment's range (read via the old fragment's +0x50/+0x58), the upper-bound clamp, then tail-jump to ScanForwardToVisibleTombstone",
                "callers": "8 direct call sites: TruncatedRangeDelIterator::SeekInternalKey, RangeDelAggregator::StripeRep::IsRangeOverlapped, ForwardRangeDelIterator::ShouldDelete (x2), and four MergingIterator / range-del aggregation paths in the 0x617xxxx region",
            },
            "top_prev": {
                "address": "0x5f32720", "name": "rocksdb::FragmentedRangeTombstoneIterator::TopPrev()",
                "algorithm": "at the first fragment -> the end position with seq = seq_base (list+0x18), NOT seq_end (this differs from Prev's end position); else frag -= 0x30, the descending-seqnum search over the previous fragment's range (read via -0x10/-0x8 of the old fragment), the upper-bound clamp, then tail-jump to ScanBackwardToVisibleTombstone",
                "callers": "4 direct call sites: ReverseRangeDelIterator::ShouldDelete (x2) and two MergingIterator / range-del aggregation reverse paths in the 0x617xxxx region",
            },
            "valid": {
                "address": "0x5f2e8f0", "name": "rocksdb::FragmentedRangeTombstoneIterator::Valid() (by shape; no catalogue row)",
                "algorithm": "(list != null) && (*(list+0x8) != +0x88): the list pointer is non-null and the current fragment is not the frag end",
            },
            "seek_to_first": {
                "address": "0x5f2e8d0", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekToFirst() (by shape; no catalogue row)",
                "algorithm": "frag = first fragment (list begin), seq = seq base (list+0x18); does not update the shadow",
            },
            "seek_to_last": {
                "address": "0x5f2ee70", "name": "rocksdb::FragmentedRangeTombstoneIterator::SeekToLast()",
                "algorithm": "frag = last fragment and seq = last seqnum in one paddq with the constant at 0x4535e0 = (-48, -8): frag = frag_end - 0x30, seq = seq_end - 8; does not update the shadow",
            },
            "next": {
                "address": "0x5f2eea0", "name": "rocksdb::FragmentedRangeTombstoneIterator::Next()",
                "algorithm": "seq_ptr += 8; if the new seq pointer is the fragment's seq-range end (seq_base + frag+0x28*8), frag += 0x30; does not update the shadow (so key() rebuilds after a Next)",
            },
            "prev": {
                "address": "0x5f2eef0", "name": "rocksdb::FragmentedRangeTombstoneIterator::Prev()",
                "algorithm": "if the seq pointer is the seq-array base (list+0x18), the end position (frag = frag_end, seq = seq_end, shadow updated too); else seq_ptr -= 8; if the new seq pointer is the fragment's seq-range start (seq_base + frag+0x20*8 - 8), frag -= 0x30; does not update the shadow except on the array-base end path",
            },
            "key": {
                "address": "0x5eba980", "name": "rocksdb::FragmentedRangeTombstoneIterator::key()",
                "algorithm": "if the fragment is the end, return the cached string; if the seq pointer is the seq-array end, return the cached string; if (frag, seq_ptr) == (shadow frag, shadow seq), return the cached string; else rebuild: clear the cached string (+0xb0 = 0, first byte 0), build a 25-byte ParsedInternalKey on the stack (start-key Slice at +0x00, seqnum at +0x10, type byte 0x0f at +0x18), call AppendInternalKey(0x5eaa060) to append start_key + PackSequenceAndType(seq, 0x0f), then set the shadow to the current position and return (cached data, cached size)",
                "note": "the cached key is the fragment START key + the 8-byte (seq << 8 | 0x0f) trailer (kTypeRangeDeletion); at the end position key() returns the STALE cached key (empty on a fresh iterator) without rebuilding; the stack canary is checked before returning",
            },
            "value": {
                "address": "0x5eba910", "name": "rocksdb::FragmentedRangeTombstoneIterator::value() (by shape; no catalogue row)",
                "algorithm": "return the fragment end-key Slice (frag+0x10, frag+0x18): for a range tombstone the 'value' is its end key",
            },
            "next_and_get_result": {
                "address": "0x5df7ce0", "name": "rocksdb::InternalIteratorBase<Slice>::NextAndGetResult(IterateResult*) (shared impl)",
                "algorithm": "call vtable slot 0x38 (Next); call vtable slot 0x10 (Valid); if valid, call vtable slot 0x50 (key) into result+0x0/+0x8 and store a u16 0 at result+0x10; return the Valid result",
                "note": "the IterateResult layout is only partly pinned: key Slice at +0x0/+0x8, a u16 0 at +0x10; the remaining fields are open",
            },
            "slot11_accessor": {
                "address": "0x5df7650", "name": "shared base-class accessor (C++ name open; by shape; no catalogue row)",
                "algorithm": "return key() with the length reduced by 8 (the internal-key trailer stripped): the user key of the current tombstone's start key; implemented once in the shared base and used by both the FragmentedRangeTombstoneIterator and MemTableIterator vtables",
                "open": "its C++ name (it sits between key() and value() in the vtable; the user-key reading is behaviourally exact but the declared name is not established)",
            },
            "status": {
                "address": "0x5f2e7b0", "name": "rocksdb::FragmentedRangeTombstoneIterator::status() (by shape; no catalogue row)",
                "algorithm": "return an OK Status (16-byte zero)",
            },
            "bool_getters_and_noops": {
                "addresses": ["0x5df7670", "0x5df7680", "0x5df7690", "0x5d485b0", "0x5f2e790", "0x5f2e7a0", "0x5df76d0", "0x5df76e0", "0x5df7640"],
                "algorithm": "tiny shared stubs: 0x5df7670/0x5df7680/0x5f2e7a0 return 1, 0x5df7690/0x5f2e790/0x5df7640 return 0, 0x5d485b0/0x5df76d0/0x5df76e0 return void; their C++ names are open (bool getters / void no-ops of the InternalIteratorBase interface)",
            },
            "status_builder": {
                "address": "0x5df7800", "name": "shared Status builder (catalogue: one of 2 identical copies of 7 build functions, e.g. Checkpoint::CreateCheckpoint; role open)",
                "algorithm": "builds a Status via 0x61cf670 from empty strings and returns `this`; shared by many vtables (19 RELATIVE slots); which interface method it serves in this vtable is open",
            },
            "dtor_d1": {
                "address": "0x5f32a10", "name": "rocksdb::FragmentedRangeTombstoneIterator::~FragmentedRangeTombstoneIterator (D1)",
                "algorithm": "reset the vtable to 0x64ccae0+0x10; free the cached-key string's heap buffer when its data pointer is not the inline buffer (operator delete(ptr, capacity+1)); release the cache shared_ptr (ctrl at +0x60) via _M_release (packed 0x100000001 fast dispose, else the 0x64ed290-selector decrement, dispose via 0x5d35070 when the count reaches 0); release the second shared_ptr (ctrl at +0x50) the same way; reset the vtable to the base 0x64ca800+0x10 and tail-jump to Cleanable::DoCleanup (0x61bd0e0)",
            },
            "dtor_d0": {
                "address": "0x5f32b80", "name": "rocksdb::FragmentedRangeTombstoneIterator::~FragmentedRangeTombstoneIterator (D0)",
                "algorithm": "identical to D1 except it CALLS Cleanable::DoCleanup (0x61bd0e0) instead of tail-jumping to it, then operator delete(this, 0xc8)",
            },
        },
        "end_positions": {
            "note": "there are TWO end variants; both are invalid (Valid() only checks frag != frag_end), but they differ in the seq pointer, which key() and MaxCoveringTombstoneSeqnum read",
            "frag_end_seq_end": "frag = frag_end (list+0x8), seq = seq_end (list+0x20): produced by the constructors' B path, Seek/SeekForPrev empty paths, SeekToCoveringTombstone empty path, ScanForward/ScanBackward end paths, Prev's array-base path",
            "frag_end_seq_base": "frag = frag_end (list+0x8), seq = seq_base (list+0x18): produced by ctor A, SeekForPrevToCoveringTombstone's no-covering path, TopPrev's first-fragment path",
            "topnext_end": "TopNext at the last fragment returns with frag = frag_end and the seq pointer LEFT AS-IS (not reset to either end variant)",
        },
        "shadow": {
            "note": "the shadow (+0x98/+0xa0) records the position at which key() was last built; key() rebuilds exactly when the current position differs from the shadow (or when it is at the end, where it returns the cached key without rebuilding)",
            "written_by": "key() itself (after rebuilding: +0x98 = +0x88, +0xa0 = +0x90); the constructors (both pairs set to the initial position); the end-position movups pairs (Seek/SeekForPrev empty paths, SeekToTopFirst/Last empty paths, SeekForPrevToCoveringTombstone empty/no-covering paths, ScanForward/ScanBackward end paths, TopPrev first-fragment path, Prev array-base path)",
            "not_written_by": "SeekToCoveringTombstone, SeekForPrevToCoveringTombstone (normal paths), ScanForward/ScanBackward (normal paths), SeekToTopFirst/Last (normal paths), TopNext/TopPrev (normal paths), SeekToFirst, SeekToLast, Next, Prev (normal paths) — all write +0x88/+0x90 with plain qword stores and leave the shadow stale, so key() rebuilds after any of them moves the iterator",
        },
        "vtables": vtables,
        "vtable_slot_owners": slot_owners,
        "census": census,
        "callers": callers,
        "packet_internal_sites": {
            "0x61bd0e0": [
                {"site": "0x5f32aea", "kind": "tail_jump", "containing_fde": ["0x5f32a10", "0x5f32b7d"], "role": "D1: tail-jump to Cleanable::DoCleanup"},
                {"site": "0x5f32c58", "kind": "direct_call", "containing_fde": ["0x5f32b80", "0x5f32cfd"], "role": "D0: call Cleanable::DoCleanup before operator delete"},
            ],
            "0x5d35070": [
                {"site": "0x5f32b63", "kind": "direct_call", "containing_fde": ["0x5f32a10", "0x5f32b7d"], "role": "D1: dispose the +0x60 shared_ptr control block when its use count reaches 0"},
                {"site": "0x5f32b73", "kind": "direct_call", "containing_fde": ["0x5f32a10", "0x5f32b7d"], "role": "D1: dispose the +0x50 shared_ptr control block when its use count reaches 0"},
                {"site": "0x5f32ce3", "kind": "direct_call", "containing_fde": ["0x5f32b80", "0x5f32cfd"], "role": "D0: dispose the +0x60 shared_ptr control block when its use count reaches 0"},
                {"site": "0x5f32cf3", "kind": "direct_call", "containing_fde": ["0x5f32b80", "0x5f32cfd"], "role": "D0: dispose the +0x50 shared_ptr control block when its use count reaches 0"},
            ],
            "0x63f0d80": [
                {"site": "0x5f32a49", "kind": "direct_call", "containing_fde": ["0x5f32a10", "0x5f32b7d"], "role": "D1: operator delete for the cached-key heap buffer (PLT _ZdlPvm)"},
                {"site": "0x5f32bb9", "kind": "direct_call", "containing_fde": ["0x5f32b80", "0x5f32cfd"], "role": "D0: operator delete for the cached-key heap buffer (PLT _ZdlPvm)"},
                {"site": "0x5f32c6b", "kind": "tail_jump", "containing_fde": ["0x5f32b80", "0x5f32cfd"], "role": "D0: operator delete(this, 0xc8) (PLT _ZdlPvm)"},
            ],
        },
        "generic_helper_counts": {
            "0x61bd0e0": "223 direct calls + 32 tail jumps binary-wide (not enumerated; see census.py note)",
            "0x5d35070": "654 direct calls + 36 tail jumps binary-wide (not enumerated; see census.py note)",
            "0x61bd0c0": "103 direct call sites binary-wide (the Cleanable ctor, called by the two iterator ctors in #3674; not a window here)",
        },
        "vendor_attribution": {
            "0x5f32900": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator26MaxCoveringTombstoneSeqnumERKNS_5SliceE",
            "0x5f316d0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator23SeekToCoveringTombstoneERKNS_5SliceE",
            "0x5f31980": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator30SeekForPrevToCoveringTombstoneERKNS_5SliceE",
            "0x5f31c80": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator29ScanForwardToVisibleTombstoneEv",
            "0x5f31eb0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator14SeekToTopFirstEv",
            "0x5f320a0/0x5f324f0": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical copies of 2 build functions, e.g. _ZN7rocksdb32FragmentedRangeTombstoneIterator11SeekForPrevERKNS_5SliceE",
            "0x5f320f0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator30ScanBackwardToVisibleTombstoneEv",
            "0x5f32310": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator13SeekToTopLastEv",
            "0x5f32540": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator7TopNextEv",
            "0x5f32720": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator7TopPrevEv",
            "0x5f32a10": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIteratorD1Ev",
            "0x5f32b80": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIteratorD0Ev",
            "0x5f2ee70": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator10SeekToLastEv",
            "0x5f2eea0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator4NextEv",
            "0x5f2eef0": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb32FragmentedRangeTombstoneIterator4PrevEv",
            "0x5eba980": "librocksdb-sys 0.11.0+8.1.1 _ZNK7rocksdb32FragmentedRangeTombstoneIterator3keyEv",
            "0x5df7ce0": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical bodies, e.g. _ZN7rocksdb20InternalIteratorBaseINS_5SliceEE16NextAndGetResultEPNS_13IterateResultE",
            "0x5df7800": "librocksdb-sys 0.11.0+8.1.1: one of 2 identical copies of 7 build functions, e.g. _ZN7rocksdb10Checkpoint16CreateCheckpointERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEmPm",
            "0x61bdc40": "librocksdb-sys 0.11.0+8.1.1 _ZNK7rocksdb12_GLOBAL__N_122BytewiseComparatorImpl23CompareWithoutTimestampERKNS_5SliceEbS4_b",
            "0x61bdc90": "librocksdb-sys 0.11.0+8.1.1 _ZNK7rocksdb12_GLOBAL__N_129ReverseBytewiseComparatorImpl23CompareWithoutTimestampERKNS_5SliceEbS4_b",
            "0x5eaa060": "librocksdb-sys 0.11.0+8.1.1 _ZN7rocksdb17AppendInternalKeyEPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS_17ParsedInternalKeyE",
            "0x5d44c70": "librocksdb-sys 0.11.0+8.1.1 _ZNK7rocksdb25FSRandomAccessFileWrapper4ReadEmmRKNS_9IOOptionsEPNS_5SliceEPcPNS_14IODebugContextE (a neighbouring GOT slot, not comparator dispatch)",
            "0x5f2e8f0/0x5f2e8d0/0x5eba910/0x5df7650/0x5f2e7b0/0x5df7670/0x5df7680/0x5df7690/0x5d485b0/0x5f2e790/0x5f2e7a0/0x5df76d0/0x5df76e0/0x5df7640": "no catalogue row; identified by shape from the vtable slot, the return value and the shared-base comparison with MemTableIterator",
        },
        "unknowns": [
            "the exact C++ names for vtable slots [11] (key-minus-8), [14]-[17], [18], [19], [20], [21]-[23]: the behaviours are pinned (return 0/1, void no-op, Status builder, user-key accessor) but the declared names are not established",
            "the IterateResult struct layout beyond key Slice at +0x0/+0x8 and a u16 0 at +0x10 (NextAndGetResult)",
            "the identity of P's +0x20 subobject Q and of the thunk 0x5d48410's target Q->vtable[0x10]; how icmp+0x8 holds a Comparator* when InternalKeyComparator is 8 bytes; the exact C++ name of comparator slot 0xc8 (CompareTimestamp is the best-supported reading)",
            "the semantic identity of the key-array entries at list+0x30 (per-seqnum 16-byte key slices compared against the upper bound via slot 0xc8; end keys vs timestamp keys is open)",
            "the list+0x10 and list+0x28 fields (never read by this family)",
            "the second shared_ptr slot at +0x48/+0x50: null from both ctors, released by the dtor when non-null — what sets it is open (no setter or copy-assignment in this family)",
            "the +0x78 arg6 threshold's source-level identity (the callers that pass it: the host 0x5f0a9c0 in #3674 and the compaction/table paths that build the iterator)",
            "the 0x5f0d050 and 0x5f0d740 MemTable lookup/Get FDEs that call MaxCoveringTombstoneSeqnum have no catalogue row; their identities are given only by the calls they make (NewRangeTombstoneIterator / GetFromTable + Hash)",
            "the 0x617xxxx MergingIterator / range-del aggregation FDEs that call TopNext/TopPrev have no catalogue row; their identities are given only by the calls they make (MergingIterator heap ops, TruncatedRangeDelIterator Valid/Seek/SeekForPrev, _Rb_tree erase)",
            "the cache struct layout behind ctor B's +0x8/+0x20 bounds (the cache embeds a list-like struct with different offsets from the raw list; the embedded list's own fields are #3674's contract)",
            "the landing-pad / LSDA tables of the seek/scan/dtors are not decoded",
        ],
    }


if __name__ == "__main__":
    sys.exit(main())
