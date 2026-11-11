"""Generate the semantic records for this packet.

Run from the repository root:
    python3 research/work-items/RE-001-fragmented-tombstone-construction-115/gen_records.py

Writes records.json, callers.tsv and relocations.txt. The census
section is produced by importing census.py and running its scan, so
records.json always agrees with the census script.
"""

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
import census as census_mod

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BIN = os.path.join(ROOT, "work/hl-node-115.bin")
RELA_OFF, RELA_SIZE = 0x6BE8, 0x163CC8

# (target, site, kind, fde_start, fde_end, role)
CALLER_ROWS = [
    ("0x5f31380", "0x5f0aa15", "direct_call", "0x5f0a9c0", "0x5f0b04c",
     "MemTable::NewRangeTombstoneIteratorInternal flag path: ctor A with "
     "(list = owner+0xce0, comparator = owner+8, seq = rdx, slice = arg2+0x58, arg6 = 0)"),
    ("0x5f31380", "0x5f33a3b", "direct_call", "0x5f33950", "0x5f33b36",
     "SplitBySnapshot: ctor A with (list = this+0x68, comparator = this+0x38, "
     "seq = snapshot, slice = this+0x80, arg6 = prev_snapshot+1)"),
    ("0x5f31470", "0x5f293b3", "direct_call", "0x5f29140", "0x5f294ce",
     "CompactionRangeDelAggregator::NewIterator: ctor List with (shared_ptr = "
     "the fresh make_shared<List> at rsp+0x30, comparator = *(aggregator+8), "
     "seq = -1, slice = null, arg6 = 0)"),
    ("0x5f31470", "0x60fcf4b", "direct_call", "0x60fcee0", "0x60fcf6a",
     "BlockBasedTable::NewRangeTombstoneIterator: ctor List with (shared_ptr = "
     "table subobject+0x208, comparator = *(table+8)+0x110, seq = snapshot or -1, "
     "slice = ReadOptions+0x58, arg6 = 0)"),
    ("0x5f315a0", "0x5f0ab05", "direct_call", "0x5f0a9c0", "0x5f0b04c",
     "MemTable::NewRangeTombstoneIteratorInternal cache path: ctor Cache with "
     "(shared_ptr = the slot's shared_ptr copy, comparator = owner+8, seq = rdx, "
     "slice = arg2+0x58, arg6 = 0)"),
    ("0x5f33950", "0x5f26a13", "direct_call", "0x5f269e0", "0x5f26ed5",
     "TruncatedRangeDelIterator::SplitBySnapshot: splits the owned iterator; "
     "the returned map is re-wrapped entry by entry"),
    ("0x5f31250", "0x5f33a03", "direct_call", "0x5f33950", "0x5f33b36",
     "SplitBySnapshot's probe gate: (list = this+0x68, lower = prev+1, snapshot)"),
    ("0x5f33670", "0x5f33ab7", "direct_call", "0x5f33950", "0x5f33b36",
     "SplitBySnapshot's map insert: _Rb_tree::_M_emplace_hint_unique"),
    ("0x5f269e0", "0x5f28815", "direct_call", "0x5f28710", "0x5f28dac",
     "CompactionRangeDelAggregator::AddTombstones: splits the truncated "
     "iterator and moves the entries into the aggregator's map"),
    ("0x5f32900", "0x5f0d1e5", "direct_call", "0x5f0d050", "0x5f0d704",
     "MemTable lookup path (no catalogue row; calls NewRangeTombstoneIterator "
     "0x5f0b050 and MaxCoveringTombstoneSeqnum)"),
    ("0x5f32900", "0x5f0e09c", "direct_call", "0x5f0d740", "0x5f0e2c7",
     "MemTable Get path (no catalogue row; calls GetFromTable 0x5f0ce10 and "
     "MaxCoveringTombstoneSeqnum)"),
    ("0x5f32900", "0x5f3d5aa", "direct_call", "0x5f3d4f0", "0x5f3d64a",
     "TableCache::UpdateRangeTombstoneSeqnums: the max covering seqnum for the key"),
    ("0x5f32900", "0x5f4055e", "direct_call", "0x5f40070", "0x5f40a8d",
     "TableCache::Get: the max covering seqnum for the key"),
    ("0x5f29140", "0x5e1561d", "direct_call", "0x5e15310", "0x5e183ab",
     "Compaction iterator-construction site (unnamed stripped FDE): NewIterator "
     "with (out = stack slot, aggregator = *(struct+0x88), slices = two stack Slices)"),
    ("0x5f29140", "0x5e1cd48", "direct_call", "0x5e1b9c0", "0x5e20481",
     "Compaction iterator-construction site (unnamed stripped FDE): NewIterator "
     "with (out = stack slot, aggregator = r15, slices = null, null), after a "
     "0x5e2f930 gate call and flag tests"),
    ("0x5f29140", "0x5ed0c70", "direct_call", "0x5ed01f0", "0x5ed2238",
     "Compaction iterator-construction site (unnamed stripped FDE): NewIterator "
     "with (out = stack slot, aggregator = stack slot, slices = null, null), "
     "after a 0x5e2f930 gate call and flag tests"),
    ("0x5f37410", "0x5f0a536", "direct_call", "0x5f0a3d0", "0x5f0a909",
     "List ctor from a MemTableIterator temp: operator new(0xe8) + ctor with "
     "(source = stack temp, comparator = rbx+0x8, arg4 = 0, scratch = stack temp)"),
    ("0x5f37410", "0x5f0ac12", "direct_call", "0x5f0a9c0", "0x5f0b04c",
     "List ctor from a MemTableIterator temp in the host: arg4 = 0, scratch = "
     "a 0x20-byte stack scratch (per #3674)"),
    ("0x5f37410", "0x5f29367", "direct_call", "0x5f29140", "0x5f294ce",
     "List ctor from a TruncatedRangeDelMergingIter temp in NewIterator: "
     "make_shared (0xf8), arg4 = 1, scratch = *(aggregator+0x88)"),
    ("0x5f37410", "0x6109f07", "direct_call", "0x6109c40", "0x6109fca",
     "List ctor from a stack temp: make_shared (0xf8, control-block vtable "
     "0x64cc9a8+0x10), arg4 = 0, scratch = r13"),
]

# (target, site, kind, fde_start, fde_end, role): generic-helper sites
# used by this packet's windows (not census targets).
INTERNAL_ROWS = [
    ("0x61bd0c0", "0x5f31498", "direct_call", "0x5f31470", "0x5f3159e",
     "ctor List: Cleanable ctor at this+0x08"),
    ("0x61bd0c0", "0x5f291dd", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: Cleanable ctor at the 0x118 temp+0x08"),
    ("0x63f0dd0", "0x5f33a1a", "direct_call", "0x5f33950", "0x5f33b36",
     "SplitBySnapshot: operator new(0xc8) for the split iterator"),
    ("0x63f0dd0", "0x5f291c4", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: operator new(0x118) for the TruncatedRangeDelMergingIter temp"),
    ("0x63f0dd0", "0x5f29328", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: operator new(0xf8) for the make_shared<List>"),
    ("0x63f0dd0", "0x5f29390", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: operator new(0xc8) for the iterator"),
    ("0x63f0dd0", "0x60fcf23", "direct_call", "0x60fcee0", "0x60fcf6a",
     "BlockBasedTable: operator new(0xc8) for the iterator"),
    ("0x63f0dd0", "0x5f26a6d", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator new(0x48) for the wrapper"),
    ("0x63f0dd0", "0x5f26bcd", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator new(0x30) for the map node"),
    ("0x63f0dd0", "0x5f2ec2a", "direct_call", "0x5f2eb90", "0x5f2ecc2",
     "Once-init: operator new(0x28) for the index tree node"),
    ("0x63f0dd0", "0x5f33693", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: operator new(0x30) for the map node"),
    ("0x63f13d0", "0x5f312c1", "direct_call", "0x5f31250", "0x5f3137e",
     "Probe: pthread_once(list+0x48, __once_proxy)"),
    ("0x63f0e90", "0x5f2ec40", "direct_call", "0x5f2eb90", "0x5f2ecc2",
     "Once-init: _Rb_tree_insert_and_rebalance for the new index node"),
    ("0x63f0e90", "0x5f26d26", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: _Rb_tree_insert_and_rebalance for the outer map"),
    ("0x63f0e90", "0x5f337b1", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: _Rb_tree_insert_and_rebalance for the new node"),
    ("0x63f0ea0", "0x5f291b2", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: _Rb_tree_increment over the aggregator map"),
    ("0x63f0ea0", "0x5f26b64", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: _Rb_tree_increment over the inner map"),
    ("0x63f0ea0", "0x5f26d53", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: _Rb_tree_increment over the outer map"),
    ("0x63f0ea0", "0x5f33826", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: _Rb_tree_increment during the hint walk"),
    ("0x63f0df0", "0x5f2ec89", "direct_call", "0x5f2eb90", "0x5f2ecc2",
     "Once-init: _Rb_tree_decrement during the lower-bound search"),
    ("0x63f0df0", "0x5f26c22", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: _Rb_tree_decrement during the hint walk"),
    ("0x63f0df0", "0x5f26daf", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: _Rb_tree_decrement during the hint walk"),
    ("0x63f0df0", "0x5f336e0", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: _Rb_tree_decrement during the hint walk"),
    ("0x63f0df0", "0x5f33885", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: _Rb_tree_decrement during the hint walk"),
    ("0x63f0d80", "0x5f26b3b", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for a freed fragment node"),
    ("0x63f0d80", "0x5f26b5c", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for the 0x48 wrapper"),
    ("0x63f0d80", "0x5f26bac", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for a freed map node"),
    ("0x63f0d80", "0x5f26cab", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for a freed fragment node"),
    ("0x63f0d80", "0x5f26cd2", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for the 0x48 wrapper"),
    ("0x63f0d80", "0x5f26cdf", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: operator delete for the 0x30 map node"),
    ("0x63f0d80", "0x5f33769", "direct_call", "0x5f33670", "0x5f338fa",
     "Map emplace: operator delete for a freed node (duplicate key path)"),
    ("0x5d35070", "0x5f29477", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: the shared_ptr dispose helper when the count reaches 0"),
    ("0x5f37410", "0x5f29367", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: the List ctor building the make_shared<List>"),
    ("0x5f25960", "0x5f26a9a", "direct_call", "0x5f269e0", "0x5f26ed5",
     "Truncated split: TruncatedRangeDelIterator ctor for the wrapper"),
    ("0x5f26100", "0x5f2919e", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: ForwardRangeDelIterator::Invalidate on a fragment"),
    ("0x5f261d0", "0x5f291aa", "direct_call", "0x5f29140", "0x5f294ce",
     "NewIterator: ForwardRangeDelIterator::Invalidate on a fragment"),
]


def rel_slots(data):
    out = {}
    for k in range(RELA_SIZE // 24):
        ro, info, add = struct.unpack_from("<QQq", data, RELA_OFF + k * 24)
        if (info & 0xFFFFFFFF) == 8:
            out[ro] = add
    return out


def build():
    data = open(BIN, "rb").read()
    calls, tails, hits, slots, installs = census_mod.scan(BIN)
    census = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in calls[t]],
            "tail_jumps": [hex(v) for v in tails[t]],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
    callers = {}
    for tgt, site, kind, fs, fe, role in CALLER_ROWS:
        callers.setdefault(tgt, []).append({
            "site": site, "kind": kind,
            "containing_fde": [fs, fe], "role": role,
        })
    internal = {}
    for tgt, site, kind, fs, fe, role in INTERNAL_ROWS:
        internal.setdefault(tgt, []).append({
            "site": site, "kind": kind,
            "containing_fde": [fs, fe], "role": role,
        })
    rel = rel_slots(data)
    records = {
        "task": "RE-001",
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "provenance_path": "provenance/artifacts.json",
        "constructors": {
            "ctor_a": {
                "address": "0x5f31380",
                "symbol": "_ZN7rocksdb32FragmentedRangeTombstoneIteratorC1EPNS_28FragmentedRangeTombstoneListERKNS_21InternalKeyComparatorEmPKNS_5SliceEm",
                "name": "rocksdb::FragmentedRangeTombstoneIterator::FragmentedRangeTombstoneIterator(FragmentedRangeTombstoneList*, const InternalKeyComparator&, unsigned long, const Slice*, unsigned long)",
                "arguments": ["rdi = this (0xc8)", "rsi = list", "rdx = comparator",
                              "rcx = seq (arg4)", "r8 = slice (arg5)", "r9 = arg6"],
                "fields": {
                    "+0x00": "vtable 0x64ccae0+0x10",
                    "+0x08": "Cleanable subobject (ctor 0x61bd0c0)",
                    "+0x28": "comparator+0x8", "+0x30": "comparator+0x8",
                    "+0x38": "comparator", "+0x40": "comparator+0x8",
                    "+0x48..+0x68": "0 (both shared_ptr holders null)",
                    "+0x68": "list",
                    "+0x70": "seq", "+0x78": "arg6", "+0x80": "slice",
                    "+0x88": "list+0x8", "+0x90": "list+0x18",
                    "+0x98": "list+0x8 (shadow)", "+0xa0": "list+0x18 (shadow)",
                    "+0xa8": "&this+0xb8 (inline key cache)", "+0xb0": "0",
                    "+0xb8": "0 (byte)",
                },
                "callers": ["0x5f0aa15 (host flag path)", "0x5f33a3b (SplitBySnapshot)"],
                "vendor": "239 bytes, 232 equal, relocation-qualified",
            },
            "ctor_list": {
                "address": "0x5f31470",
                "symbol": "_ZN7rocksdb32FragmentedRangeTombstoneIteratorC1ERKSt10shared_ptrINS_28FragmentedRangeTombstoneListEERKNS_21InternalKeyComparatorEmPKNS_5SliceEm",
                "name": "rocksdb::FragmentedRangeTombstoneIterator::FragmentedRangeTombstoneIterator(const shared_ptr<FragmentedRangeTombstoneList>&, const InternalKeyComparator&, unsigned long, const Slice*, unsigned long)",
                "arguments": ["rdi = this (0xc8)", "rsi = &shared_ptr<List>",
                              "rdx = comparator", "rcx = seq (arg4)",
                              "r8 = slice (arg5)", "r9 = arg6"],
                "fields": {
                    "+0x00": "vtable 0x64ccae0+0x10",
                    "+0x08": "Cleanable subobject (ctor 0x61bd0c0)",
                    "+0x28": "comparator+0x8", "+0x30": "comparator+0x8",
                    "+0x38": "comparator", "+0x40": "comparator+0x8",
                    "+0x48": "shared_ptr<List> ptr (copied from the caller)",
                    "+0x50": "shared_ptr<List> ctrl (use count bumped: lock addl "
                            "iff the global byte at 0x64ed290 is 0, else plain addl)",
                    "+0x58..+0x68": "0 (the Cache holder is null)",
                    "+0x68": "list ptr (the shared_ptr's ptr)",
                    "+0x70": "seq", "+0x78": "arg6", "+0x80": "slice",
                    "+0x88": "list+0x8", "+0x90": "list+0x18",
                    "+0x98": "list+0x8 (shadow)", "+0xa0": "list+0x18 (shadow)",
                    "+0xa8": "&this+0xb8 (inline key cache)", "+0xb0": "0",
                    "+0xb8": "0 (byte)",
                },
                "callers": ["0x5f293b3 (CompactionRangeDelAggregator::NewIterator)",
                            "0x60fcf4b (BlockBasedTable::NewRangeTombstoneIterator)"],
                "vendor": "302 bytes, 292 equal, relocation-qualified",
                "resolves": "#3900's open unknown 'what sets the second shared_ptr "
                           "at +0x48/+0x50': this constructor copies the caller's "
                           "shared_ptr<List> there (with the use-count bump).",
            },
            "ctor_cache": {
                "address": "0x5f315a0",
                "symbol": "_ZN7rocksdb32FragmentedRangeTombstoneIteratorC1ERKSt10shared_ptrINS_33FragmentedRangeTombstoneListCacheEERKNS_21InternalKeyComparatorEmPKNS_5SliceEm",
                "name": "rocksdb::FragmentedRangeTombstoneIterator::FragmentedRangeTombstoneIterator(const shared_ptr<FragmentedRangeTombstoneListCache>&, const InternalKeyComparator&, unsigned long, const Slice*, unsigned long)",
                "arguments": ["rdi = this (0xc8)", "rsi = &shared_ptr<Cache>",
                              "rdx = comparator", "rcx = seq (arg4)",
                              "r8 = slice (arg5)", "r9 = arg6"],
                "fields": {
                    "+0x00": "vtable 0x64ccae0+0x10",
                    "+0x08": "Cleanable subobject (ctor 0x61bd0c0)",
                    "+0x28": "comparator+0x8", "+0x30": "comparator+0x8",
                    "+0x38": "comparator", "+0x40": "comparator+0x8",
                    "+0x48..+0x58": "0 (the List holder is null)",
                    "+0x58": "shared_ptr<Cache> ptr (copied from the caller)",
                    "+0x60": "shared_ptr<Cache> ctrl (use count bumped, same rule)",
                    "+0x68": "cache+0x28 (the cache's embedded List*)",
                    "+0x70": "seq", "+0x78": "arg6", "+0x80": "slice",
                    "+0x88": "cache+0x8", "+0x90": "cache+0x20",
                    "+0x98": "cache+0x8 (shadow)", "+0xa0": "cache+0x20 (shadow)",
                    "+0xa8": "&this+0xb8 (inline key cache)", "+0xb0": "0",
                    "+0xb8": "0 (byte)",
                },
                "callers": ["0x5f0ab05 (host cache path)"],
                "vendor": "302 bytes, 292 equal, relocation-qualified",
                "note": "pinned by #3674 (records.json ctor_b); not re-shipped as "
                        "an excerpt here.",
            },
        },
        "arg6": {
            "identity": "the lower snapshot bound: a tombstone is visible "
                        "when its seqnum >= arg6 (and <= the read seq at +0x70), "
                        "per #3900. arg6 is the previous snapshot + 1 in a split, "
                        "and 0 (no lower bound) everywhere else.",
            "per_caller": {
                "host 0x5f0a9c0 flag path (ctor A)": "0",
                "host 0x5f0a9c0 cache path (ctor Cache)": "0",
                "CompactionRangeDelAggregator::NewIterator 0x5f29140 (ctor List)": "0",
                "BlockBasedTable::NewRangeTombstoneIterator 0x60fcee0 (ctor List)": "0",
                "SplitBySnapshot 0x5f33950 (ctor A)": "prev_snapshot+1 (0 for the "
                "first snapshot; r14 starts 0 and becomes snapshot+1 each round)",
            },
            "resolves": "#3900's open unknown 'the +0x78 arg6 threshold's "
                        "source-level identity'.",
        },
        "split_by_snapshot": {
            "address": "0x5f33950",
            "symbol": "_ZN7rocksdb32FragmentedRangeTombstoneIterator15SplitBySnapshotERKSt6vectorImSaImEE",
            "name": "rocksdb::FragmentedRangeTombstoneIterator::SplitBySnapshot(const std::vector<unsigned long>&)",
            "arguments": ["rdi = sret (0x38-byte return struct: +0x00 open, "
                          "std::map at +0x08)", "rsi = this (iterator)",
                          "rdx = &snapshots vector"],
            "return_struct": "0x38 bytes: +0x00 is never written by this "
                             "function nor read by its consumers (see unknowns); "
                             "+0x08..+0x38 is a std::map<SequenceNumber, "
                             "unique_ptr<FragmentedRangeTombstoneIterator>> "
                             "(header: color +0x08 = 0, parent +0x10 = 0, "
                             "left +0x18 = right +0x20 = &header, count +0x28 = 0)",
            "algorithm": "for each snapshot ascending, with lower starting at 0 "
                         "and then prev+1: probe(list, lower, snapshot); when the "
                         "probe is true, operator new(0xc8) + ctor A with (list = "
                         "this+0x68, comparator = this+0x38, seq = snapshot, slice "
                         "= this+0x80, arg6 = lower), then _Rb_tree::_M_emplace_hint_unique "
                         "(0x5f33670) inserts (snapshot, unique_ptr<iterator>) into "
                         "the map (first wins: a duplicate key keeps the first "
                         "iterator and the new one is destroyed via vtable slot 1); "
                         "lower becomes snapshot+1 either way.",
            "vendor": "486 bytes, 456 equal, relocation-qualified",
            "resolves": "#3674's open unknown 'the second ctor-A consumer in FDE "
                        "0x5f33950 (exact use open)'.",
        },
        "probe": {
            "address": "0x5f31250",
            "name": "list seqnum probe (no catalogue row; pinned from the binary)",
            "arguments": ["rdi = list", "rsi = lower", "rdx = snapshot"],
            "algorithm": "pthread_once(list+0x48, __once_proxy) with the "
                         "libstdc++ TLS handoff (__once_callable = &list cell, "
                         "__once_call = 0x5f2eb90) builds the list's sorted seqnum "
                         "index on first use; then lower_bound(lower) over that "
                         "index (nodes: +0x10 left, +0x18 right, +0x20 key; "
                         "sentinel &list+0x58, root *(list+0x60)); returns True "
                         "iff a key exists and it is >= snapshot, i.e. iff NO "
                         "indexed seqnum lies in [lower, snapshot).",
            "callers": ["0x5f33a03 (SplitBySnapshot only)"],
        },
        "once_init": {
            "address": "0x5f2eb90",
            "name": "list seqnum index initializer (no catalogue row; pinned "
                    "from the binary; invoked only via pthread_once)",
            "arguments": ["none (the list pointer arrives via the "
                          "__once_callable TLS slot)"],
            "algorithm": "reads the list's u64 seq array at list+0x18..+0x20; "
                         "for each seqnum, lower_bound-searches the index tree "
                         "at list+0x58 (root *(list+0x60)); inserts a fresh "
                         "0x28-byte node (key at +0x20) via "
                         "_Rb_tree_insert_and_rebalance when the key is absent "
                         "(dedup) and increments the count at list+0x78.",
            "invocation": "no direct calls; the address is taken by the probe's "
                          "lea at 0x5f312ac and reached only through pthread_once "
                          "+ __once_proxy.",
        },
        "map_emplace": {
            "address": "0x5f33670",
            "symbol": "_ZNSt8_Rb_treeImSt4pairIKmSt10unique_ptrIN7rocksdb32FragmentedRangeTombstoneIteratorESt14default_deleteIS4_EEESt10_Select1stIS8_ESt4lessImESaIS8_EE22_M_emplace_hint_uniqueIJRmS7_EEESt17_Rb_tree_iteratorIS8_ESt23_Rb_tree_const_iteratorIS8_EDpOT_",
            "name": "std::_Rb_tree<unsigned long, pair<const unsigned long, unique_ptr<FragmentedRangeTombstoneIterator>>>::_M_emplace_hint_unique",
            "arguments": ["rdi = the return struct (tree header at +0x08)",
                          "rsi = hint iterator", "rdx = &snapshot key",
                          "rcx = &unique_ptr<iterator> value"],
            "algorithm": "allocates a 0x30-byte node (key at +0x20, unique_ptr "
                         "at +0x28), moves the unique_ptr into it, finds the "
                         "insert position (re-searching from the root when the "
                         "hint is the end), inserts and rebalances; on a "
                         "duplicate key the new node is freed and the existing "
                         "iterator is returned.",
            "vendor": "650 bytes, 632 equal, relocation-qualified",
        },
        "truncated_split": {
            "address": "0x5f269e0",
            "symbol": "_ZN7rocksdb25TruncatedRangeDelIterator15SplitBySnapshotERKSt6vectorImSaImEE",
            "name": "rocksdb::TruncatedRangeDelIterator::SplitBySnapshot(const std::vector<unsigned long>&)",
            "arguments": ["rdi = sret (same 0x38-byte return struct)",
                          "rsi = this (TruncatedRangeDelIterator)",
                          "rdx = &snapshots vector"],
            "algorithm": "calls the owned iterator's SplitBySnapshot "
                         "(this = *(this+0x00), the owned FragmentedRangeTombstoneIterator*) "
                         "into a stack temp map at rsp+0x40; then for each "
                         "(snapshot, unique_ptr<iterator>) in that map ascending, "
                         "operator new(0x48) + TruncatedRangeDelIterator ctor "
                         "0x5f25960 (by contract) wrapping the moved-out iterator, "
                         "and inserts (snapshot, unique_ptr<truncated>) into the "
                         "outer return map; the inner map's nodes are freed as "
                         "they are consumed.",
            "vendor": "1269 bytes, 1205 equal, relocation-qualified",
            "callers": ["0x5f28815 (CompactionRangeDelAggregator::AddTombstones)"],
        },
        "compaction_new_iterator": {
            "address": "0x5f29140",
            "symbol": "_ZN7rocksdb28CompactionRangeDelAggregator11NewIteratorEPKNS_5SliceES3_",
            "name": "rocksdb::CompactionRangeDelAggregator::NewIterator(const Slice*, const Slice*)",
            "arguments": ["rdi = out (InternalIterator**; also returned)",
                          "rsi = this (aggregator)", "rdx = Slice* (arg3)",
                          "rcx = Slice* (arg4)"],
            "algorithm": "finalizes the aggregator's fragment map (each entry: "
                         "ForwardRangeDelIterator::Invalidate via 0x5f26100/0x5f261d0 "
                         "when its +0x30 != +0x38); builds a 0x118-byte "
                         "TruncatedRangeDelMergingIter temp (vtable 0x64cc8e8) "
                         "field-wise; make_shared<FragmentedRangeTombstoneList> "
                         "(0xf8 = 0x10 control block + 0xe8 List) via the List "
                         "ctor 0x5f37410(cache = buffer+0x10, list = &temp, "
                         "comparator = *(aggregator+8), arg4 = 1, scratch = "
                         "*(aggregator+0x88)); destroys the temp via vtable slot 1; "
                         "operator new(0xc8) + ctor List with (shared_ptr = "
                         "{buffer+0x10, buffer}, comparator = *(aggregator+8), "
                         "seq = -1, slice = null, arg6 = 0); stores the iterator "
                         "at *out; releases the claim-time List reference with "
                         "the packed 0x100000001 fast dispose / selector decrement.",
            "vendor": "910 bytes, 831 equal, relocation-qualified",
            "callers": ["0x5e1561d (FDE 0x5e15310..0x5e183ab, compaction "
                        "iterator-construction site: aggregator = *(struct+0x88), "
                        "slices = two stack Slices)",
                        "0x5e1cd48 (FDE 0x5e1b9c0..0x5e20481, compaction "
                        "iterator-construction site: aggregator = r15, slices = null)",
                        "0x5ed0c70 (FDE 0x5ed01f0..0x5ed2238, compaction "
                        "iterator-construction site: aggregator = stack slot, "
                        "slices = null)"],
        },
        "block_table_new_iterator": {
            "address": "0x60fcee0",
            "symbol": "_ZN7rocksdb15BlockBasedTable25NewRangeTombstoneIteratorERKNS_11ReadOptionsE",
            "name": "rocksdb::BlockBasedTable::NewRangeTombstoneIterator(const ReadOptions&)",
            "arguments": ["rdi = this (BlockBasedTable)", "rsi = &ReadOptions"],
            "algorithm": "rbx = *(table_subobject+0x208) (the cached shared_ptr<List>'s "
                         "ptr); null -> return null; snapshot = ReadOptions vtable "
                         "slot 0 (or -1 when absent); operator new(0xc8) + ctor List "
                         "with (shared_ptr = table subobject+0x208, comparator = "
                         "*(table_subobject+0x110), seq = snapshot, slice = "
                         "ReadOptions+0x58, arg6 = 0).",
            "vendor": "138 bytes, 127 equal, relocation-qualified",
        },
        "list_ctor": {
            "address": "0x5f37410",
            "name": "FragmentedRangeTombstoneList constructor (by shape; #3674's "
                    "'cache ctor')",
            "arguments": ["rdi = list (0xe8)", "rsi = &source iterator",
                          "rdx = comparator", "ecx = arg4", "r8 = scratch"],
            "evidence": "the make_shared<List> control block in NewIterator "
                        "(vtable 0x64cc9b8, typeinfo "
                        "std::_Sp_counted_ptr_inplace<FragmentedRangeTombstoneList>) "
                        "proves the 0xe8 object built by 0x5f37410 is a "
                        "FragmentedRangeTombstoneList; see corrections.",
            "callers": ["0x5f0a536 (FDE 0x5f0a3d0..0x5f0a909: operator new(0xe8) "
                        "+ ctor from a MemTableIterator temp, arg4 = 0, scratch = "
                        "stack temp)",
                        "0x5f0ac12 (host 0x5f0a9c0..0x5f0b04c: from a MemTableIterator "
                        "temp, arg4 = 0, scratch = 0x20-byte stack scratch, per #3674)",
                        "0x5f29367 (NewIterator 0x5f29140..0x5f294ce: make_shared, "
                        "from a TruncatedRangeDelMergingIter temp, arg4 = 1, scratch "
                        "= *(aggregator+0x88))",
                        "0x6109f07 (FDE 0x6109c40..0x6109fca: make_shared, from a "
                        "stack temp, arg4 = 0, scratch = r13)"],
        },
        "vtable_installs": {
            "vtable": "0x64ccae0+0x10 (slot 0 = 0x64ccaf0)",
            "lea_sites": ["0x5f313b2 (ctor A)", "0x5f314a7 (ctor List)",
                          "0x5f315d4 (ctor Cache)", "0x5f32a1d (D1: vtable reset)",
                          "0x5f32b8d (D0: vtable reset)"],
            "conclusion": "the only vtable installers are the three constructors; "
                         "no copy/move constructor exists in the binary, so the "
                         "second shared_ptr (+0x48/+0x50) can only be set by ctor "
                         "0x5f31470.",
        },
        "census": census,
        "callers": callers,
        "packet_internal_sites": internal,
        "windows": [
            "0x5f31470 (ctor List, 302 B)", "0x5f33950 (SplitBySnapshot, 486 B)",
            "0x5f31250 (probe, 334 B)", "0x5f2eb90 (once-init, 402 B)",
            "0x5f29140 (CompactionRangeDelAggregator::NewIterator, 910 B)",
            "0x60fcee0 (BlockBasedTable::NewRangeTombstoneIterator, 138 B)",
            "0x5f269e0 (TruncatedRangeDelIterator::SplitBySnapshot, 1269 B)",
            "0x5f33670 (map emplace, 650 B)",
        ],
        "vendor_attribution": {
            "0x5f31380": "239 bytes, 232 equal, relocation-qualified",
            "0x5f31470": "302 bytes, 292 equal, relocation-qualified",
            "0x5f315a0": "302 bytes, 292 equal, relocation-qualified",
            "0x5f33950": "486 bytes, 456 equal, relocation-qualified",
            "0x5f33670": "650 bytes, 632 equal, relocation-qualified",
            "0x5f29140": "910 bytes, 831 equal, relocation-qualified",
            "0x60fcee0": "138 bytes, 127 equal, relocation-qualified",
            "0x5f269e0": "1269 bytes, 1205 equal, relocation-qualified",
            "0x5f32a10": "365 bytes, 337 equal, relocation-qualified",
            "0x5f32b80": "381 bytes, 350 equal, relocation-qualified",
            "0x5f31250": "no catalogue row (pinned from the binary)",
            "0x5f2eb90": "no catalogue row (pinned from the binary)",
        },
        "corrections": [
            "0x5f37410 constructs a FragmentedRangeTombstoneList (0xe8 bytes), "
            "not a 'cache': the make_shared<List> control-block typeinfo "
            "(vtable 0x64cc9b8, _Sp_counted_ptr_inplace<FragmentedRangeTombstoneList>) "
            "in CompactionRangeDelAggregator::NewIterator proves the 0xe8 object "
            "is a List. #3674's 'cache ctor' / 'cache' labels for 0x5f37410 and "
            "its 0xe8 object are superseded; the Cache is the separate struct "
            "ctor B (0x5f315a0) takes a shared_ptr to.",
            "The 0x80-byte source object consumed by 0x5f37410 in the host is a "
            "MemTableIterator temp (vtable 0x64cc638, typeinfo "
            "rocksdb::MemTableIterator, embedded KeyComparator 0x64cc600 and "
            "InternalKeyComparator 0x64c8fe8), not a FragmentedRangeTombstoneList. "
            "#3674's 'list' label for it is superseded. In NewIterator the source "
            "is a TruncatedRangeDelMergingIter temp (0x118 bytes, vtable 0x64cc8e8, "
            "typeinfo rocksdb::(anonymous)::TruncatedRangeDelMergingIter).",
            "The List struct's index fields are now pinned: +0x48 is the "
            "pthread_once_t for the seqnum index, +0x58 is the index tree header "
            "(root at +0x60), +0x78 is the index count, and +0x18/+0x20 is the "
            "u64 seq array the index is built from.",
            "#3900's layout note 'the cache shared_ptr at +0x58/+0x60 is null' for "
            "ctor A is confirmed; the same packet's 'second shared_ptr' unknown is "
            "resolved by ctor 0x5f31470 (see constructors.ctor_list.resolves).",
        ],
        "unknowns": [
            "The source-level rationale for the probe gate: the interval semantics "
            "is pinned (create the split iff no indexed seqnum lies in [lower, "
            "snapshot)), but why a split is created exactly when its snapshot "
            "range contains no fragment start is open.",
            "The +0x00 qword of the SplitBySnapshot return struct (map at +0x08): "
            "never written by either SplitBySnapshot nor read by "
            "CompactionRangeDelAggregator::AddTombstones (the caller's pre-call "
            "store to that slot holds a stale pointer no consumer reads).",
            "The List ctor 0x5f37410's arg4 (0 in the host, in FDE 0x5f0a3d0 "
            "and in FDE 0x6109c40; 1 in NewIterator) and its r8 scratch (a stack "
            "scratch in the host paths, *(aggregator+0x88) in NewIterator, r13 "
            "in FDE 0x6109c40) -- by contract from #3674.",
            "The Cache struct's full layout beyond +0x08/+0x20/+0x28.",
            "The TruncatedRangeDelIterator ctor 0x5f25960's internals (by contract; "
            "its 7 call sites are the wrapper family).",
            "The CompactionRangeDelAggregator::NewIterator caller set: three "
            "direct callers are pinned (0x5e1561d, 0x5e1cd48, 0x5ed0c70), all in "
            "unnamed stripped FDEs in the compaction area; their source-level "
            "identities are open (the binary is stripped).",
            "The TruncatedRangeDelMergingIter temp's field names beyond the vtable "
            "(its construction is field-wise in NewIterator).",
            "The landing-pad / LSDA tables of the windows.",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(HERE, "callers.tsv"), "w") as fh:
        fh.write("target\tsite\tkind\tcontaining_fde_start\tcontaining_fde_end\trole\n")
        for tgt, site, kind, fs, fe, role in CALLER_ROWS:
            fh.write("%s\t%s\t%s\t%s\t%s\t%s\n" % (tgt, site, kind, fs, fe, role))
    rel = rel_slots(data)
    lines = []
    lines.append("# R_X86_64_RELATIVE entries (type 8) and the GLOB_DAT/TLS slots "
                 "this packet relies on. Addends are the pre-relocation values; "
                 "the .data.rel.ro file bytes are zero at these slots (PIE), so "
                 "the relocation table is the authority, as in #3932.")
    for ro in (0x64CCAE8, 0x64CCAF0, 0x64CCAF8, 0x64CCB00):
        lines.append("RELATIVE slot %s -> %s (iterator vtable)" % (hex(ro), hex(rel[ro])))
    for ro in (0x64CC8E0, 0x64CC9B0):
        lines.append("RELATIVE slot %s -> %s (typeinfo pointer; name resolved "
                     "via its +0x8 RELATIVE slot, see below)"
                     % (hex(ro), hex(rel[ro])))
    lines.append("RELATIVE slot 0x64cc9e8 -> 0x970e00 = name string "
                 "'N7rocksdb32FragmentedRangeTombstoneIteratorE' (iterator typeinfo 0x64cc9e0)")
    lines.append("RELATIVE slot 0x64cc830 -> 0x970d40 = name string "
                 "'*N7rocksdb12_GLOBAL__N_128TruncatedRangeDelMergingIterE' "
                 "(TruncatedRangeDelMergingIter typeinfo 0x64cc828)")
    lines.append("RELATIVE slot 0x64cc848 -> 0x970d80 = name string "
                 "'St23_Sp_counted_ptr_inplaceIN7rocksdb28FragmentedRangeTombstoneListE"
                 "SaIvELN9__gnu_cxx12_Lock_policyE2EE' (make_shared<List> control-block "
                 "typeinfo 0x64cc840; proves the 0xe8 object built by 0x5f37410 is a "
                 "FragmentedRangeTombstoneList)")
    lines.append("RELATIVE slot 0x64ed7f0 -> %s (NewIterator type-check global)"
                 % hex(rel.get(0x64ED7F0, 0)))
    lines.append("GLOB_DAT slot 0x64ed290 (atomicity-selector pointer; type 6, sym 248)")
    lines.append("TLS slot 0x64ed818 (__once_callable; type 18, sym 358)")
    lines.append("TLS slot 0x64ed820 (__once_call; type 18, sym 359)")
    lines.append("GLOB_DAT slot 0x64ed828 (__once_proxy; type 6, sym 360)")
    lines.append("vtable-install leas to 0x64ccae0: 0x5f313b2, 0x5f314a7, 0x5f315d4, "
                 "0x5f32a1d, 0x5f32b8d (census.py)")
    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote records.json, callers.tsv, relocations.txt")
    return 0


if __name__ == "__main__":
    sys.exit(build())
