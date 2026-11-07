#!/usr/bin/env python3
"""Generate the semantic records for RE-001-iterator-vtable-tail-115.

Reads the vtable census (vtables.tsv source data in windows.txt /
tail_table.tsv, produced by census.py from the node #115 binary and its
.rela.dyn) and the dispatch-site census (callers.tsv), and emits
records.json (semantic records only -- no per-instruction mnemonic
list; instruction detail lives in excerpts/*.objdump.txt) and
vtables.tsv (the 21 InternalIterator vtables, tail slots [11],
[14]-[23]).

Usage (from the repository root):
    python3 research/work-items/RE-001-iterator-vtable-tail-115/gen_records.py

The binary must be present at work/hl-node-115.bin.
"""
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# C++ names pinned for each tail slot, with the base-class default.
# Evidence: the 78 whole-function excerpts plus the RocksDB v8.1.1
# headers (table/internal_iterator.h,
# table/block_based/block_based_table_iterator.h, db/forward_iterator.h)
# and the IteratorWrapperBase calls in table/iterator_wrapper.h.
SLOT_MAP = {
    11: {"name": "user_key", "signature": "Slice user_key() const",
         "default": "key() with 8 bytes stripped (0x5df7650)",
         "returns": "Slice"},
    14: {"name": "PrepareValue", "signature": "bool PrepareValue()",
         "default": "true (0x5df7670)", "returns": "bool"},
    15: {"name": "MayBeOutOfUpperBound",
         "signature": "bool MayBeOutOfUpperBound() const",
         "default": "true (0x5df7680)", "returns": "bool"},
    16: {"name": "UpperBoundCheckResult",
         "signature": "IterBoundCheck UpperBoundCheckResult() const",
         "default": "kUnknown (0) (0x5df7690)", "returns": "IterBoundCheck"},
    17: {"name": "SetPinnedItersMgr",
         "signature": "void SetPinnedItersMgr(PinnedIteratorsManager*)",
         "default": "no-op (0x5d485b0)", "returns": "void"},
    18: {"name": "IsKeyPinned", "signature": "bool IsKeyPinned() const",
         "default": "false (0x5df76a0)", "returns": "bool"},
    19: {"name": "IsValuePinned",
         "signature": "bool IsValuePinned() const",
         "default": "false (0x5df76b0)", "returns": "bool"},
    20: {"name": "GetProperty",
         "signature": "Status GetProperty(std::string, std::string*)",
         "default": "Status::NotSupported (code 3) (0x5df7800)",
         "returns": "Status"},
    21: {"name": "GetReadaheadState",
         "signature": "void GetReadaheadState(ReadaheadFileInfo*)",
         "default": "no-op (0x5df76d0)", "returns": "void"},
    22: {"name": "SetReadaheadState",
         "signature": "void SetReadaheadState(ReadaheadFileInfo*)",
         "default": "no-op (0x5df76e0)", "returns": "void"},
    23: {"name": "IsDeleteRangeSentinelKey",
         "signature": "bool IsDeleteRangeSentinelKey() const",
         "default": "false (0x5df7640)", "returns": "bool"},
}

# Whole-function behaviour of every distinct tail-window function.
# Keyed by address; each entry is (classes, slots, behaviour).
WINDOWS = {
    0x5D485B0: ("base default", [17], "no-op ret (SetPinnedItersMgr default)"),
    0x5DF7330: ("BlobCountingIterator", [11], "delegate to inner (+0x28) slot [11]"),
    0x5DF7350: ("BlobCountingIterator", [14], "delegate to inner (+0x28) slot [14]"),
    0x5DF7360: ("BlobCountingIterator", [15], "delegate to inner (+0x28) slot [15]"),
    0x5DF7370: ("BlobCountingIterator", [16], "delegate to inner (+0x28) slot [16]"),
    0x5DF7390: ("BlobCountingIterator", [17], "delegate to inner (+0x28) slot [17]"),
    0x5DF73B0: ("BlobCountingIterator", [18], "delegate to inner (+0x28) slot [18]"),
    0x5DF73D0: ("BlobCountingIterator", [19], "delegate to inner (+0x28) slot [19]"),
    0x5DF73F0: ("BlobCountingIterator", [23], "delegate to inner (+0x28) slot [23]"),
    0x5DF7430: ("ClippingIterator", [11], "delegate to inner (+0x28) slot [11]"),
    0x5DF74A0: ("ClippingIterator", [14], "inner PrepareValue; on false clear flag +0x48"),
    0x5DF74C0: ("ClippingIterator", [15], "return false (clipped range is in-bounds)"),
    0x5DF74D0: ("ClippingIterator", [16], "return 2 (kInbound)"),
    0x5DF74E0: ("ClippingIterator", [17], "delegate to inner (+0x28) slot [17]"),
    0x5DF7500: ("ClippingIterator", [18], "delegate to inner (+0x28) slot [18]"),
    0x5DF7520: ("ClippingIterator", [19], "delegate to inner (+0x28) slot [19]"),
    0x5DF7540: ("ClippingIterator", [23], "delegate to inner (+0x28) slot [23]"),
    0x5DF75E0: ("HistoryTrimmingIterator", [18], "delegate to inner (+0x28) slot [18]"),
    0x5DF7600: ("HistoryTrimmingIterator", [19], "delegate to inner (+0x28) slot [19]"),
    0x5DF7620: ("HistoryTrimmingIterator", [23], "delegate to inner (+0x28) slot [23]"),
    0x5DF7640: ("base default", [23], "return false"),
    0x5DF7650: ("base default", [11], "key() then Slice(data, len-8)"),
    0x5DF7670: ("base default", [14], "return true"),
    0x5DF7680: ("base default", [15], "return true"),
    0x5DF7690: ("base default", [16], "return 0 (kUnknown)"),
    0x5DF76A0: ("base default", [18], "return false"),
    0x5DF76B0: ("base default", [19], "return false"),
    0x5DF76D0: ("base default", [21], "no-op ret"),
    0x5DF76E0: ("base default", [22], "no-op ret"),
    0x5DF7800: ("base default", [20], "Status code 3 (kNotSupported), empty messages"),
    0x5DF9BA0: ("ClippingIterator", [20], "copy prop_name, call inner GetProperty"),
    0x5DF9C70: ("BlobCountingIterator", [20], "copy prop_name, call inner GetProperty"),
    0x5E27A30: ("SequenceIterWrapper", [23], "delegate to wrapped (+0x38) slot [23]"),
    0x5ED8A60: ("ForwardLevelIterator", [14], "inner (+0x58) PrepareValue; on false clear +0x40"),
    0x5ED8A80: ("ForwardLevelIterator", [18], "mgr (+0x60) null or +0x20==0 -> false, else inner (+0x58) slot [18]"),
    0x5ED8AB0: ("ForwardLevelIterator", [19], "mgr (+0x60) null or +0x20==0 -> false, else inner (+0x58) slot [19]"),
    0x5ED8AE0: ("ForwardLevelIterator", [17], "store mgr at +0x60, forward to inner (+0x58) slot [17] if non-null"),
    0x5ED8B70: ("ForwardIterator", [18], "mgr (+0x1e0) null or +0x20==0 -> false, else child (+0x158) slot [18]"),
    0x5ED8BB0: ("ForwardIterator", [19], "mgr (+0x1e0) null or +0x20==0 -> false, else child (+0x158) slot [19]"),
    0x5ED9AF0: ("ForwardIterator", [14], "child (+0x158) PrepareValue; on false clear +0x160 and copy child status() into +0x178/+0x17c/+0x180"),
    0x5ED9BB0: ("ForwardIterator", [20], "property 'rocksdb.iterator.super-version-number' (37 chars) -> decimal SuperVersion+0x218; else Status code 4 (kInvalidArgument)"),
    0x5EDA2F0: ("ForwardIterator", [17], "store mgr at +0x1e0, tail-jump to UpdateChildrenPinnedItersMgr (0x5eda1e0)"),
    0x5F04E00: ("MemTableIterator", [18], "return true (memtable keys are arena-pinned)"),
    0x5F04E10: ("MemTableIterator", [19], "return byte +0x5a (construction flag)"),
    0x5F2E790: ("FragmentedRangeTombstoneIterator", [18], "return false (key() rebuilds into a cached string)"),
    0x5F2E7A0: ("FragmentedRangeTombstoneIterator", [19], "return true (value is the stable fragment end key)"),
    0x5F2E8B0: ("VectorIterator", [18], "return true"),
    0x5F2E8C0: ("VectorIterator", [19], "return true"),
    0x5F610D0: ("LevelIterator", [14], "if +0xc9 set return true; else file_iter_ (+0xb0) PrepareValue; on false clear +0xd0, on true set +0xc9"),
    0x5F61120: ("LevelIterator", [15], "if +0x94 == 0 return false, else file_iter_ (+0xb0) slot [15]"),
    0x5F61150: ("LevelIterator", [16], "if +0xd0 == 0 and +0xf8 == 0 return 0, else return cached byte +0xc8"),
    0x5F61170: ("LevelIterator", [17], "store mgr at +0xd8, forward to file_iter_ (+0xb0) slot [17] if non-null"),
    0x5F611A0: ("LevelIterator", [18], "mgr (+0xd8) null or +0x20==0 -> false, else file_iter_ (+0xb0) slot [18]"),
    0x5F611E0: ("LevelIterator", [19], "mgr (+0xd8) null or +0x20==0 -> false, else file_iter_ (+0xb0) slot [19]"),
    0x5F61220: ("LevelIterator", [23], "return flag byte +0xf8 (is_delete_range_sentinel_key_)"),
    0x60E2020: ("BlockIter/DataBlockIter/MetaBlockIter", [18], "return +0x109 ? +0x108 : 0"),
    0x60E2040: ("BlockIter/DataBlockIter/MetaBlockIter", [19], "return byte +0x109"),
    0x61232C0: ("BlockBasedTableIterator", [16], "is_out_of_bound_ (+0x28a) -> 1; block_upper_bound_check_ (+0x28c) == 1 -> 2; else 0"),
    0x61232E0: ("BlockBasedTableIterator", [17], "store mgr at +0x50"),
    0x61232F0: ("BlockBasedTableIterator", [18], "mgr null or +0x20==0 -> false; at first key from index -> index_iter_ IsValuePinned; else inlined block_iter_ IsKeyPinned gated by block_iter_points_to_real_block_ (+0x289)"),
    0x6123360: ("BlockBasedTableIterator", [19], "mgr null or +0x20==0 -> false; else block_iter_points_to_real_block_ (+0x289)"),
    0x61233C0: ("BlockBasedTableIterator", [22], "if table (+0x38) readahead enabled, copy 16-byte Slice from *rsi to +0x260, forward to index_iter_ (+0x28) slot [22] unless it is the base stub"),
    0x6123410: ("BlockBasedTableIterator", [21], "fill *rsi with the 16-byte Slice from the table holder (+0x280: +0x20/+0x60), forward to index_iter_ (+0x28) slot [21] unless it is the base stub"),
    0x6123670: ("BlockBasedTableIterator", [11], "at first key from index: ExtractUserKey(index_iter_->value().first_internal_key); else block_iter_.key() with len-8"),
    0x6126070: ("BlockBasedTableIterator", [14], "at first key from index -> MaterializeCurrentBlock (0x6125ba0); else true"),
    0x6172620: ("MergingIterator", [15], "delegate to current_ wrapper (+0xb0) slot [15]"),
    0x6172640: ("MergingIterator", [16], "return cached bound_check_result byte at current_ wrapper +0x18"),
    0x6172650: ("MergingIterator", [17], "store mgr at +0x148, forward to every child (+0x38..+0x40, stride 0x58) slot [17]"),
    0x6172690: ("MergingIterator", [18], "mgr (+0x148) null or +0x20==0 -> false, else current_ slot [18]"),
    0x61726D0: ("MergingIterator", [19], "mgr (+0x148) null or +0x20==0 -> false, else current_ slot [19]"),
    0x6172DB0: ("MergingIterator", [14], "if current_ wrapper +0x19 (prepared) return true; else current_ PrepareValue; on false clear +0x20 and copy child status() into +0xb8/+0xba/+0xc0; on true set +0x19"),
    0x617DBF0: ("CompactionMergingIterator", [15], "if child (+0xa0) +0x50 == 1 return true, else child slot [15]"),
    0x617DC20: ("CompactionMergingIterator", [16], "if child (+0xa0) +0x50 == 1 return 0, else child +0x18 (bound_check_result)"),
    0x617DC40: ("CompactionMergingIterator", [17], "store mgr at +0x130, forward to every child (+0x38..+0x40, stride 0x58) slot [17]"),
    0x617DC80: ("CompactionMergingIterator", [23], "return (child (+0xa0) +0x50 == 1)"),
    0x617DCE0: ("CompactionMergingIterator", [18], "return false"),
    0x617DCF0: ("CompactionMergingIterator", [19], "return false"),
    0x617DD00: ("CompactionMergingIterator", [14], "return false"),
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    actual = sha256_file(BIN)
    assert actual == DIGEST, f"binary digest mismatch: {actual}"
    # vtable census rows from census.py output (tail_table.tsv)
    rows = []
    for line in open(HERE / "tail_table.tsv").read().splitlines()[1:]:
        cls, slot, addr = line.split("\t")
        rows.append({"class": cls, "slot": int(slot),
                     "address": addr,
                     "name": SLOT_MAP[int(slot)]["name"]})
    classes = sorted({r["class"] for r in rows})
    assert len(classes) == 21, f"expected 21 vtables, got {len(classes)}"
    assert len(rows) == 231, f"expected 231 tail rows, got {len(rows)}"
    # dispatch census summary from callers.tsv
    kept = {}
    total = 0
    for line in open(HERE / "callers.tsv").read().splitlines()[1:]:
        slot = int(line.split("\t")[0])
        kept[slot] = kept.get(slot, 0) + 1
        total += 1
    records = {
        "task": "RE-001",
        "artifact": {"node": 115, "path": "work/hl-node-115.bin",
                     "sha256": DIGEST},
        "question": ("What are the C++ names and behaviours of the "
                     "InternalIteratorBase vtable tail slots [11] and "
                     "[14]-[23] in node #115?"),
        "slot_map": {str(s): SLOT_MAP[s] for s in sorted(SLOT_MAP)},
        "enums": {
            "IterBoundCheck": {"kUnknown": 0, "kOutOfBound": 1,
                               "kInbound": 2},
            "BlockUpperBound": {"kUpperBoundInCurBlock": 0,
                                "kUpperBoundBeyondCurBlock": 1,
                                "kUnknown": 2},
        },
        "vtables": {
            "count": len(classes),
            "classes": classes,
            "tail_rows": len(rows),
            "rows": rows,
            "excluded_false_positives": [
                {"stored_ptr": "0x64ece78", "typeinfo": None,
                 "reason": "no typeinfo; tail pattern matches by chance"},
                {"stored_ptr": "0x64ed2a8", "typeinfo": None,
                 "reason": "no typeinfo; tail pattern matches by chance"},
                {"stored_ptr": "0x64ed2d0", "typeinfo": None,
                 "reason": "no typeinfo; tail pattern matches by chance"},
                {"stored_ptr": "0x64ed2f8", "typeinfo": None,
                 "reason": "no typeinfo; tail pattern matches by chance"},
                {"stored_ptr": "0x64ed308", "typeinfo": None,
                 "reason": "no typeinfo; tail pattern matches by chance"},
            ],
        },
        "windows": [
            {"address": f"0x{a:x}", "class": c, "slots": s,
             "behaviour": b}
            for a, (c, s, b) in sorted(WINDOWS.items())
        ],
        "supporting_windows": [
            {"address": "0x5df7ce0", "slot": 8,
             "name": "NextAndGetResult (base default)",
             "behaviour": ("Next(); if Valid() then result->key = key() "
                           "and a zero u16 at result+0x10; returns Valid()")},
            {"address": "0x5eda1e0",
             "name": "ForwardIterator::UpdateChildrenPinnedItersMgr",
             "behaviour": ("forward the mgr at +0x1e0 to the immutable "
                           "iterator (+0x108) and to every iterator in "
                           "the arrays +0x110..+0x118 and +0x128..+0x130 "
                           "via slot [17]")},
        ],
        "field_notes": [
            {"class": "BlockBasedTableIterator",
             "fields": {"+0x28": "index_iter_", "+0x38": "table",
                        "+0x50": "pinned_iters_mgr_",
                        "+0x58": "block_iter_ subobject",
                        "+0x260": "readahead state (16-byte Slice)",
                        "+0x280": "readahead holder",
                        "+0x289": "block_iter_points_to_real_block_",
                        "+0x28a": "is_out_of_bound_",
                        "+0x28c": "block_upper_bound_check_",
                        "+0x290": "is_at_first_key_from_index_"}},
            {"class": "MergingIterator",
             "fields": {"+0x38..+0x40": "children array (stride 0x58)",
                        "+0xb0": "current_ (IteratorWrapper*)",
                        "+0x148": "pinned_iters_mgr_",
                        "+0xb8/+0xba/+0xc0": "cached child Status",
                        "wrapper +0x18": "bound_check_result",
                        "wrapper +0x19": "prepared flag",
                        "wrapper +0x20": "cleared on PrepareValue failure"}},
            {"class": "LevelIterator",
             "fields": {"+0x94": "MayBe gate flag", "+0xb0": "file_iter_",
                        "+0xc8": "cached IterBoundCheck byte",
                        "+0xc9": "prepared flag", "+0xd0": "flag",
                        "+0xd8": "pinned_iters_mgr_",
                        "+0xf8": "is_delete_range_sentinel_key_"}},
            {"class": "ForwardIterator",
             "fields": {"+0x100": "SuperVersion*",
                        "+0x158": "current child iterator",
                        "+0x160": "prepared flag",
                        "+0x178/+0x17c/+0x180": "cached child Status",
                        "+0x1e0": "pinned_iters_mgr_",
                        "SuperVersion +0x218": "version number (uint64)"}},
            {"class": "BlockIter",
             "fields": {"+0x108": "key-pinned byte",
                        "+0x109": "value-pinned byte"}},
            {"class": "CompactionMergingIterator",
             "fields": {"+0xa0": "current child",
                        "child +0x50": "flag (== 1 means sentinel path)",
                        "+0x130": "pinned_iters_mgr_"}},
        ],
        "properties": [
            {"name": "rocksdb.iterator.super-version-number", "length": 37,
             "class": "ForwardIterator", "address": "0x5ed9bb0",
             "value": "decimal SuperVersion+0x218",
             "unknown_property_status": 4,
             "unknown_property_status_name": "kInvalidArgument"},
        ],
        "status_layout": {
            "size_bytes": 16,
            "note": ("Status is returned by value (hidden sret pointer in "
                     "rdi, this in rsi) by slot [13] status(); field copies "
                     "cover {code, subcode, state_} in 16 bytes")},
        "dispatch_census": {
            "raw_verified_sites": 1719,
            "kept_iterator_consumer_sites": total,
            "per_slot_kept": {str(k): v for k, v in sorted(kept.items())},
            "filter": ("keep a site only if its containing FDE is one of "
                       "the 78 tail windows (wrapper delegation) or "
                       "dispatches through Valid (0x10) and key (0x50) "
                       "plus at least two more core InternalIterator "
                       "slots; offsets 0x98/0xa0/0xb0 are shared with "
                       "other hierarchies, so the core-slot bar is what "
                       "separates a real InternalIterator dispatch from "
                       "a same-offset dispatch through another vtable"),
        },
        "notes": [
            ("The 8.1.1 interface has exactly one MayBe* slot ([15]); "
             "there is no MayBeOutOfLowerBound slot in this binary -- "
             "that method appears only in later RocksDB releases' "
             "IteratorWrapperBase."),
            ("Slot [13] is status() (returns Status by value); it is "
             "outside the tail range but is called by ForwardIterator "
             "and MergingIterator PrepareValue on the false path."),
            ("IterateResult layout beyond key (Slice at +0) plus a zero "
             "u16 at +0x10 remains open (carried from #3900)."),
            ("MemTableIterator [19] reads the byte at +0x5a; its exact "
             "construction-flag meaning is open (see #3803)."),
            ("CompactionMergingIterator child +0x50 flag's source "
             "identity is open; only its observed effect is recorded."),
            ("BlockIter +0x108/+0x109 member names are not pinned; only "
             "the observed byte semantics are recorded."),
        ],
    }
    with open(HERE / "records.json", "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    # vtables.tsv: the 21 vtables, tail slots only
    with open(HERE / "vtables.tsv", "w") as f:
        f.write("class\tstored_ptr\tslot\tname\taddress\n")
        ptrs = {}
        for line in open(HERE / "vtables_all.txt"):
            m = re.match(
                r"=== vtable stored_ptr (0x[0-9a-f]+) typeinfo=(\S+)", line)
            if m:
                ptrs[m.group(2)] = m.group(1)
        for r in rows:
            f.write(f"{r['class']}\t{ptrs.get(r['class'], '')}\t"
                    f"{r['slot']}\t{r['name']}\t{r['address']}\n")
    print(f"records.json: {len(rows)} tail rows, {len(WINDOWS)} windows, "
          f"{total} kept dispatch sites")


if __name__ == "__main__":
    main()
