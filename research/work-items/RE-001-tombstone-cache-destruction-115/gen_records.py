"""Generate records.json for RE-001-tombstone-cache-destruction-115.

Run from the repository root:
    python3 research/work-items/RE-001-tombstone-cache-destruction-115/gen_records.py

Semantic records only: no per-instruction mnemonic list. Instruction
detail lives in the verbatim objdump excerpts. The caller census is
recomputed from the digest-verified binary by census.py.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
import census as census_mod

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    {"address": "0x5f061b0", "size": 920, "fde_offset": "0x745470",
     "catalogue": "_ZNSt23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE10_M_disposeEv",
     "name": "shared_ptr control-block _M_dispose for FragmentedRangeTombstoneListCache"},
    {"address": "0x5f0b080", "size": 920, "fde_offset": "0x7457e8",
     "catalogue": "std::unique_ptr<rocksdb::FragmentedRangeTombstoneList>::~unique_ptr()",
     "name": "unique_ptr<FragmentedRangeTombstoneList>::~unique_ptr"},
    {"address": "0x5f10d40", "size": 2648, "fde_offset": "0x745c2c",
     "catalogue": "rocksdb::MemTable::~MemTable()",
     "name": "MemTable::~MemTable"},
    {"address": "0x605e8a0", "size": 71, "fde_offset": "0x367860",
     "catalogue": "rocksdb::AllocTracker::FreeMem",
     "name": "AllocTracker::FreeMem"},
    {"address": "0x605e860", "size": 62, "fde_offset": "0x367840",
     "catalogue": "rocksdb::AllocTracker::DoneAllocating",
     "name": "AllocTracker::DoneAllocating"},
    {"address": "0x606a890", "size": 47, "fde_offset": "0x368ddc",
     "catalogue": "rocksdb::WriteBufferManager::FreeMem",
     "name": "WriteBufferManager::FreeMem"},
    {"address": "0x5f0a290", "size": 137, "fde_offset": "0x358b8c",
     "catalogue": "_ZNSt23_Sp_counted_ptr_inplaceIKNSt10shared_ptrIN7rocksdb33FragmentedRangeTombstoneListCacheEEESaIS4_ELN9__gnu_cxx12_Lock_policyE2EE10_M_disposeEv",
     "name": "shared_ptr control-block _M_dispose for the inner shared_ptr<Cache>"},
    {"address": "0x5f10180", "size": 50, "fde_offset": "0x358c70",
     "catalogue": "rocksdb::ConcurrentArena::~ConcurrentArena D1",
     "name": "ConcurrentArena::~ConcurrentArena (base-object destructor)"},
    {"address": "0x5f10d00", "size": 60, "fde_offset": "0x358c90",
     "catalogue": "rocksdb::ConcurrentArena::~ConcurrentArena D0",
     "name": "ConcurrentArena::~ConcurrentArena (deleting destructor)"},
    {"address": "0x5f05b80", "size": 457, "fde_offset": "0x3585a4",
     "catalogue": None,
     "name": "RB-tree erase helper, 0x30-byte nodes (no catalogue row; by shape)"},
    {"address": "0x5f06770", "size": 1086, "fde_offset": "0x358710",
     "catalogue": None,
     "name": "RB-tree erase helper, 0x60-byte nodes (no catalogue row; by shape)"},
    {"address": "0x5ecd650", "size": 853, "fde_offset": "0x35634c",
     "catalogue": "std::unique_ptr<rocksdb::FlushJobInfo>::~unique_ptr()",
     "name": "unique_ptr<FlushJobInfo>::~unique_ptr"},
    {"address": "0x5f053d0", "size": 712, "fde_offset": "0x358434",
     "catalogue": None,
     "name": "__introsort_loop (re-shipped from PR #3803; by shape)",
     "re_shipped_from": "RE-001-fragmented-range-tombstones-115 (PR #3803)"},
    {"address": "0x5f05120", "size": 213, "fde_offset": "0x358394",
     "catalogue": None,
     "name": "__insertion_sort (re-shipped from PR #3803; by shape)",
     "re_shipped_from": "RE-001-fragmented-range-tombstones-115 (PR #3803)"},
    {"address": "0x5f04f80", "size": 429, "fde_offset": "0x358344",
     "catalogue": None,
     "name": "__adjust_heap (re-shipped from PR #3803; by shape)",
     "re_shipped_from": "RE-001-fragmented-range-tombstones-115 (PR #3803)"},
    {"address": "0x61bd0e0", "size": 81, "fde_offset": "0x76b880",
     "catalogue": "rocksdb::Cleanable::DoCleanup (one of 2 identical copies)",
     "name": "Cleanable::DoCleanup (re-shipped from PR #3803)",
     "re_shipped_from": "RE-001-fragmented-range-tombstones-115 (PR #3803)"},
    {"address": "0x5f059b0", "size": 457, "fde_offset": "0x358558",
     "catalogue": None,
     "name": "FragmentedRangeTombstoneList release (re-shipped from PR #3803; by shape)",
     "re_shipped_from": "RE-001-fragmented-range-tombstones-115 (PR #3803)"},
]

CALLER_LABELS = {
    # site -> (containing FDE range, catalogue label of the containing function)
    "0x5f1021b": (["0x5f101b2", "0x5f103e6"], "rocksdb::MemTable::MemTable C2 (.cold part)"),
    "0x5d51427": (["0x5d511b0", "0x5d515ae"], "rocksdb::JobContext::Clean"),
    "0x5d51a27": (["0x5d519d0", "0x5d51aaf"], "rocksdb::DBImpl::WriteContext::~WriteContext"),
    "0x5d72288": (["0x5d71fe0", "0x5d72e50"], "rocksdb::DBImpl::SetDBOptions"),
    "0x5d8cae0": (["0x5d8ca70", "0x5d8caf9"], "rocksdb::ColumnFamilyData::CreateNewMemtable"),
    "0x5d8d877": (["0x5d8d820", "0x5d8d96b"], "rocksdb::SuperVersion::~SuperVersion"),
    "0x5d90010": (["0x5d8fef0", "0x5d906df"], "rocksdb::ColumnFamilyData::~ColumnFamilyData"),
    "0x5d905cb": (["0x5d8fef0", "0x5d906df"], "rocksdb::ColumnFamilyData::~ColumnFamilyData"),
    "0x5d94390": (["0x5d93900", "0x5d9456b"], "rocksdb::ColumnFamilyHandleImpl::~ColumnFamilyHandleImpl"),
    "0x5e46c5f": (["0x5e46100", "0x5e4968b"], "FDE 0x5e46100..0x5e4968b (no catalogue row)"),
    "0x5e4783f": (["0x5e46100", "0x5e4968b"], "FDE 0x5e46100..0x5e4968b (no catalogue row)"),
    "0x5e47dd8": (["0x5e46100", "0x5e4968b"], "FDE 0x5e46100..0x5e4968b (no catalogue row)"),
    "0x5e4810a": (["0x5e46100", "0x5e4968b"], "FDE 0x5e46100..0x5e4968b (no catalogue row)"),
    "0x5e48f47": (["0x5e46100", "0x5e4968b"], "FDE 0x5e46100..0x5e4968b (no catalogue row)"),
    "0x5e8b3bf": (["0x5e8a890", "0x5e8c518"], "rocksdb::DBImpl::SwitchMemtable"),
    "0x5edc1b8": (["0x5edbac0", "0x5edc3b3"], "rocksdb::ForwardIterator::SVCleanup"),
    "0x5f10d5f": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x605cc5f": (["0x605cc30", "0x605cf73"], "rocksdb::Arena::~Arena"),
    "0x605e8f8": (["0x605e8f0", "0x605e902"], "rocksdb::AllocTracker::~AllocTracker"),
    "0x5f14117": (["0x5f140c0", "0x5f14179"], "rocksdb::MemTableList::Add"),
    "0x605e8e0": (["0x605e8a0", "0x605e8e7"], "rocksdb::AllocTracker::FreeMem"),
    "0x605e8d3": (["0x605e8a0", "0x605e8e7"], "rocksdb::AllocTracker::FreeMem"),
    "0x5f10276": (["0x5f101b2", "0x5f103e6"], "rocksdb::MemTable::MemTable C2 (.cold part)"),
    "0x5f05c11": (["0x5f05b80", "0x5f05d49"], "RB-tree erase helper, 0x30-byte nodes (self-recursion)"),
    "0x5f1138c": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f0683c": (["0x5f06770", "0x5f06bae"], "RB-tree erase helper, 0x60-byte nodes (self-recursion)"),
    "0x5f10f0b": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f10f4e": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5eced73": (["0x5eced64", "0x5eceda4"], "rocksdb::FlushJob::GetFlushJobInfo (.cold part)"),
    "0x5f10227": (["0x5f101b2", "0x5f103e6"], "rocksdb::MemTable::MemTable C2 (.cold part)"),
    "0x5f14e5d": (["0x5f14d85", "0x5f14e79"], "rocksdb::InstallMemtableAtomicFlushResults"),
    "0x5f16845": (["0x5f1683e", "0x5f16972"], "rocksdb::MemTableList::TryInstallMemtableFlushResults"),
    "0x5d8ca47": (["0x5d8ca00", "0x5d8ca6a"], "rocksdb::ColumnFamilyData::ConstructNewMemtable"),
    "0x5ed08ab": (["0x5ed01f0", "0x5ed2238"], "rocksdb::FlushJob::MemPurge"),
}

INTERNAL_SITE_LABELS = {
    "0x5f06348": (["0x5f061b0", "0x5f06548"], "shared_ptr _M_dispose (Cache)"),
    "0x5f0b218": (["0x5f0b080", "0x5f0b418"], "unique_ptr<List>::~unique_ptr"),
    "0x5f115b6": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f055b9": (["0x5f053d0", "0x5f05678"], "__introsort_loop (self-recursion)"),
    "0x5f06367": (["0x5f061b0", "0x5f06548"], "shared_ptr _M_dispose (Cache)"),
    "0x5f06496": (["0x5f061b0", "0x5f06548"], "shared_ptr _M_dispose (Cache)"),
    "0x5f0b237": (["0x5f0b080", "0x5f0b418"], "unique_ptr<List>::~unique_ptr"),
    "0x5f0b366": (["0x5f0b080", "0x5f0b418"], "unique_ptr<List>::~unique_ptr"),
    "0x5f115d5": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f116f1": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f0560d": (["0x5f053d0", "0x5f05678"], "__introsort_loop"),
    "0x5f0564f": (["0x5f053d0", "0x5f05678"], "__introsort_loop"),
    "0x5f0620a": (["0x5f061b0", "0x5f06548"], "shared_ptr _M_dispose (Cache)"),
    "0x5f0b0d9": (["0x5f0b080", "0x5f0b418"], "unique_ptr<List>::~unique_ptr"),
    "0x5f10e02": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
    "0x5f06234": (["0x5f061b0", "0x5f06548"], "shared_ptr _M_dispose (Cache)"),
    "0x5f0b104": (["0x5f0b080", "0x5f0b418"], "unique_ptr<List>::~unique_ptr"),
    "0x5f10e24": (["0x5f10d40", "0x5f11798"], "rocksdb::MemTable::~MemTable"),
}

BEHAVIOURS = {
    "cache_dispose": {
        "entry": "0x5f061b0",
        "control_block_offset_of_list": "+0x38",
        "list_size": "0xe8",
        "steps": [
            "load List* from control-block +0x38; null -> return without freeing",
            "if cache +0xb8 flag is set: sort/dedup/invoke path; else free-array path",
            "sort path: load end from cache +0xc8, clear the +0xb8 flag, sort the index with __introsort_loop (0x5f053d0) then __insertion_sort (0x5f05120), invoke each entry destructor via call *0x8(%rbx), store the new end back to +0xc8",
            "sort path (continued): walk the +0xb0 chain inline (call fn(+0x8,+0x10), free 0x20 per node), zero +0x98 and +0xb0, then rejoin the common tail",
            "common tail: free the +0xc0 index array, DoCleanup(+0x98) at 0x61bd0e0, walk the +0x80 list (0x30-byte nodes, call fn(+0x8,+0x10), free each node), release the +0x60 tree via 0x5f059b0, free the +0x30, +0x18 and +0x00 buffers, operator delete the 0xe8-byte control block",
            "free-array path: free the +0xc0 array if non-null (size = end - base), then the same common tail",
        ],
        "dedup": "std::unique-style adjacent scan over the sorted index",
        "sort_helpers": {"introsort_loop": "0x5f053d0", "insertion_sort": "0x5f05120", "adjust_heap": "0x5f04f80", "depth_limit": "2*log2(n) (cmp $0x100 threshold: insertion sort for <=16 entries)"},
    },
    "unique_ptr_list_dtor": {
        "entry": "0x5f0b080",
        "owner_offset_of_cache": "+0x00",
        "note": "structurally identical to 0x5f061b0 except the owner-load offset and branch targets; the same flag-gated sort/dedup/invoke teardown, inlined",
        "standalone_calls": "only from MemTable::MemTable .cold cleanup (0x5f1021b); the normal MemTable::~MemTable path inlines this teardown at +0xce0",
    },
    "memtable_dtor_order": {
        "entry": "0x5f10d40",
        "order": [
            "AllocTracker::FreeMem(+0x80) at 0x5f10d5f",
            "release the +0xd10 CoreLocalArray elements via _Sp_counted_base::_M_release (0x5d350c0) each, then operator delete[] the element array",
            "teardown the cache at +0xce0 (unique_ptr<List>, flag-gated sort/dedup/invoke, inlined)",
            "destroy unique_ptr<FlushJobInfo> at +0xcd8 (0x340-byte object, member-wise, inlined): 13 strings, maps at +0x2d0/+0x300 erased via the 0x60-byte-node helper 0x5f06770, vector at +0x328 of 0x38-byte elements",
            "free the +0xc90 chain of 0x28-byte nodes",
            "memset the +0xc80 inline array (count at +0xc88), free the buffer if it is not the inline +0xcb0 slot, zero +0xc98/+0xc90",
            "free +0xc60 (0x10 bytes)",
            "destroy the +0xc40 vector of 0x38-byte pthread_rwlock_t via 0x60d5930, free the buffer",
            "dispose the strings at +0xbf8/+0xbd0",
            "free the buffers at +0xba8/+0xb90",
            "destroy the +0xb78 vector of 0x58-byte structs (2 strings each)",
            "destroy the +0xb60 vector of 0x130-byte structs (4 strings each)",
            "destroy the +0xb40 RB-tree (0x30-byte nodes via 0x5f05b80)",
            "destroy the +0xb18 vector of 0x28-byte structs (1 string each)",
            "dispose the strings at +0xac0/+0xaa0",
            "virtual slot 0x88 calls on the reps at +0xa58 and +0xa50 (SkipListRep slot 17 resolves to the 0x58-byte delete stub 0x6063010)",
            "install the ConcurrentArena vtable at +0xa0, Arena::~Arena(+0x100) at 0x605cc30, operator delete[] on *(+0xe8)",
            "tail-jump to AllocTracker::~AllocTracker (0x605e8f0) at +0x80",
        ],
    },
    "alloc_tracker": {
        "free_mem": {
            "entry": "0x605e8a0",
            "steps": [
                "if +0x10 == 0, call DoneAllocating() first",
                "if *(tracker) is null, return",
                "if +0x11 != 0, return (already freed)",
                "if *(manager) != 0 or manager+0x20 != 0, call WriteBufferManager::FreeMem(manager, tracker+0x8)",
                "set +0x11 = 1",
            ],
        },
        "done_allocating": {
            "entry": "0x605e860",
            "steps": [
                "if *(tracker) is null, return",
                "if +0x10 != 0, return (already done)",
                "if *(manager) != 0 or manager+0x20 != 0, call 0x606a110(manager, tracker+0x8) (atomic sub of the second counter at manager+0x18)",
                "set +0x10 = 1",
            ],
        },
        "write_buffer_manager_free_mem": {
            "entry": "0x606a890",
            "steps": [
                "if manager+0x20 != 0: call FreeMemWithCache (0x606a170), then MaybeEndWriteStall (0x606a650)",
                "else if *(manager) != 0: lock sub %rsi, 0x10(%rdi)",
                "then MaybeEndWriteStall (0x606a650)",
            ],
        },
        "manager_counters": {"+0x10": "first counter (atomic sub on the no-cache path)", "+0x18": "second counter (atomic sub in 0x606a110)", "+0x20": "cache gate"},
        "arena_owns_tracker": "Arena::~Arena calls FreeMem on the AllocTracker at Arena+0x8e8 (if non-null)",
        "done_allocating_external_caller": "MemTableList::Add calls DoneAllocating on MemTable+0x80",
    },
    "shared_ptr_release_chain": {
        "cache_control_block_vtable": "0x64cc718",
        "cache_control_block_typeinfo": "0x64cc598",
        "cache_control_block_typeinfo_name": "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE",
        "cache_control_block_slots": {"D2": "0x5f04e30", "D0": "0x5f04e50", "_M_dispose": "0x5f061b0", "_M_destroy": "0x5f04f70", "_M_get_deleter": "0x5f057c0"},
        "inner_control_block_vtable": "0x64cc750",
        "inner_control_block_slots": {"D2": "0x5f04e20", "D0": "0x5f04e60", "_M_dispose": "0x5f0a290", "_M_destroy": "0x5f04f60"},
        "inner_dispose": {
            "entry": "0x5f0a290",
            "steps": [
                "load *(ctrl+0x18): the inner shared_ptr's control block",
                "decrement its use count (single-threaded fast path at 0x64ed290, lock xadd slow path)",
                "at count 1: call vtable slot 0x10 (the Cache _M_dispose, 0x5f061b0), then tail-jump to vtable slot 0x18 (_M_destroy)",
            ],
        },
        "chain": "array element -> 0x5f0a290 -> Cache control block -> 0x5f061b0 -> List teardown",
        "cache_struct": "FragmentedRangeTombstoneListCache is a 0x38-byte struct; the first 0x28 bytes are trivially destructible (zeroed at construction) and the FragmentedRangeTombstoneList* sits at +0x28 (= control-block +0x38, what _M_dispose loads)",
        "vtable_resolution_note": ".data.rel.ro file bytes are zeros for these tables; vtable resolution goes through .rela.dyn R_X86_64_RELATIVE addends",
    },
    "concurrent_arena": {
        "vtable": "0x64cc5d8",
        "typeinfo_name": "N7rocksdb15ConcurrentArenaE",
        "d1": "0x5f10180",
        "d0": "0x5f10d00",
        "d1_steps": ["install the Arena vtable (0x64cc5c8+0x10) at this+0x0", "call Arena::~Arena(this+0x60) at 0x605cc30", "operator delete[] on *(this+0x48) if non-null"],
        "d0_extra": "same as D1, then operator delete this with size 0x9b0 (sizeof(ConcurrentArena) = 0x9b0)",
        "memtable_layout": "MemTable spans +0xa0..+0xa50 for the ConcurrentArena; the reps sit at +0xa50/+0xa58",
    },
    "rb_erase": {
        "node_30": {"entry": "0x5f05b80", "node_size": "0x30", "shape": "recurse on the right child (+0x18), dispose the value strings inline via the SSO-free pattern (no _M_dispose PLT calls), delete the node, move to the left child (+0x10)"},
        "node_60": {"entry": "0x5f06770", "node_size": "0x60", "shape": "same as the 0x30-byte helper, for 0x60-byte nodes"},
        "note": "standard libstdc++ _M_erase shape",
    },
    "flush_job_info": {
        "entry": "0x5ecd650",
        "object_size": "0x340",
        "strings": ["+0x8", "+0x28", "+0x140", "+0x160", "+0x180", "+0x1a0", "+0x1c0", "+0x200", "+0x220", "+0x2a0", "+0x240", "+0x280", "+0x260"],
        "maps": ["+0x2d0", "+0x300"],
        "vector": {"offset": "+0x328", "element_size": "0x38"},
        "standalone_calls": "FlushJob::GetFlushJobInfo (.cold, 0x5eced73), MemTable::MemTable .cold (0x5f10227), InstallMemtableAtomicFlushResults (0x5f14e5d), MemTableList::TryInstallMemtableFlushResults (0x5f16845)",
    },
    "memtable_ctor_construction_side": {
        "entry": "0x5f103f0",
        "size": 2312,
        "cold_part": "0x5f101b2",
        "steps": [
            "+0x80: AllocTracker ctor 0x605e810",
            "+0xa0: ConcurrentArena ctor 0x605e010",
            "+0xa50/+0xa58: MemTableRep* from SkipListFactory (ctor 0x6064440; CreateMemTableRep 0x6063640)",
            "+0xa60 byte = 1; +0xc80 inline array, +0xc88 = 1; +0xca0 = 1.0f",
            "+0xc40 vector of rwlocks, count from MemTable+0x38, each built via 0x60d5880",
            "+0xc60 conditionally created via 0x61c26f0 (0x10 bytes) when *(+0x30)==0 and *(+0x20)!=0",
            "+0xcd8/+0xce0 zeroed",
            "+0xd10: CoreLocalArray<shared_ptr<FragmentedRangeTombstoneListCache>> ctor 0x5f0b420: builds 1<<*(owner+0xd18) elements; one _Sp_counted_ptr_inplace<Cache> block (0x48 B; Cache object 0x38 B at +0x10, zeroed); per element a _Sp_counted_ptr_inplace<const shared_ptr<Cache>> block (0x20 B) whose inplace shared_ptr<Cache> = {ptr=cache+0x10, control=cache block}; ends with a tail-jump _M_release on its own reference",
        ],
        "cold_cleanup_order": ["CoreLocalArray deleter 0x5f0a1dc on +0xd10", "unique_ptr dtor 0x5f0b080 on +0xce0", "0x5ecd650 on +0xcd8", "VersionEdit::~VersionEdit 0x5d516f0 on +0xa98", "slot-0x88 on the reps", "ConcurrentArena D1 0x5f10180 on +0xa0", "AllocTracker dtor 0x605e8f0 on +0x80"],
    },
    "sso_string_dispose": "if data != S+0x10, operator delete(data, *(S+0x10)+1) (allocation size = capacity+1)",
}

VTABLES = {
    "cache_control_block": {
        "vtable": "0x64cc718", "typeinfo_object": "0x64cc598",
        "typeinfo_name": "St23_Sp_counted_ptr_inplaceIN7rocksdb33FragmentedRangeTombstoneListCacheESaIvELN9__gnu_cxx12_Lock_policyE2EE",
        "slots": {"0": "0x5f04e30", "1": "0x5f04e50", "2": "0x5f061b0", "3": "0x5f04f70", "4": "0x5f057c0"},
        "slot_names": {"0": "D2", "1": "D0", "2": "_M_dispose", "3": "_M_destroy", "4": "_M_get_deleter"},
        "relative_slot_for_dispose": "0x64cc728",
    },
    "inner_control_block": {
        "vtable": "0x64cc750",
        "slots": {"0": "0x5f04e20", "1": "0x5f04e60", "2": "0x5f0a290", "3": "0x5f04f60"},
        "slot_names": {"0": "D2", "1": "D0", "2": "_M_dispose", "3": "_M_destroy"},
        "relative_slot_for_dispose": "0x64cc760",
    },
    "concurrent_arena": {
        "vtable": "0x64cc5d8",
        "typeinfo_name": "N7rocksdb15ConcurrentArenaE",
        "slots": {"0": "0x5f10180", "1": "0x5f10d00", "2": "0x5f11c40", "3": "0x5f117a0", "4": "0x5f04da0", "6": "0x64cc568", "7": "0x5f05d50", "8": "0x5f06050", "9": "0x5f05f20", "10": "0x5f04db0", "11": "0x5f04e40", "13": "0x64cc580", "14": "0x5f04e70", "15": "0x5f058e0", "16": "0x5f04de0", "17": "0x5f081d0", "18": "0x5f08320", "19": "0x5f08c40", "20": "0x5f09050", "21": "0x5f08600", "22": "0x5f08790", "23": "0x5f08470"},
    },
    "skiplist_rep": {
        "vtable": "0x64d26e8", "typeinfo_object": "0x64d25f0",
        "typeinfo_name": "N7rocksdb12_GLOBAL__N_111SkipListRepE",
        "slots": {"0": "0x6063150", "1": "0x6065f80", "2": "0x6065f60", "3": "0x6065ec0", "4": "0x6065fa0", "5": "0x6066680", "6": "0x6066710", "7": "0x6066670", "8": "0x6066660", "9": "0x6064930", "10": "0x5f04d50", "11": "0x5f04d60", "12": "0x6065040", "13": "0x60646d0", "14": "0x6066f20", "15": "0x6062fb0", "16": "0x6062fc0", "17": "0x6063010", "18": "0x6063070", "19": "0x5f04d80", "20": "0x5e572d0", "21": "0x5d483f0", "22": "0x5f05db0"},
        "slot_names": {"0": "Allocate", "9": "Contains", "10": "trivial ret stub", "11": "trivial ret stub", "12": "Get", "13": "ApproximateNumEntries", "14": "UniqueRandomSample", "15": "return-0 stub", "16": "return-void stub", "17": "slot 0x88 (0x58-byte delete stub 0x6063010)", "18": "GetIterator", "19": "forwarder to slot 18", "22": "MemTableRep::UserKey"},
    },
}

UNKNOWNS = [
    "+0xa98 VersionEdit asymmetry: the MemTable ctor .cold path calls VersionEdit::~VersionEdit(+0xa98) but the normal destructor destroys only the strings at +0xaa0/+0xac0 and the ctor body never constructs a VersionEdit there",
    "the precise C++ element type of the +0xd10 CoreLocalArray (the aliasing-shared_ptr reading is an interpretation; the operational facts are pinned)",
    "the identity of the slot-0x88 calls on the reps (+0xa58/+0xa50); slot 17 of the SkipListRep vtable resolves to the 0x58-byte delete stub 0x6063010, whose role (deleting destructor tail vs another method) is not pinned",
    "the WriteBufferManager +0x0/+0x20 gate identities (+0x10 = first counter, +0x18 = second counter; the +0x20 cache pointer's type is not pinned)",
    "the individual FlushJobInfo string/map field names",
    "the MemTable vtable (the N7rocksdb8MemTableE typeinfo name string was not found in the binary by a plain string search; MemTable is deleted directly by 15 callers, not virtually)",
]


def main():
    calls, tails, hits, slots = census_mod.scan(os.path.join(ROOT, "work/hl-node-115.bin"))
    census = {}
    callers = {}
    for t in census_mod.TARGETS:
        census[hex(t)] = {
            "direct_calls": [hex(v) for v in sorted(set(calls[t]))],
            "tail_jumps": [hex(v) for v in sorted(set(tails[t]))],
            "qword_hits_file_offsets": [hex(v) for v in hits[t]],
            "relative_slots": [hex(v) for v in slots[t]],
        }
        rows = []
        for v in sorted(set(calls[t])):
            fde, label = CALLER_LABELS[hex(v)]
            rows.append({"site": hex(v), "kind": "direct_call",
                         "containing_fde": fde, "containing_function": label})
        for v in sorted(set(tails[t])):
            fde, label = CALLER_LABELS[hex(v)]
            rows.append({"site": hex(v), "kind": "tail_jump",
                         "containing_fde": fde, "containing_function": label})
        callers[hex(t)] = rows
    internal = {}
    for t in census_mod.GENERIC_HELPERS:
        rows = []
        # sites are recorded from the packet excerpts (verified by verify.py)
        for site_hex, (fde, label) in INTERNAL_SITE_LABELS.items():
            pass
        internal[hex(t)] = rows
    # fill packet-internal sites from the excerpt grep results
    internal_sites = {
        "0x5f053d0": ["0x5f06348", "0x5f0b218", "0x5f115b6", "0x5f055b9"],
        "0x5f05120": ["0x5f06367", "0x5f06496", "0x5f0b237", "0x5f0b366", "0x5f115d5", "0x5f116f1"],
        "0x5f04f80": ["0x5f0560d", "0x5f0564f"],
        "0x61bd0e0": ["0x5f0620a", "0x5f0b0d9", "0x5f10e02"],
        "0x5f059b0": ["0x5f06234", "0x5f0b104", "0x5f10e24"],
    }
    for t_hex, sites in internal_sites.items():
        rows = []
        for s in sites:
            fde, label = INTERNAL_SITE_LABELS[s]
            rows.append({"site": s, "kind": "direct_call",
                         "containing_fde": fde, "containing_function": label})
        internal[t_hex] = rows

    records = {
        "task_id": "RE-001",
        "work_item": "RE-001-tombstone-cache-destruction-115",
        "question": "How is the node #115 fragmented range-tombstone cache destroyed: the shared_ptr dispose, the unique_ptr destructor, and MemTable::~MemTable?",
        "artifact": "artifacts/node/115/hl-node",
        "artifact_sha256": DIGEST,
        "binary": "work/hl-node-115.bin",
        "windows": WINDOWS,
        "behaviours": BEHAVIOURS,
        "vtables": VTABLES,
        "census": census,
        "callers": callers,
        "packet_internal_sites": internal,
        "unknowns": UNKNOWNS,
        "re_shipped": {
            "from": "RE-001-fragmented-range-tombstones-115 (PR #3803)",
            "excerpts": ["introsort-5f053d0", "insertion-5f05120", "adjust-heap-5f04f80", "cleanable-dtor-61bd0e0", "list-release-5f059b0"],
            "note": "byte-identical re-ships; the sort/dedup/invoke helpers and the Cleanable/list-release helpers are shared by the dispose, the unique_ptr dtor and the MemTable dtor, so this packet is self-contained",
        },
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=2)
        fh.write("\n")
    print("wrote records.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
