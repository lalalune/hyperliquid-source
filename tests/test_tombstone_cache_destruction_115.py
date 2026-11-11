"""Tests for tools/tombstone_cache_destruction_115.py.

Every expectation is grounded in
research/work-items/RE-001-tombstone-cache-destruction-115/records.json
and the verbatim objdump excerpts in that packet.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import tombstone_cache_destruction_115 as m

CHECKS = 0


def check(cond, label):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError("check failed: " + label)


def eq(a, b, label):
    check(a == b, "%s: %r != %r" % (label, a, b))


# --- constants -------------------------------------------------------
eq(m.CACHE_SIZE, 0xE8, "cache size")
eq(m.CACHE_LIST_OFFSET, 0x38, "cache list offset")
eq(m.CACHE_READY_FLAG_OFFSET, 0xB8, "cache ready flag offset")
eq(m.CACHE_INDEX_OFFSET, 0xC0, "cache index offset")
eq(m.CACHE_END_OFFSET, 0xC8, "cache end offset")
eq(m.CACHE_CLEANABLE_OFFSET, 0x98, "cache cleanable offset")
eq(m.CACHE_LIST_HEAD_OFFSET, 0x80, "cache list head offset")
eq(m.CACHE_TREE_OFFSET, 0x60, "cache tree offset")
eq(m.CACHE_CHAIN_OFFSET, 0xB0, "cache chain offset")
eq(m.ALLOC_TRACKER_DONE_OFFSET, 0x10, "tracker done offset")
eq(m.ALLOC_TRACKER_FREED_OFFSET, 0x11, "tracker freed offset")
eq(m.ALLOC_TRACKER_AMOUNT_OFFSET, 0x08, "tracker amount offset")
eq(m.WBM_FIRST_COUNTER_OFFSET, 0x10, "wbm first counter offset")
eq(m.WBM_SECOND_COUNTER_OFFSET, 0x18, "wbm second counter offset")
eq(m.WBM_CACHE_GATE_OFFSET, 0x20, "wbm cache gate offset")
eq(m.ARENA_SIZE, 0x9B0, "arena size")
eq(m.SKIPLIST_REP_SIZE, 0x58, "skiplist rep size")
eq(m.FLUSH_JOB_INFO_SIZE, 0x340, "flush job info size")
eq(m.CORE_LOCAL_ARRAY_OFFSET, 0xD10, "core local array offset")
eq(m.MEMTABLE_CACHE_OFFSET, 0xCE0, "memtable cache offset")
eq(m.MEMTABLE_FLUSH_JOB_INFO_OFFSET, 0xCD8, "memtable flush job info offset")

# --- sort / dedup ----------------------------------------------------
eq(m.sort_index([]), [], "sort empty")
eq(m.sort_index([("b", 2)]), [("b", 2)], "sort single")
eq(m.sort_index([("b", 2), ("a", 1)]), [("a", 1), ("b", 2)], "sort two")
eq(m.sort_index([("a", 2), ("a", 1)]), [("a", 1), ("a", 2)], "sort by seq")
eq(m.sort_index([(3, 1), (1, 9), (1, 2), (2, 0)]),
   [(1, 2), (1, 9), (2, 0), (3, 1)], "sort mixed")
eq(m.dedup_sorted([]), [], "dedup empty")
eq(m.dedup_sorted([("a", 1)]), [("a", 1)], "dedup single")
eq(m.dedup_sorted([("a", 1), ("a", 1)]), [("a", 1)], "dedup adjacent dup")
eq(m.dedup_sorted([("a", 1), ("a", 2)]), [("a", 1), ("a", 2)], "dedup same key diff seq kept")
eq(m.dedup_sorted([("a", 1), ("b", 1), ("a", 1)]),
   [("a", 1), ("b", 1), ("a", 1)], "dedup only adjacent")
eq(m.dedup_sorted(m.sort_index([("b", 2), ("a", 1), ("a", 1), ("b", 2)])),
   [("a", 1), ("b", 2)], "sort then dedup")
eq(m.depth_limit(0), -2, "depth limit 0")
eq(m.depth_limit(1), 0, "depth limit 1")
eq(m.depth_limit(2), 2, "depth limit 2")
eq(m.depth_limit(16), 8, "depth limit 16")
eq(m.depth_limit(17), 8, "depth limit 17")
eq(m.depth_limit(32), 10, "depth limit 32")
eq(m.depth_limit(256), 16, "depth limit 256")

# --- dispose: flag-set path ------------------------------------------
c = m.Cache(entries=[("b", 2), ("a", 1), ("a", 1)], chain=[1, 2, 3],
            list_head=[1], tree={"id": 1},
            buffers={"+0x30": 1, "+0x18": 2, "+0x00": 3})
c.flag_set = True
trace = m.dispose(c, flag_set=True)
eq(trace[0], "sort_dedup_invoke", "dispose flag path first step")
eq(trace[-1], "delete_0xe8", "dispose flag path last step")
eq(trace, ["sort_dedup_invoke", "chain_walked", "free_index_array",
           "do_cleanup", "walk_0x80_list", "release_0x60_tree",
           "free_buffers", "delete_0xe8"], "dispose flag path full trace")
check(c.freed, "dispose flag path frees the block")
check(not c.flag_set, "dispose flag path clears the flag")
eq(c.index, [("a", 1), ("b", 2)], "dispose flag path sorted+deduped index")
eq(c.invoked, [("a", 1), ("b", 2)], "dispose flag path invoked entries")
eq(c.chain, [], "dispose flag path empties the chain")
eq(c.list_head, [], "dispose flag path empties the 0x80 list")
check(c.tree is None, "dispose flag path releases the tree")
eq(c.buffers, {}, "dispose flag path frees the buffers")

# --- dispose: free-array path ----------------------------------------
c = m.Cache(entries=[("a", 1)], chain=[1], list_head=[1], tree={"id": 1},
            buffers={"+0x30": 1})
trace = m.dispose(c, flag_set=False)
eq(trace[0], "free_array", "dispose free-array first step")
eq(trace[-1], "delete_0xe8", "dispose free-array last step")
check("sort_dedup_invoke" not in trace, "dispose free-array skips sort")
check("do_cleanup" in trace, "dispose free-array still does cleanup")
check("walk_0x80_list" in trace, "dispose free-array walks the list")
check("release_0x60_tree" in trace, "dispose free-array releases tree")
check(c.freed, "dispose free-array frees the block")
eq(c.invoked, [], "dispose free-array invokes nothing")
eq(c.chain, [1], "dispose free-array leaves the chain alone")

# --- dispose: null list ------------------------------------------------
c = m.Cache(entries=None)
eq(m.dispose(c, flag_set=True), ["return_null_list"], "dispose null list")
check(not c.freed, "dispose null list frees nothing")

# --- dispose: cleanable head runs --------------------------------------
called = []
c = m.Cache(entries=[("a", 1)], cleanable_head=[lambda: called.append(1),
                                                lambda: called.append(2)])
m.dispose(c, flag_set=False)
eq(called, [1, 2], "dispose runs the cleanable head in order")

# --- dispose: empty index with flag set --------------------------------
c = m.Cache(entries=[], index=[])
trace = m.dispose(c, flag_set=True)
eq(trace[0], "sort_dedup_invoke", "dispose empty index still sorts")
eq(c.invoked, [], "dispose empty index invokes nothing")
check(c.freed, "dispose empty index frees the block")

# --- unique_ptr<List> dtor ----------------------------------------------
c1 = m.Cache(entries=[("b", 2), ("a", 1)])
c2 = m.Cache(entries=[("b", 2), ("a", 1)])
t1 = m.dispose(c1, flag_set=True)
t2 = m.unique_ptr_list_dtor(c2, flag_set=True)
eq(t1, t2, "unique_ptr dtor trace matches dispose trace")
eq(c2.invoked, [("a", 1), ("b", 2)], "unique_ptr dtor invokes entries")
c3 = m.Cache(entries=[("a", 1)])
t3 = m.unique_ptr_list_dtor(c3, flag_set=False)
eq(t3[0], "free_array", "unique_ptr dtor free-array path")

# --- AllocTracker --------------------------------------------------------
wbm = m.WriteBufferManager(first=100, second=50, has_cache=False)
trk = m.AllocTracker(manager=wbm, amount=30)
eq(trk.done_allocating(), "done", "done_allocating first call")
check(trk.done, "done_allocating sets done")
eq(wbm.second, 20, "done_allocating subtracts from second counter")
eq(trk.done_allocating(), "already_done", "done_allocating idempotent")
eq(wbm.second, 20, "done_allocating second call changes nothing")

trk2 = m.AllocTracker(manager=wbm, amount=10)
eq(trk2.free_mem(), "freed", "free_mem first call")
check(trk2.done, "free_mem calls done_allocating first")
check(trk2.freed, "free_mem sets freed")
eq(wbm.first, 90, "free_mem subtracts from first counter")
eq(trk2.free_mem(), "already_freed", "free_mem idempotent")
eq(wbm.first, 90, "free_mem second call changes nothing")

trk3 = m.AllocTracker(manager=None, amount=5)
eq(trk3.done_allocating(), "no_manager", "done_allocating no manager")
eq(trk3.free_mem(), "no_manager", "free_mem no manager")
check(not trk3.freed, "free_mem no manager does not set freed")

# lazy DoneAllocating from FreeMem
wbm2 = m.WriteBufferManager(first=40, second=40, has_cache=False)
trk4 = m.AllocTracker(manager=wbm2, amount=15)
check(not trk4.done, "tracker starts not done")
eq(trk4.free_mem(), "freed", "free_mem with lazy done")
check(trk4.done, "free_mem set done lazily")
eq(wbm2.second, 25, "lazy done subtracted from second counter")
eq(wbm2.first, 25, "free_mem subtracted from first counter")

# --- WriteBufferManager --------------------------------------------------
wbm3 = m.WriteBufferManager(first=80, second=80, has_cache=True)
eq(wbm3.free_mem(25), "free_mem_with_cache", "wbm cache path")
check(wbm3.cache_freed, "wbm cache path frees the cache")
check(wbm3.stall_checked, "wbm cache path checks the stall")
eq(wbm3.first, 80, "wbm cache path does not touch first counter")
wbm4 = m.WriteBufferManager(first=0, second=0, has_cache=False)
eq(wbm4.free_mem(25), "atomic_sub_first", "wbm no-cache zero-first path")
eq(wbm4.first, 0, "wbm no-cache zero-first leaves counter at 0")
check(wbm4.stall_checked, "wbm no-cache path checks the stall")
eq(wbm4.done_allocating_amount(10), "no_manager", "wbm 0x606a110 no manager")
wbm5 = m.WriteBufferManager(first=60, second=70, has_cache=False)
eq(wbm5.done_allocating_amount(10), "atomic_sub_second", "wbm 0x606a110 path")
eq(wbm5.second, 60, "wbm 0x606a110 subtracts from second counter")

# --- shared_ptr release chain --------------------------------------------
cache = m.Cache(entries=[("b", 2), ("a", 1)])
cache.flag_set = True
chain = m.SharedPtrChain(cache, use_count=1, weak_count=1)
res = chain.inner_dispose()
eq(res[0], "cache_dispose", "inner dispose reaches cache dispose")
eq(res[-1], "cache_destroy", "inner dispose ends with cache destroy")
check(chain.destroyed, "inner dispose destroys the cache block")
check(cache.freed, "inner dispose frees the cache")
eq(cache.invoked, [("a", 1), ("b", 2)], "inner dispose invokes entries")
eq(chain.inner_dispose(), "already_released", "inner dispose second call")

chain2 = m.SharedPtrChain(m.Cache(entries=[("a", 1)]), use_count=3, weak_count=1)
eq(chain2.inner_dispose(), "decremented", "inner dispose decrement path")
eq(chain2.use_count, 2, "inner dispose decrements the use count")
check(not chain2.destroyed, "inner dispose decrement does not destroy")

# --- RB-erase --------------------------------------------------------------
def node(i, left=None, right=None):
    return {"id": i, "left": left, "right": right}

eq(m.rb_erase(None, 0x30), [], "rb-erase empty 0x30")
eq(m.rb_erase(None, 0x60), [], "rb-erase empty 0x60")
eq(m.rb_erase(node(1), 0x30), [1], "rb-erase single 0x30")
eq(m.rb_erase(node(1), 0x60), [1], "rb-erase single 0x60")
tree = node(1, left=node(2), right=node(3, left=node(4), right=node(5)))
eq(m.rb_erase(tree, 0x30), [5, 3, 4, 1, 2],
   "rb-erase right-first order 0x30")
tree = node(1, left=node(2), right=node(3, left=node(4), right=node(5)))
eq(m.rb_erase(tree, 0x60), [5, 3, 4, 1, 2],
   "rb-erase right-first order 0x60")
deep = node(1, right=node(2, right=node(3, right=node(4))))
eq(m.rb_erase(deep, 0x30), [4, 3, 2, 1], "rb-erase right chain")
lefty = node(1, left=node(2, left=node(3)))
eq(m.rb_erase(lefty, 0x60), [1, 2, 3], "rb-erase left chain")

# --- FlushJobInfo -----------------------------------------------------------
info = {"strings": ["s%d" % i for i in range(13)],
        "maps": ["+0x2d0", "+0x300"], "vector_len": 3}
trace = m.destroy_flush_job_info(info)
eq(len([t for t in trace if t.startswith("dispose_string:")]), 13,
   "flush job info disposes 13 strings")
eq(len([t for t in trace if t.startswith("erase_map:")]), 2,
   "flush job info erases 2 maps")
eq(len([t for t in trace if t.startswith("destroy_vector_element:")]), 3,
   "flush job info destroys 3 vector elements")
eq(trace[-1], "delete_0x340", "flush job info ends with 0x340 delete")
eq(m.destroy_flush_job_info({"strings": [], "maps": [], "vector_len": 0}),
   ["delete_0x340"], "flush job info empty")

# --- MemTable dtor order ------------------------------------------------------
order = m.memtable_dtor_order()
eq(len(order), 18, "memtable dtor order length")
eq(order[0], "alloc_tracker_free_mem", "memtable dtor starts with FreeMem")
eq(order[1], "core_local_array_release", "memtable dtor second is array release")
eq(order[2], "cache_teardown", "memtable dtor third is cache teardown")
eq(order[3], "flush_job_info_destroy", "memtable dtor fourth is FlushJobInfo")
eq(order[12], "destroy_b40_rbtree", "memtable dtor RB-tree step")
eq(order[15], "rep_slot_88_calls", "memtable dtor rep step")
eq(order[16], "concurrent_arena_destroy", "memtable dtor arena step")
eq(order[17], "alloc_tracker_dtor", "memtable dtor ends with tracker dtor")
check("cache_teardown" in order and "flush_job_info_destroy" in order,
      "memtable dtor covers cache and flush job info")
check(order.index("cache_teardown") < order.index("flush_job_info_destroy"),
      "memtable dtor cache before flush job info")
check(order.index("destroy_b40_rbtree") < order.index("rep_slot_88_calls"),
      "memtable dtor tree before reps")

# --- ConcurrentArena -----------------------------------------------------------
arena = {"blocks": [1, 2]}
eq(m.concurrent_arena_d1(arena),
   ["install_arena_vtable", "arena_dtor", "delete_array_blocks"],
   "arena D1 with blocks")
eq(m.concurrent_arena_d1({"blocks": None}),
   ["install_arena_vtable", "arena_dtor"], "arena D1 without blocks")
eq(m.concurrent_arena_d0(arena)[-1], "delete_0x9b0", "arena D0 deletes 0x9b0")
eq(len(m.concurrent_arena_d0(arena)), 4, "arena D0 trace length")

# --- records.json cross-check ---------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
records = json.load(open(os.path.join(
    ROOT, "research/work-items/RE-001-tombstone-cache-destruction-115",
    "records.json")))
eq(records["task_id"], "RE-001", "records task id")
eq(records["artifact_sha256"],
   "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301",
   "records digest")
eq(len(records["windows"]), 17, "records window count")
addrs = {w["address"] for w in records["windows"]}
for a in ["0x5f061b0", "0x5f0b080", "0x5f10d40", "0x605e8a0", "0x605e860",
          "0x606a890", "0x5f0a290", "0x5f10180", "0x5f10d00", "0x5f05b80",
          "0x5f06770", "0x5ecd650"]:
    check(a in addrs, "records has window " + a)
eq(len(records["census"]), 13, "records census target count")
eq(len(records["callers"]["0x5f10d40"]), 15, "memtable dtor has 15 callers")
eq(records["census"]["0x5f061b0"]["relative_slots"], ["0x64cc728"],
   "dispose reached only via its vtable slot")
eq(records["census"]["0x5f0b080"]["direct_calls"], ["0x5f1021b"],
   "unique_ptr dtor has one standalone caller")
eq(records["vtables"]["cache_control_block"]["slots"]["2"], "0x5f061b0",
   "cache control block slot 2 is the dispose")
eq(records["vtables"]["skiplist_rep"]["slots"]["17"], "0x6063010",
   "skiplist rep slot 17 is the 0x58 delete stub")
eq(len(records["vtables"]["skiplist_rep"]["slots"]), 23,
   "skiplist rep has 23 slots")
check(len(records["unknowns"]) >= 5, "records lists the open unknowns")
check(records["behaviours"]["cache_dispose"]["list_size"] == "0xe8",
   "records cache list size")

print("%d tests passed" % CHECKS)
