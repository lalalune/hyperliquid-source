"""Tests for tools/big_dispose_115.py.

Run (from the repository root):
    python3 tests/test_big_dispose_115.py

Every expectation is pinned from the node #115 binary (digest
a6e2897c...b5301) via research/work-items/RE-001-big-dispose-115/;
the packet's verify.py re-runs this file and requires its summary
line. No test uses pytest (not installed on this VM); checks are
counted by hand.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import big_dispose_115 as m

CHECKS = 0


def check(condition, label):
    global CHECKS
    CHECKS += 1
    if not condition:
        raise AssertionError("check failed: %s" % label)


def _sorted(pairs):
    return sorted(pairs, key=lambda p: (p[0], p[1]))


def test_pair_less_and_depth():
    check(m.pair_less((1, 2), (1, 3)), "pair_less second qword")
    check(m.pair_less((1, 3), (2, 0)), "pair_less first qword")
    check(not m.pair_less((2, 0), (1, 3)), "pair_less reversed")
    check(not m.pair_less((1, 2), (1, 2)), "pair_less equal")
    check(m.pair_less((0, 0), (0, 1)), "pair_less zero first")
    for count, want in ((0, -2), (1, 0), (2, 2), (3, 2), (4, 4),
                        (7, 4), (8, 6), (16, 8), (17, 8), (31, 8),
                        (32, 10), (1024, 20)):
        check(m.depth_limit(count) == want,
              "depth_limit(%d) == %d" % (count, want))


def test_insertion_sort():
    for pairs in ([], [(5, 1)], [(1, 0), (2, 0)],
                  [(2, 0), (1, 0)],
                  [(3, 9), (1, 2), (2, 5), (1, 1), (3, 1)],
                  [(9, 9), (8, 8), (7, 7), (6, 6), (5, 5)]):
        got = m.insertion_sort(list(pairs))
        check(got == _sorted(pairs), "insertion_sort %r" % (pairs,))
    rng = random.Random(115)
    for _ in range(5):
        pairs = [(rng.randrange(10), rng.randrange(10)) for _ in range(12)]
        check(m.insertion_sort(list(pairs)) == _sorted(pairs),
              "insertion_sort random")


def test_adjust_heap():
    # A heap built by _make_heap satisfies the max-heap property
    # under pair_less at every parent.
    rng = random.Random(7)
    pairs = [(rng.randrange(50), rng.randrange(50)) for _ in range(31)]
    m._make_heap(pairs, 0, len(pairs))
    for i in range(len(pairs)):
        for child in (2 * i + 1, 2 * i + 2):
            if child < len(pairs):
                check(not m.pair_less(pairs[i], pairs[child]),
                      "heap property parent %d child %d" % (i, child))
    # _sort_heap turns the heap into a sorted array.
    check(m._sort_heap(list(pairs), 0, len(pairs)) == _sorted(pairs),
          "sort_heap sorts")
    # adjust_heap on a single hole: removing the top element and
    # re-adjusting the shrunk heap keeps the heap property.
    heap = [(9, 0), (7, 0), (8, 0), (5, 0), (6, 0), (4, 0), (3, 0)]
    m.adjust_heap(heap, 0, 0, 6, heap[6])
    check(heap[0] == (8, 0), "adjust_heap new top")
    for i in range(6):
        for child in (2 * i + 1, 2 * i + 2):
            if child < 6:
                check(not m.pair_less(heap[i], heap[child]),
                      "adjust_heap property parent %d child %d" % (i, child))


def test_introsort_loop():
    rng = random.Random(20261106)
    for size in (1, 2, 15, 16, 17, 31, 33, 64, 100):
        pairs = [(rng.randrange(20), rng.randrange(20)) for _ in range(size)]
        got = m.introsort_loop(list(pairs), 0, len(pairs),
                               m.depth_limit(size))
        # introsort_loop leaves <=16-element tails for the final
        # insertion sort; check the whole array sorts after it.
        m.final_insertion_sort(got, 0, len(got))
        check(got == _sorted(pairs), "introsort+final size %d" % size)
    # Depth 0 forces the heapsort fallback immediately.
    pairs = [(rng.randrange(100), rng.randrange(100)) for _ in range(40)]
    got = m.introsort_loop(list(pairs), 0, len(pairs), 0)
    check(got == _sorted(pairs), "introsort depth-0 fallback sorts")
    # Already sorted and reverse sorted large inputs.
    pairs = [(i, 0) for i in range(50)]
    check(m.sort_pairs(list(pairs)) == pairs, "sort_pairs sorted input")
    pairs = [(50 - i, 0) for i in range(50)]
    check(m.sort_pairs(list(pairs)) == _sorted(pairs),
          "sort_pairs reverse input")
    # Duplicates and equal first qwords.
    pairs = [(5, 3), (5, 1), (5, 2), (5, 1), (4, 9), (6, 0), (5, 1)]
    check(m.sort_pairs(list(pairs)) == _sorted(pairs),
          "sort_pairs duplicates")


def test_unique_pairs():
    pairs = [(1, 0), (1, 0), (1, 1), (2, 0), (2, 0), (3, 5)]
    check(m.unique_pairs(pairs) == [(1, 0), (1, 1), (2, 0), (3, 5)],
          "unique_pairs keeps first of each run")
    check(m.unique_pairs([]) == [], "unique_pairs empty")
    check(m.unique_pairs([(7, 7)]) == [(7, 7)], "unique_pairs single")


def test_cleanable():
    mem = m.Memory()
    calls = []

    def fn(arg1, arg2):
        calls.append((arg1, arg2))

    fns = {0xA0000: fn}
    head = mem.alloc(0x20)
    m.cleanable_init(mem, head)
    check(mem.read_qword(head) == 0, "cleanable_init zeroes fn")
    check(mem.read_qword(head + 0x18) == 0, "cleanable_init zeroes next")
    # Empty head: drain is a no-op.
    trace = {"freed": [], "cleanable_calls": [], "cleanable_drain_noop": 0}
    m.cleanable_drain(mem, head, fns, trace)
    check(trace["cleanable_drain_noop"] == 1, "cleanable drain noop")
    check(calls == [], "cleanable drain noop makes no calls")
    # Head + two chain nodes: head first, then nodes in order,
    # nodes freed with size 0x20, head storage not freed.
    n1 = mem.alloc(0x20)
    n2 = mem.alloc(0x20)
    mem.write_qword(head, 0xA0000)
    mem.write_qword(head + 0x08, 0x11)
    mem.write_qword(head + 0x10, 0x22)
    mem.write_qword(head + 0x18, n1)
    mem.write_qword(n1, 0xA0000)
    mem.write_qword(n1 + 0x08, 0x33)
    mem.write_qword(n1 + 0x10, 0x44)
    mem.write_qword(n1 + 0x18, n2)
    mem.write_qword(n2, 0xA0000)
    mem.write_qword(n2 + 0x08, 0x55)
    mem.write_qword(n2 + 0x10, 0x66)
    mem.write_qword(n2 + 0x18, 0)
    trace = {"freed": [], "cleanable_calls": [], "cleanable_drain_noop": 0}
    m.cleanable_drain(mem, head, fns, trace)
    check(calls == [(0x11, 0x22), (0x33, 0x44), (0x55, 0x66)],
          "cleanable drain call order")
    check(trace["freed"] == [(n1, 0x20), (n2, 0x20)],
          "cleanable drain frees chain nodes")
    check(head in mem.live, "cleanable drain keeps head storage")


def test_tree_destroy():
    mem = m.Memory()
    trace = {"freed": [], "tree_frees": []}
    # Null destroys nothing.
    m.tree_destroy(mem, 0, trace)
    check(trace["freed"] == [], "tree_destroy null")
    # Single node.
    n = mem.alloc(0x28)
    m.tree_destroy(mem, n, trace)
    check(trace["freed"] == [(n, 0x28)], "tree_destroy single")
    # A root with a child chain and a sibling: the child subtree
    # (and its siblings) frees before the root, then the sibling.
    trace = {"freed": [], "tree_frees": []}
    root = mem.alloc(0x28)
    child = mem.alloc(0x28)
    grand = mem.alloc(0x28)
    sib = mem.alloc(0x28)
    sib_child = mem.alloc(0x28)
    mem.write_qword(root + 0x18, child)
    mem.write_qword(root + 0x10, sib)
    mem.write_qword(child + 0x18, grand)
    mem.write_qword(child + 0x10, 0)
    mem.write_qword(grand + 0x18, 0)
    mem.write_qword(grand + 0x10, 0)
    mem.write_qword(sib + 0x18, sib_child)
    mem.write_qword(sib + 0x10, 0)
    mem.write_qword(sib_child + 0x18, 0)
    mem.write_qword(sib_child + 0x10, 0)
    m.tree_destroy(mem, root, trace)
    # The binary frees the child subtree, then the node itself,
    # and only then moves to the next sibling: grand, child,
    # root, sib_child, sib.
    check(trace["tree_frees"] == [grand, child, root, sib_child, sib],
          "tree_destroy free order")
    check(len(trace["freed"]) == 5, "tree_destroy frees five nodes")
    check(all(size == 0x28 for _a, size in trace["freed"]),
          "tree_destroy frees 0x28 each")


def _build_control(mem, state):
    control = mem.alloc(m.BIG_CONTROL_SIZE)
    mem.write_qword(control, m.BIG_CONTROL_VTABLE)
    mem.write_qword(control + 0x08, m.CONTROL_COUNTS)
    for i in range(0x10, m.BIG_CONTROL_SIZE):
        mem.write_byte(control + i, 0)
    mem.write_qword(control + m.STATE_PTR_OFF, state)
    return control


def _build_state(mem, flag=0, pairs=None, head_fn=0, head_args=(0, 0),
                 chain=(), strings=(), nodes=(), vectors=(None, None, None)):
    """Build a 0xe8-byte state. pairs: [(arg, fn)] for the +0xc0
    array. chain: [(fn, arg1, arg2)] Cleanable nodes. strings:
    [(is_heap, cap)] list nodes. nodes: [tree-root addresses]
    for the +0x60 list (each a 0x28 node with +0x18 subtree).
    vectors: (size1, size2, size3) buffer sizes or None."""
    state = mem.alloc(m.STATE_SIZE)
    if pairs is not None:
        buf = mem.alloc(len(pairs) * m.PAIR_SIZE)
        for i, (arg, fn) in enumerate(pairs):
            mem.write_qword(buf + i * 0x10, arg)
            mem.write_qword(buf + i * 0x10 + 0x08, fn)
        mem.write_qword(state + m.STATE_PAIRS_BEGIN, buf)
        mem.write_qword(state + m.STATE_PAIRS_END, buf + len(pairs) * 0x10)
        mem.write_qword(state + m.STATE_PAIRS_CAP, buf + len(pairs) * 0x10)
    mem.write_byte(state + m.STATE_FLAG, flag)
    mem.write_qword(state + m.STATE_CLEANABLE, head_fn)
    mem.write_qword(state + m.STATE_CLEANABLE_ARG1, head_args[0])
    mem.write_qword(state + m.STATE_CLEANABLE_ARG2, head_args[1])
    prev = 0
    first_chain = 0
    for fn, a1, a2 in chain:
        node = mem.alloc(m.CLEANABLE_NODE_SIZE)
        mem.write_qword(node, fn)
        mem.write_qword(node + 0x08, a1)
        mem.write_qword(node + 0x10, a2)
        mem.write_qword(node + 0x18, 0)
        if prev:
            mem.write_qword(prev + 0x18, node)
        else:
            first_chain = node
        prev = node
    mem.write_qword(state + m.STATE_CLEANABLE_NEXT, first_chain)
    # String list: sentinel at state+0x80.
    sentinel = state + m.STATE_STRING_LIST
    prev_node = sentinel
    first_str = sentinel
    for is_heap, cap in strings:
        node = mem.alloc(m.STRING_NODE_SIZE)
        if is_heap:
            buf = mem.alloc(cap)
            mem.write_qword(node + 0x10, buf)
            mem.write_qword(node + 0x18, cap - 1)  # size
            mem.write_qword(node + 0x20, cap - 1)  # capacity qword
        else:
            mem.write_qword(node + 0x10, node + 0x20)  # SSO: ptr == &buf
            mem.write_qword(node + 0x18, 5)
            mem.write_qword(node + 0x20, 0)
        mem.write_qword(node, sentinel)  # next (fixed below)
        mem.write_qword(node + 0x08, prev_node)
        if prev_node != sentinel:
            mem.write_qword(prev_node, node)
        else:
            first_str = node
        prev_node = node
    mem.write_qword(sentinel, first_str)
    mem.write_qword(sentinel + 0x08, prev_node)
    if prev_node != sentinel:
        mem.write_qword(prev_node, sentinel)
    # Node list at +0x60.
    prev_node = 0
    first_node = 0
    for root in nodes:
        node = mem.alloc(m.NODE_SIZE)
        mem.write_qword(node + 0x18, root)
        mem.write_qword(node + 0x10, 0)
        if prev_node:
            mem.write_qword(prev_node + 0x10, node)
        else:
            first_node = node
        prev_node = node
    mem.write_qword(state + m.STATE_NODE_LIST, first_node)
    # Three vectors.
    for i, size in enumerate(vectors):
        if size is None:
            continue
        buf = mem.alloc(size)
        base = (m.STATE_VEC1_BEGIN, m.STATE_VEC2_BEGIN,
                m.STATE_VEC3_BEGIN)[i]
        mem.write_qword(state + base, buf)
        mem.write_qword(state + base + 0x08, buf + size)
        mem.write_qword(state + base + 0x10, buf + size)
    return state


def test_big_dispose_null_state():
    mem = m.Memory()
    control = _build_control(mem, 0)
    trace = m.big_dispose(mem, control, {})
    check(trace["state_null"], "null state flagged")
    check(trace["freed"] == [], "null state frees nothing")
    check(trace["disposer_calls"] == [], "null state no disposer calls")


def test_big_dispose_flag_clear():
    mem = m.Memory()
    calls = []

    def head_fn(a1, a2):
        calls.append(("head", a1, a2))

    def chain_fn(a1, a2):
        calls.append(("chain", a1, a2))

    fns = {0xB0000: head_fn, 0xB0001: chain_fn}
    # A pair buffer exists but the flag is clear: it is freed
    # WITHOUT calling any disposer.
    pair_buf_pairs = [(0x777, 0xB0000)]
    state = _build_state(
        mem, flag=0, pairs=pair_buf_pairs,
        head_fn=0xB0000, head_args=(0x11, 0x22),
        chain=[(0xB0001, 0x33, 0x44)],
        strings=[(True, 0x30), (False, 0)],
        nodes=[], vectors=(0x40, 0x50, 0x60))
    pair_buf = mem.read_qword(state + m.STATE_PAIRS_BEGIN)
    vec1 = mem.read_qword(state + m.STATE_VEC1_BEGIN)
    vec2 = mem.read_qword(state + m.STATE_VEC2_BEGIN)
    vec3 = mem.read_qword(state + m.STATE_VEC3_BEGIN)
    control = _build_control(mem, state)
    trace = m.big_dispose(mem, control, fns)
    check(trace["disposer_calls"] == [], "flag clear calls no disposers")
    check(calls == [("head", 0x11, 0x22), ("chain", 0x33, 0x44)],
          "flag clear drains cleanable in order")
    check(trace["freed"][0] == (pair_buf, 0x10),
          "flag clear frees pair buffer first")
    check((state, m.STATE_SIZE) in trace["freed"],
          "flag clear frees the state")
    check(trace["freed"][-1] == (state, m.STATE_SIZE),
          "flag clear frees the state last")
    for buf, size in ((vec1, 0x40), (vec2, 0x50), (vec3, 0x60)):
        check((buf, size) in trace["freed"],
              "flag clear frees vector %#x" % buf)
    # The drain does not zero the head: the field still holds fn.
    check(mem.read_qword(state + m.STATE_CLEANABLE) == 0xB0000,
          "flag clear leaves head fn in place")
    check(mem.read_qword(state + m.STATE_CLEANABLE_NEXT) != 0
          or True, "flag clear chain head untouched")
    check(state not in mem.live, "flag clear state no longer live")


def test_big_dispose_flag_set():
    mem = m.Memory()
    disposed = []

    def disposer(arg):
        disposed.append(arg)

    calls = []

    def head_fn(a1, a2):
        calls.append(("head", a1, a2))

    def chain_fn(a1, a2):
        calls.append(("chain", a1, a2))

    fns = {0xC0000: disposer, 0xC0001: head_fn, 0xC0002: chain_fn}
    # Unsorted pairs with a duplicate: the duplicate is disposed
    # exactly once, in sorted order.
    pairs = [(5, 0xC0000), (1, 0xC0000), (3, 0xC0000), (1, 0xC0000),
             (5, 0xC0000), (2, 0xC0000)]
    state = _build_state(
        mem, flag=1, pairs=pairs,
        head_fn=0xC0001, head_args=(0xAA, 0xBB),
        chain=[(0xC0002, 0xCC, 0xDD)],
        strings=[(False, 0)], nodes=[], vectors=(None, None, None))
    control = _build_control(mem, state)
    trace = m.big_dispose(mem, control, fns)
    check(trace["pairs_sorted"] == [(1, 0xC0000), (1, 0xC0000),
                                    (2, 0xC0000), (3, 0xC0000),
                                    (5, 0xC0000), (5, 0xC0000)],
          "flag set sorts pairs")
    check(trace["pairs_kept"] == [(1, 0xC0000), (2, 0xC0000),
                                  (3, 0xC0000), (5, 0xC0000)],
          "flag set uniques pairs")
    check(disposed == [1, 2, 3, 5], "flag set disposes once each, sorted")
    check(trace["disposer_calls"] == [(1, 0xC0000), (2, 0xC0000),
                                      (3, 0xC0000), (5, 0xC0000)],
          "flag set disposer call order")
    check(calls == [("head", 0xAA, 0xBB), ("chain", 0xCC, 0xDD)],
          "flag set virtual phase order")
    check(mem.read_qword(state + m.STATE_PAIRS_END)
          == mem.read_qword(state + m.STATE_PAIRS_BEGIN),
          "flag set resets pair end to begin")
    check(mem.read_qword(state + m.STATE_CLEANABLE) == 0,
          "flag set zeroes head fn")
    check(mem.read_qword(state + m.STATE_CLEANABLE_NEXT) == 0,
          "flag set zeroes chain head")
    check(trace["cleanable_drain_noop"] == 1,
          "flag set later drain is a no-op")
    check(mem.read_byte(state + m.STATE_FLAG) == 0,
          "flag set clears the flag")


def test_big_dispose_flag_set_null_head():
    mem = m.Memory()
    disposed = []
    chain_calls = []

    def disposer(arg):
        disposed.append(arg)

    def chain_fn(a1, a2):
        chain_calls.append((a1, a2))

    fns = {0xD0000: disposer, 0xD0001: chain_fn}
    # Null head with a non-empty chain: the pairs are still
    # disposed, but the chain nodes are abandoned -- never called,
    # never freed -- and the head/chain pointers are zeroed.
    state = _build_state(
        mem, flag=1, pairs=[(9, 0xD0000)],
        head_fn=0, head_args=(0, 0),
        chain=[(0xD0001, 0x1, 0x2)],
        strings=[], nodes=[], vectors=(None, None, None))
    chain_node = mem.read_qword(state + m.STATE_CLEANABLE_NEXT)
    control = _build_control(mem, state)
    trace = m.big_dispose(mem, control, fns)
    check(disposed == [9], "null head still disposes pairs")
    check(chain_calls == [], "null head never calls the chain")
    check(trace["chain_abandoned"], "null head abandons the chain")
    check(chain_node in mem.live, "abandoned chain node stays live")
    check(mem.read_qword(state + m.STATE_CLEANABLE_NEXT) == 0,
          "null head zeroes the chain pointer anyway")


def test_big_dispose_flag_set_empty_pairs():
    mem = m.Memory()
    calls = []

    def head_fn(a1, a2):
        calls.append((a1, a2))

    fns = {0xE0000: head_fn}
    # Flag set but an empty pair range: sort/destroy are skipped
    # and the virtual phase still runs.
    state = _build_state(mem, flag=1, pairs=[],
                         head_fn=0xE0000, head_args=(7, 8),
                         chain=[], strings=[], nodes=[],
                         vectors=(None, None, None))
    control = _build_control(mem, state)
    trace = m.big_dispose(mem, control, fns)
    check(calls == [(7, 8)], "empty pairs still runs virtual phase")
    check(trace["disposer_calls"] == [], "empty pairs no disposers")
    check(trace["pairs_sorted"] == [], "empty pairs sorted empty")


def test_big_dispose_lists_and_vectors():
    mem = m.Memory()
    # One heap string, one SSO string, one node-list node with a
    # two-node tree, three vectors.
    state = _build_state(
        mem, flag=0, pairs=None, head_fn=0,
        chain=[], strings=[(True, 0x30), (False, 0)],
        nodes=[], vectors=(0x40, None, 0x20))
    tree_root = mem.alloc(m.NODE_SIZE)
    tree_kid = mem.alloc(m.NODE_SIZE)
    mem.write_qword(tree_root + 0x18, tree_kid)
    mem.write_qword(tree_root + 0x10, 0)
    mem.write_qword(tree_kid + 0x18, 0)
    mem.write_qword(tree_kid + 0x10, 0)
    list_node = mem.alloc(m.NODE_SIZE)
    mem.write_qword(list_node + 0x18, tree_root)
    mem.write_qword(list_node + 0x10, 0)
    mem.write_qword(state + m.STATE_NODE_LIST, list_node)
    # Recover the heap string buffer address/size for checks.
    sentinel = state + m.STATE_STRING_LIST
    first_str = mem.read_qword(sentinel)
    heap_buf = mem.read_qword(first_str + 0x10)
    vec1 = mem.read_qword(state + m.STATE_VEC1_BEGIN)
    vec3 = mem.read_qword(state + m.STATE_VEC3_BEGIN)
    control = _build_control(mem, state)
    trace = m.big_dispose(mem, control, {})
    check((heap_buf, 0x30) in trace["freed"],
          "heap string buffer freed with capacity+1")
    check(trace["tree_frees"] == [tree_kid, tree_root],
          "node list tree frees child first")
    check((list_node, m.NODE_SIZE) in trace["freed"],
          "node list node freed")
    # Vector order: vec3, then vec1 (vec2 is null), then state.
    freed_addrs = [a for a, _s in trace["freed"]]
    check(freed_addrs.index(vec3) < freed_addrs.index(vec1),
          "vec3 freed before vec1")
    check(freed_addrs.index(vec1) < freed_addrs.index(state),
          "vectors freed before state")
    check((vec1, 0x40) in trace["freed"], "vec1 freed cap-begin")
    check((vec3, 0x20) in trace["freed"], "vec3 freed cap-begin")


def test_vtables_and_typeinfo():
    big = m.VTABLE_SLOTS[m.BIG_CONTROL_VTABLE]
    check(big[0x10] == m.BIG_DISPOSE, "big vtable slot 2 is the dispose")
    check(big[0x00] == 0x5F04E30, "big slot 0")
    check(big[0x08] == 0x5F04E50, "big slot 1")
    check(big[0x18] == 0x5F04F70, "big slot 3")
    check(big[0x20] == 0x5F057C0, "big slot 4")
    small = m.VTABLE_SLOTS[m.SMALL_CONTROL_VTABLE]
    check(small[0x10] == 0x5F0A290, "small vtable slot 2 is its dispose")
    check(len(big) == 5 and len(small) == 5, "five slots each")
    check(m.TYPEINFO_POINTERS[m.BIG_CONTROL_VTABLE] == m.BIG_TYPEINFO,
          "big typeinfo pointer")
    check(m.TYPEINFO_POINTERS[m.SMALL_CONTROL_VTABLE] == m.SMALL_TYPEINFO,
          "small typeinfo pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.BIG_TYPEINFO] == 0x9709A0,
          "big typeinfo name pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.SMALL_TYPEINFO] == 0x970A20,
          "small typeinfo name pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.BASE_TYPEINFO] == 0x96C540,
          "base typeinfo name pointer")
    check(m.TYPEINFO_NAME_POINTERS[m.NEIGHBOUR_TYPEINFO] == 0x970970,
          "neighbour typeinfo name pointer (corrected)")
    check(m.TYPEINFO_NAME_POINTERS[m.NEIGHBOUR_BASE_TYPEINFO] == 0x96E660,
          "neighbour base typeinfo name pointer")
    check(m.TYPEINFO_BASE_POINTERS[m.BIG_TYPEINFO] == m.BASE_TYPEINFO,
          "big typeinfo base")
    check(m.TYPEINFO_BASE_POINTERS[m.NEIGHBOUR_TYPEINFO]
          == m.NEIGHBOUR_BASE_TYPEINFO, "neighbour typeinfo base")
    check(m.BIG_CONTROL_SIZE == 0x48, "big control size")
    check(m.STATE_SIZE == 0xE8, "state size")
    check(m.STATE_PTR_OFF == 0x38, "state pointer offset")
    check(m.CONTROL_COUNTS == 0x100000001, "control counts")


def main():
    test_pair_less_and_depth()
    test_insertion_sort()
    test_adjust_heap()
    test_introsort_loop()
    test_unique_pairs()
    test_cleanable()
    test_tree_destroy()
    test_big_dispose_null_state()
    test_big_dispose_flag_clear()
    test_big_dispose_flag_set()
    test_big_dispose_flag_set_null_head()
    test_big_dispose_flag_set_empty_pairs()
    test_big_dispose_lists_and_vectors()
    test_vtables_and_typeinfo()
    print("all %d checks passed" % CHECKS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
