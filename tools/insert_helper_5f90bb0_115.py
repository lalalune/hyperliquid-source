"""Python model of node #115's insert helper 0x5f90bb0.

Implements the semantics pinned by
research/work-items/RE-001-insert-helper-5f90bb0-115. The window is
the inlined-insert body of a libstdc++ ``_Hashtable<u64, u64,
Identity, equal_to<u64>, hash<u64>, _Mod_range_hashing,
_Default_ranged_hash, _Prime_rehash_policy, _Hashtable_traits<false,
true, true>>`` (vendor window node115-vendor-5f90bb0; the twin copy
at 0x5da0640 differs only inside relative branch displacement
fields). It takes the table in rdi and a pointer to the key in rsi
(the consumer passes a holder whose first qword is the key) and
returns the node pointer in rax with a flag in dl: 1 when the key
was inserted by this call, 0 when it was already present. The hash
is the identity: the bucket of a key is ``key % bucket_count``
(unsigned divide). Both observed consumers (0x5f90f9c inside walk
0x5f90da0, 0x5f91217 inside getter 0x5f91010) ignore the result.

State shape (plain dict, offsets modelled as addresses):

- ``this`` is implicit. Addresses are integers in a flat space that
  starts at the table base: the before-begin slot owner (the value
  stored in a bucket slot when the bucket's first node is the list
  head) is ``BB = 0x10`` (the address of the +0x10 field itself),
  and the inline single-bucket storage is ``SINGLE = 0x30`` (the
  address of the +0x30 field). Nodes and heap bucket arrays are
  bump-allocated from ``ALLOC_BASE = 0x10000``: 0x10 bytes per node,
  ``8 * count`` bytes per bucket array, sizes rounded up to 16,
  mirroring the harness allocator so model and emulated addresses
  agree one to one.
- ``nodes`` maps a node address to ``{"next": addr | None,
  "key": int}``, mirroring the 16-byte node (next at +0x0, key at
  +0x8).
- ``buckets`` is the list of slot values for the current bucket
  array; a slot is None, ``BB``, or a node address (the node whose
  ``next`` is the bucket's first node). ``buckets_ptr`` is ``SINGLE``
  or the array's allocation address.
- ``bucket_count``, ``element_count``, ``next_resize`` are ints;
  ``max_load_factor`` is the float stored at +0x20 (the model keeps
  the Python float; callers pass values exactly representable in
  binary32).
- ``head`` mirrors the qword at +0x10 (before-begin's next).

The rehash-policy callee ``_M_need_rehash`` (PLT 0x63f0ef0) is an
external libstdc++ function, not a body in this binary; the model
implements the algorithm as executed by the runtime library
(probed against the host ``libstdc++.so.6`` symbol of the same
mangled name over the full test grid): with ``total = element_count
+ n_ins``, if ``total <= next_resize`` the answer is no; otherwise
``min_bkts`` is ``11.0 / max_load_factor`` when ``next_resize == 0``
and ``total <= 10``, else ``total / max_load_factor``; if
``min_bkts < bucket_count`` the answer is no and ``next_resize``
becomes the truncated double product ``bucket_count *
max_load_factor``; else the table grows to the first prime in the
policy list strictly above ``max(int(min_bkts), 2 * bucket_count)``
and ``next_resize`` becomes ``int(new_count * max_load_factor)``.
The prime list below is the policy's list, extracted from the
runtime library's ``__prime_list`` symbol.

The rehash body 0x5da04d0 is modelled on its success path only:
allocate and zero the new array (or reuse the inline slot when the
new count is 1), detach the list, then re-link each node in
original list order - after its bucket's current slot owner when
the slot is taken, otherwise as the new list head with the
previous-bucket slot fixup the body performs - free the old array
unless it was the inline slot, and adopt the new count. Its
exception path (restore ``next_resize`` from the caller's saved
copy and rethrow) and the helper's own cleanup pad are documented
in the packet README and not modelled.

Model-side notes (not binary behavior, stated explicitly): the
binary's empty-count find phase scans the whole list from the head;
on a well-formed table that state (count 0 with nodes present) does
not arise from these operations alone, but the model follows the
binary anyway. The binary's defensive re-test of the found node
pointer for null (0x5f90c34) is unreachable on a well-formed table
and is not modelled. Keys outside the unsigned 64-bit range raise
ValueError, mirroring that the binary field is exactly that wide.
"""

MASK64 = (1 << 64) - 1
BB = 0x10
SINGLE = 0x30
ALLOC_BASE = 0x10000

# The libstdc++ _Prime_rehash_policy prime list, extracted from the
# runtime library's __prime_list symbol (see module docstring).
PRIMES = (
    2, 3, 5, 7, 11, 13,
    17, 19, 23, 29, 31, 37,
    41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89,
    97, 103, 109, 113, 127, 137,
    139, 149, 157, 167, 179, 193,
    199, 211, 227, 241, 257, 277,
    293, 313, 337, 359, 383, 409,
    439, 467, 503, 541, 577, 619,
    661, 709, 761, 823, 887, 953,
    1031, 1109, 1193, 1289, 1381, 1493,
    1613, 1741, 1879, 2029, 2179, 2357,
    2549, 2753, 2971, 3209, 3469, 3739,
    4027, 4349, 4703, 5087, 5503, 5953,
    6427, 6949, 7517, 8123, 8783, 9497,
    10273, 11113, 12011, 12983, 14033, 15173,
    16411, 17749, 19183, 20753, 22447, 24281,
    26267, 28411, 30727, 33223, 35933, 38873,
    42043, 45481, 49201, 53201, 57557, 62233,
    67307, 72817, 78779, 85229, 92203, 99733,
    107897, 116731, 126271, 136607, 147793, 159871,
    172933, 187091, 202409, 218971, 236897, 256279,
    277261, 299951, 324503, 351061, 379787, 410857,
    444487, 480881, 520241, 562841, 608903, 658753,
    712697, 771049, 834181, 902483, 976369, 1056323,
    1142821, 1236397, 1337629, 1447153, 1565659, 1693859,
    1832561, 1982627, 2144977, 2320627, 2510653, 2716249,
    2938679, 3179303, 3439651, 3721303, 4026031, 4355707,
    4712381, 5098259, 5515729, 5967347, 6456007, 6984629,
    7556579, 8175383, 8844859, 9569143, 10352717, 11200489,
    12117689, 13109983, 14183539, 15345007, 16601593, 17961079,
    19431899, 21023161, 22744717, 24607243, 26622317, 28802401,
    31160981, 33712729, 36473443, 39460231, 42691603, 46187573,
    49969847, 54061849, 58488943, 63278561, 68460391, 74066549,
    80131819, 86693767, 93793069, 101473717, 109783337, 118773397,
    128499677, 139022417, 150406843, 162723577, 176048909, 190465427,
    206062531, 222936881, 241193053, 260944219, 282312799, 305431229,
    330442829, 357502601, 386778277, 418451333, 452718089, 489790921,
    529899637, 573292817, 620239453, 671030513, 725980837, 785430967,
    849749479, 919334987, 994618837, 1076067617, 1164186217, 1259520799,
    1362662261, 1474249943, 1594975441, 1725587117, 1866894511, 2019773507,
    2185171673, 2364114217, 2557710269, 2767159799, 2993761039, 3238918481,
    3504151727, 3791104843, 4101556399, 4294967291, 6442450933, 8589934583,
    12884901857, 17179869143, 25769803693, 34359738337, 51539607367, 68719476731,
    103079215087, 137438953447, 206158430123, 274877906899, 412316860387, 549755813881,
    824633720731, 1099511627689, 1649267441579, 2199023255531, 3298534883309, 4398046511093,
    6597069766607, 8796093022151, 13194139533241, 17592186044399, 26388279066581, 35184372088777,
    52776558133177, 70368744177643, 105553116266399, 140737488355213, 211106232532861, 281474976710597,
    562949953421231, 1125899906842597, 2251799813685119, 4503599627370449, 9007199254740881, 18014398509481951,
    36028797018963913, 72057594037927931, 144115188075855859, 288230376151711717, 576460752303423433, 1152921504606846883,
    2305843009213693951, 4611686018427387847, 9223372036854775783, 18446744073709551557,
)

def _u64(value):
    if not 0 <= value <= MASK64:
        raise ValueError("field value %r is outside unsigned 64-bit range" % (value,))
    return value


def next_prime_above(n):
    """First policy-list prime strictly greater than ``n``."""
    for p in PRIMES:
        if p > n:
            return p
    raise ValueError("growth target %r past the modelled prime prefix" % (n,))


def need_rehash(state, n_bkt, n_elt, n_ins):
    """_Prime_rehash_policy::_M_need_rehash as executed by libstdc++.

    Mutates ``state["next_resize"]`` exactly where the library does
    and returns ``(grow, new_bucket_count)``; the count is 0 when
    ``grow`` is False.
    """
    mlf = state["max_load_factor"]
    total = n_elt + n_ins
    if total <= state["next_resize"]:
        return (False, 0)
    if state["next_resize"] == 0 and total <= 10:
        min_bkts = 11.0 / mlf
    else:
        min_bkts = total / mlf
    if min_bkts < n_bkt:
        state["next_resize"] = int(n_bkt * mlf)
        return (False, 0)
    new_count = next_prime_above(max(int(min_bkts), 2 * n_bkt))
    state["next_resize"] = int(new_count * mlf)
    return (True, new_count)


def new_table(max_load_factor=1.0):
    """A default-constructed table: one inline bucket, empty list."""
    return {
        "nodes": {},
        "buckets": [None],
        "buckets_ptr": SINGLE,
        "bucket_count": 1,
        "head": None,
        "element_count": 0,
        "max_load_factor": max_load_factor,
        "next_resize": 0,
        "alloc_next": ALLOC_BASE,
    }


def _alloc(state, size):
    addr = state["alloc_next"]
    state["alloc_next"] = addr + ((size + 15) & ~15)
    return addr


def _slot_next(state, slot):
    if slot == BB:
        return state["head"]
    return state["nodes"][slot]["next"]


def _set_slot_next(state, slot, value):
    if slot == BB:
        state["head"] = value
    else:
        state["nodes"][slot]["next"] = value


def _rehash(state, new_count, saved_state):
    """Rehash body 0x5da04d0, success path (see module docstring).

    ``saved_state`` is the caller's saved ``next_resize``; the body
    reads it only on its exception path, so it is accepted and
    unused here.
    """
    if new_count == 1:
        new_ptr = SINGLE
        new_buckets = [None]
    else:
        new_ptr = _alloc(state, 8 * new_count)
        new_buckets = [None] * new_count
    old_ptr = state["buckets_ptr"]
    node = state["head"]
    state["head"] = None
    prev_bkt = 0
    while node is not None:
        nxt = state["nodes"][node]["next"]
        bkt = state["nodes"][node]["key"] % new_count
        slot = new_buckets[bkt]
        if slot is not None:
            state["nodes"][node]["next"] = _slot_next(state, slot)
            _set_slot_next(state, slot, node)
        else:
            state["nodes"][node]["next"] = state["head"]
            state["head"] = node
            new_buckets[bkt] = BB
            if state["nodes"][node]["next"] is not None:
                new_buckets[prev_bkt] = node
            prev_bkt = bkt
        node = nxt
    # Adopting the new array frees the old one unless it was inline;
    # the addresses stay allocated in the model either way.
    state["buckets"] = new_buckets
    state["buckets_ptr"] = new_ptr
    state["bucket_count"] = new_count


def insert(state, key):
    """Insert helper 0x5f90bb0: insert ``key`` if absent.

    Returns ``(node_address, inserted)`` mirroring the rax/dl pair.
    """
    key = _u64(key)
    nodes = state["nodes"]
    if state["element_count"] != 0:
        bkt = key % state["bucket_count"]
        slot = state["buckets"][bkt]
        if slot is not None:
            node = _slot_next(state, slot)
            while True:
                if nodes[node]["key"] == key:
                    return (node, False)
                nxt = nodes[node]["next"]
                if nxt is None:
                    break
                if nodes[nxt]["key"] % state["bucket_count"] != bkt:
                    break
                node = nxt
    else:
        node = state["head"]
        while node is not None:
            if nodes[node]["key"] == key:
                return (node, False)
            node = nodes[node]["next"]
        bkt = key % state["bucket_count"]
    # Insert path: allocate and populate the node first.
    new_node = _alloc(state, 0x10)
    nodes[new_node] = {"next": None, "key": key}
    saved_state = state["next_resize"]
    grow, new_count = need_rehash(
        state, state["bucket_count"], state["element_count"], 1)
    if grow:
        _rehash(state, new_count, saved_state)
        bkt = key % state["bucket_count"]
    slot = state["buckets"][bkt]
    if slot is not None:
        nodes[new_node]["next"] = _slot_next(state, slot)
        _set_slot_next(state, slot, new_node)
    else:
        old_head = state["head"]
        state["head"] = new_node
        nodes[new_node]["next"] = old_head
        if old_head is not None:
            old_bkt = nodes[old_head]["key"] % state["bucket_count"]
            state["buckets"][old_bkt] = new_node
        state["buckets"][bkt] = BB
    state["element_count"] += 1
    return (new_node, True)
