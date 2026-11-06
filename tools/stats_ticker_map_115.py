"""Python model of the node #115 StatisticsImpl slot-0xf0
ticker-map fill and the four DB-family vtables behind the
DBImpl rebuild (RE-001-stats-ticker-map-115).

Models, from the pinned excerpts:
  * StatisticsImpl slot 0xf0, 0x6076030 (vtable 0x64d2d88,
    slot 0xf0; the next slot after ToString at 0xe8):
    fills a caller-supplied std::map<std::string, uint64_t>
    with one (ticker name -> shard-summed count) entry per
    entry of the BSS ticker vector at 0x6506260, and returns
    true; a null map pointer returns false without locking.
    The old map contents are freed first (every node via the
    recursive _Rb_tree::_M_erase 0x60700d0, heap string
    buffers freed when not SSO, nodes freed as 0x48 bytes),
    the header is re-initialised (root null, left/right =
    &header, count 0), the mutex at this+0x38 is locked via
    0x60d5230 and unlocked via 0x60d52f0. Each ticker id is
    summed by 0x6070430 (same getter ToString uses), the name
    is built into a std::string (SSO at <=15 chars, heap via
    _M_create above that; a null name throws logic_error
    "basic_string: construction from null is not valid"),
    and the pair is inserted through the inlined RB-tree
    lower_bound + _Rb_tree_insert_and_rebalance; an existing
    key keeps its node and takes the new summed value
    (last duplicate wins). On exception the temp string is
    disposed and the mutex is unlocked by the shared cleanup
    fragment 0x6075ff6..0x607602a, then unwinding resumes.
  * ticker sum 0x6070430 (re-shipped from #3362): the count
    for one ticker is the sum over 2**shard_bits shards of
    the u64 at shard_base + shard*0xce40 + ticker*8.
  * DBImpl rebuild 0x5d58720 (#3362): 233 bytes, locks
    db+0x700 via the instrumented acquire 0x606ca40, builds
    a temp via 0x60c2e20, copies the statistics shared_ptr
    into DB+0x548, unlocks. It has no direct callers; it is
    reached only through vtable slot 0x2d0 of four
    151-slot DB-family vtables, none of which overrides it:
    DBImpl 0x64c9368, DBImplReadOnly 0x64cb0e0,
    CompactedDBImpl 0x64cb5c0, DBImplSecondary 0x64cbbc0.
    The override map (slots where each subclass differs
    from DBImpl) is pinned below; the full 151-slot tables
    live in the packet's vtables.tsv, re-derived from
    relocations.txt by verify.py.

Conventions: counts are u64 (masked to 64 bits). The map is
a std::map, so iteration order is key-sorted; the model
keeps a plain dict and exposes sorted items for that order.
"""

SHARD_STRIDE = 0xCE40
TICKER_VECTOR = 0x6506260
TICKER_ENTRY_SIZE = 0x28
STATISTICS_VTABLE = 0x64D2D88
SLOT_F0 = 0xF0
SLOT_F0_ROUTINE = 0x6076030
TICKER_GETTER = 0x6070430
TREE_ERASE = 0x60700D0
MUTEX_OFFSET = 0x38
LOGIC_ERROR_MESSAGE = "basic_string: construction from null is not valid"

REBUILD = 0x5D58720
REBUILD_SLOT = 0x2D0
DB_VTABLE_SLOTS = 151

# class name -> (vtable address, typeinfo, base typeinfo)
DB_VTABLES = {
    "DBImpl": (0x64C9368, "N7rocksdb6DBImplE", "N7rocksdb2DBE"),
    "DBImplReadOnly": (0x64CB0E0, "N7rocksdb14DBImplReadOnlyE",
                       "N7rocksdb6DBImplE"),
    "CompactedDBImpl": (0x64CB5C0, "N7rocksdb15CompactedDBImplE",
                        "N7rocksdb6DBImplE"),
    "DBImplSecondary": (0x64CBBC0, "N7rocksdb15DBImplSecondaryE",
                        "N7rocksdb6DBImplE"),
}

# Slots where each subclass vtable differs from DBImpl's, as
# (slot offset -> subclass routine). Every other slot is
# inherited unchanged, including slot 0x2d0 -> 0x5d58720.
DB_OVERRIDES = {
    "DBImplReadOnly": {
        0x010: 0x5E6E0D0, 0x018: 0x5E6E0F0, 0x050: 0x5E6E790,
        0x070: 0x5E6E710, 0x078: 0x5E6E690, 0x098: 0x5E6E610,
        0x0C8: 0x5E6E590, 0x0E0: 0x5E6E510, 0x0F0: 0x5E6E080,
        0x108: 0x5E704C0, 0x198: 0x5E71580, 0x1A8: 0x5E71920,
        0x228: 0x5E6E490, 0x250: 0x5E6E410, 0x2E8: 0x5E6E390,
        0x308: 0x5E6E310, 0x328: 0x5E6E290, 0x340: 0x5E6E210,
        0x388: 0x5E74150, 0x3A0: 0x5E6E190, 0x3B8: 0x5E6E110,
        0x4A0: 0x5E6E060,
    },
    "CompactedDBImpl": {
        0x010: 0x5E74220, 0x018: 0x5E74240, 0x050: 0x5E747E0,
        0x070: 0x5E74760, 0x078: 0x5E746E0, 0x0C8: 0x5E74660,
        0x0E0: 0x5E745E0, 0x0F0: 0x5E741D0, 0x108: 0x5E76160,
        0x128: 0x5E748E0, 0x138: 0x5E76FB0, 0x228: 0x5E74560,
        0x2E8: 0x5E744E0, 0x308: 0x5E74460, 0x328: 0x5E743E0,
        0x340: 0x5E74360, 0x388: 0x5E7A4F0, 0x3A0: 0x5E742E0,
        0x3B8: 0x5E74260, 0x4A0: 0x5E741B0,
    },
    "DBImplSecondary": {
        0x010: 0x5E7BD20, 0x018: 0x5E7BEA0, 0x050: 0x5E7ADD0,
        0x070: 0x5E7AD50, 0x078: 0x5E7ACD0, 0x098: 0x5E7AC50,
        0x0C8: 0x5E7ABD0, 0x0E0: 0x5E7AB50, 0x0F0: 0x5E7D920,
        0x108: 0x5E7D970, 0x198: 0x5E7DAC0, 0x1A8: 0x5E807E0,
        0x228: 0x5E7AAD0, 0x238: 0x5E7AA50, 0x248: 0x5E7A9D0,
        0x250: 0x5E7A950, 0x2E8: 0x5E7A8D0, 0x308: 0x5E7A850,
        0x328: 0x5E7A7D0, 0x340: 0x5E7A750, 0x388: 0x5E7A6D0,
        0x3A0: 0x5E7A650, 0x468: 0x5E84A80, 0x498: 0x5E85100,
        0x4A0: 0x5E7A560, 0x4A8: 0x5E846D0, 0x4B0: 0x5E7A640,
    },
}


class LogicError(Exception):
    pass


def ticker_sum(shards, shard_bits, ticker):
    """0x6070430: sum over 2**shard_bits shards of the u64 at
    shard_base + shard*0xce40 + ticker*8. `shards` is a list of
    dicts {ticker: count}; missing entries count as 0."""
    total = 0
    for shard in range(1 << shard_bits):
        total += shards[shard].get(ticker, 0)
    return total & 0xFFFFFFFFFFFFFFFF


def fill_ticker_map(out, tickers, shards, shard_bits, trace=None):
    """0x6076030 end to end. `out` is a dict or None (the
    caller-supplied map); `tickers` is a list of (ticker_id,
    name) in vector order; `shards` is the per-shard store
    ticker_sum reads; `shard_bits` selects the shard count.
    A None map returns False without locking. Otherwise the
    old contents are cleared, the mutex is locked, every
    ticker is summed and inserted (last duplicate wins),
    the mutex is unlocked and True is returned. A null name
    raises LogicError with the binary's message; the mutex
    is unlocked on that path too (the shared cleanup
    fragment). `trace` records the lock/unlock bracketing
    when supplied."""
    if trace is None:
        trace = []
    if out is None:
        return False
    out.clear()
    trace.append("lock:+0x38")
    try:
        for ticker_id, name in tickers:
            if name is None:
                raise LogicError(LOGIC_ERROR_MESSAGE)
            out[name] = ticker_sum(shards, shard_bits, ticker_id)
    except LogicError:
        trace.append("unlock:+0x38 (exception path)")
        raise
    trace.append("unlock:+0x38")
    return True


def ticker_map_items(mapping):
    """std::map iteration order: keys sorted."""
    return [(name, mapping[name]) for name in sorted(mapping)]


def rebuild_slot_target(vtable_slots):
    """Slot 0x2d0 of a DB-family vtable: the rebuild routine.
    `vtable_slots` is a {slot offset: target} dict."""
    return vtable_slots[REBUILD_SLOT]


def override_slots(class_name):
    """The slots a DBImpl subclass overrides, as a sorted
    list of offsets."""
    return sorted(DB_OVERRIDES[class_name])
