"""Node #115 slot lookup with accumulator apply and group append.

Maps RE-001 windows 0x5f45cf0 (365 bytes), 0x5f6b620 (64 bytes) and
0x5f78060 (95 bytes) from the digest-verified node #115 binary
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Lookup signature, in native argument order:

  lookup(slot_array, accumulator, element, index)

  slot_array   base of the slot array; slot = base + 112 * index, where
               index is the int32 argument sign-extended to 64 bits.
  accumulator  object carrying the +0xfb0/+0xfb8/+0xfc0 totals and the
               +0xa98 group array (24-byte entries, as in the
               element-rate pass of 0x5f6b660).
  element      record carrying the key at +0x8, +0x80, +0x88, +0xb0
               and the flag byte at +0xb5.
  index        int32 group/slot index.

Key rule: key = element+0x8 & 0x3fffffffffffffff. The mask is applied
once, up front, and every comparison in every stage uses the masked
key. The slot's mode flags decide which structure each stage reads;
the fields the lookup never reads (slot +0x20/+0x28/+0x30, and
+0x58..+0x70 past the last field) are unknown and not claimed.

Decision tree, stated literally:

  Stage 1/2 (selected by slot+0x18):
    - If slot+0x18 == 0: walk the chain headed at slot+0x10. Each
      node compares its +0x8 key with the masked key and links via
      its +0x0 qword. A key match runs the leaf. Exhausting the
      chain falls through to stage 3/list below.
    - If slot+0x18 != 0: bucket = masked key % slot+0x8 (count); the
      bucket entry is slot+0x0 (table)[bucket]. A null bucket entry
      falls through to stage 3/list. Otherwise walk the record
      chain: the first record's key is compared directly; each later
      record's key must first re-hash to the same bucket (key %
      count == bucket) or the walk falls through to stage 3/list,
      and a key match runs the leaf. (The wrapper's first qword is
      re-checked nonzero at 0x5f45da4 before the leaf tail-jump;
      in every reachable state it is the record just dereferenced,
      so a stage-2 key match always reaches the leaf.)

  Stage 3/list (selected by slot+0x50; reached on any stage 1/2 miss):
    - If slot+0x50 != 0: bucket = masked key % slot+0x40 (count);
      the bucket entry is slot+0x38 (table)[bucket]. A null bucket
      entry runs the append. Otherwise walk the record chain: the
      first record's key is compared directly; each later record's
      key must first re-hash to the same bucket or the walk runs
      the append, and a key match runs the owner test.
    - If slot+0x50 == 0: walk the list headed at slot+0x48. Each
      node compares its +0x8 key with the masked key and links via
      its +0x0 qword. A key match runs the owner test. Exhausting
      the list runs the append.
    - Owner test: if the matched record's +0x10 pointer is the
      element itself, run the append; otherwise run the leaf.

  Leaf (0x5f6b620, accumulator apply):
    - If element+0xb5 == 0, return without touching the accumulator.
    - Otherwise, all arithmetic wrapping at 64 bits:
        acc+0xfb0 = acc+0xfb0 + element+0x88 - element+0x80
        acc+0xfb8 = acc+0xfb8 - element+0x88
        acc+0xfc0 = acc+0xfc0 - 1

  Append (0x5f78060, group append):
    - group = accumulator+0xa98 entries [index] (24 bytes; +0x8 is
      the cursor, +0x10 the capacity end; +0x0 is never read here).
    - If cursor != capacity end: store the element at the cursor,
      advance the cursor by 8, and increment element+0xb0 by 1.
    - If cursor == capacity end: call the grow helper at 0x5d9ee20
      with (group entry, cursor, pointer to a slot holding the
      element) -- the callee is NOT modelled here, only its call
      site and arguments are recorded -- then increment
      element+0xb0 by 1. The model extends the capacity by the
      minimal amount that fits the append; the native grow amount
      is unknown and not claimed, so tests assert the appended
      items and the +0xb0 increment on the grow path, never the
      exact post-grow capacity.

A null table entry with a nonzero count, a zero count in a hash
stage, a negative or out-of-range index, or a missing field are
model guard errors, not native behaviors: the native code divides,
dereferences or reads those locations without a check.
"""

MASK64 = (1 << 64) - 1
KEY_MASK = 0x3FFFFFFFFFFFFFFF
SLOT_STRIDE = 112


class SlotLookupError(ValueError):
    """Guard error for inputs the native code would read, divide or
    dereference unchecked, plus the native divide-by-zero traps."""


def _u64(value):
    return value & MASK64


def _signed32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >= (1 << 31) else value


def make_element(key=0, lo=0, hi=0, ref=0, flag=0):
    """Build an element dict in the layout above.

    key is the raw +0x8 value (masked by the lookup itself); lo/hi
    are +0x80/+0x88; ref is +0xb0; flag is the +0xb5 byte.
    """
    return {
        "key": _u64(key),
        "lo": _u64(lo),
        "hi": _u64(hi),
        "ref": _u64(ref),
        "flag": flag & 0xFF,
    }


def make_slot(mode1=0, chain1=None, table1=None, count1=0,
              mode2=0, table2=None, count2=0, list2=None):
    """Build a slot dict in the layout above.

    chain1: list of keys (stage-1 chain, walk order).
    table1: dict bucket -> list of record keys (stage-2 chain), or
        None for a bucket entry to mean the null bucket entry.
    table2: dict bucket -> list of records {"key", "owner"}.
    list2: list of records {"key", "owner"} (secondary list).
    A record's "owner" is the element dict itself (identity compared
    with `is`) or any other object for a different owner.
    """
    return {
        "mode1": mode1,
        "chain1": list(chain1) if chain1 is not None else [],
        "table1": dict(table1) if table1 is not None else {},
        "count1": _u64(count1),
        "mode2": mode2,
        "table2": dict(table2) if table2 is not None else {},
        "count2": _u64(count2),
        "list2": list(list2) if list2 is not None else [],
    }


def make_group(items=None, cap=None):
    """Build a group: items are the element dicts already stored, in
    cursor order; cap is the capacity end (number of element slots).
    """
    items = list(items) if items is not None else []
    return {"items": items, "cap": len(items) if cap is None else cap}


def make_accumulator(groups=None):
    """Build an accumulator dict (fb0/fb8/fc0 totals + groups)."""
    return {
        "fb0": 0,
        "fb8": 0,
        "fc0": 0,
        "groups": list(groups) if groups is not None else [],
    }


def _need(mapping, field):
    if mapping is None or field not in mapping:
        raise SlotLookupError("missing field: %s" % field)
    return mapping[field]


def _leaf(acc, element):
    """The 0x5f6b620 accumulator apply; returns "leaf"."""
    if _need(element, "flag") == 0:
        return "leaf"
    hi = _need(element, "hi")
    lo = _need(element, "lo")
    acc["fb0"] = (acc["fb0"] + hi - lo) & MASK64
    acc["fb8"] = (acc["fb8"] - hi) & MASK64
    acc["fc0"] = (acc["fc0"] - 1) & MASK64
    return "leaf"


def _append(acc, element, index):
    """The 0x5f78060 group append; returns "append"."""
    groups = _need(acc, "groups")
    if index >= len(groups):
        raise SlotLookupError("fewer supplied groups than index")
    group = groups[index]
    items = _need(group, "items")
    cap = _need(group, "cap")
    if len(items) != 0 and len(items) > cap:
        raise SlotLookupError("group cursor past capacity end")
    if len(items) < cap:
        items.append(element)
    else:
        # Grow path: the native helper at 0x5d9ee20 is not modelled;
        # extend capacity by the minimal fitting amount (see module
        # docstring) and append.
        group["cap"] = len(items) + 1
        items.append(element)
    element["ref"] = (_need(element, "ref") + 1) & MASK64
    return "append"


def _owner_test(acc, element, index, record):
    """Stage-3/list owner test: same element -> append, else leaf."""
    if record.get("owner") is element:
        return _append(acc, element, index)
    return _leaf(acc, element)


def _stage3_or_list(slots, acc, element, index, key):
    """Stage 3/list resolution; returns "leaf" or "append"."""
    slot = slots[index]
    mode2 = _need(slot, "mode2")
    if mode2 != 0:
        count2 = _need(slot, "count2")
        if count2 == 0:
            raise SlotLookupError(
                "native divide-by-zero: stage-3 count is zero")
        bucket = key % count2
        table2 = _need(slot, "table2")
        chain = table2.get(bucket)
        if chain is None:
            return _append(acc, element, index)
        if not chain:
            raise SlotLookupError(
                "stage-3 bucket entry non-null but chain empty")
        if _need(chain[0], "key") == key:
            return _owner_test(acc, element, index, chain[0])
        for record in chain[1:]:
            rkey = _need(record, "key")
            if rkey % count2 != bucket:
                return _append(acc, element, index)
            if rkey == key:
                return _owner_test(acc, element, index, record)
        return _append(acc, element, index)
    for record in _need(slot, "list2"):
        if _need(record, "key") == key:
            return _owner_test(acc, element, index, record)
    return _append(acc, element, index)


def slot_lookup(slots, acc, element, index):
    """Run the lookup; returns "leaf" or "append" (which terminal ran).

    slots is the slot-array list; acc and element are dicts in the
    layouts above; index is the int32 index argument.
    """
    for field in ("fb0", "fb8", "fc0", "groups"):
        _need(acc, field)
    for field in ("key", "lo", "hi", "ref", "flag"):
        _need(element, field)
    index = _signed32(index)
    if index < 0 or index >= len(slots):
        raise SlotLookupError("index out of range: %d" % index)
    slot = slots[index]
    key = _need(element, "key") & KEY_MASK
    mode1 = _need(slot, "mode1")
    if mode1 == 0:
        for ckey in _need(slot, "chain1"):
            if _u64(ckey) == key:
                return _leaf(acc, element)
        return _stage3_or_list(slots, acc, element, index, key)
    count1 = _need(slot, "count1")
    if count1 == 0:
        raise SlotLookupError("native divide-by-zero: stage-2 count is zero")
    bucket = key % count1
    table1 = _need(slot, "table1")
    chain = table1.get(bucket)
    if chain is None:
        return _stage3_or_list(slots, acc, element, index, key)
    if not chain:
        raise SlotLookupError("stage-2 bucket entry non-null but chain empty")
    if _u64(chain[0]) == key:
        return _leaf(acc, element)
    for ckey in chain[1:]:
        ckey = _u64(ckey)
        if ckey % count1 != bucket:
            return _stage3_or_list(slots, acc, element, index, key)
        if ckey == key:
            return _leaf(acc, element)
    return _stage3_or_list(slots, acc, element, index, key)
