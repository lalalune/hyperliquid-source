"""Node #115 two-phase filtered accumulation (0x5f77330) with its
accumulator leaf (0x5f6b590).

RE-001 work item. This is a complete behavior, not a lone-window
fragment: the 593-byte scan takes the group's element table, filters
every element through a predicate oracle, accumulates every match
into a counter block through the 136-byte leaf, and — after a
20-hit cap on non-sentinel virtual-chain results or a full forward
scan — runs a reverse scan that stops as soon as the accumulated
+0x98 counter becomes nonzero.

Native layout (all offsets from the disassembly of
work/hl-node-115.bin, bound to provenance/artifacts.json digest
a6e2897c...5301):

  scan(groups, predicate, virtual_chain):
    count = signed32(obj + 0x50); groups are the first count
    24-byte entries at obj + 0xad8, each entry holding an 8-byte
    element-pointer array in its first two qwords (begin, end).
    count <= 0 returns at once with no predicate call.
    Phase 1 (forward): for each group in order, for each element
    pointer in [begin, end) in order:
      if not predicate(obj, element): continue
      accumulate(obj + 0x40, element)
      v = virtual_chain(obj)          (oracle; see below)
      if v == 0x400000: continue       (sentinel: not special)
      special += 1
      if special == 20: break out of both loops into phase 2
    Phase 2 (reverse): entered after phase 1 however it ended.
      if acc.f98 != 0: return at once (phase 2 skipped)
      for each group from last to first, for each element pointer
      from last to first:
        if predicate(obj, element): accumulate(obj + 0x40, element)
        if acc.f98 != 0: return at once (phase 2 ends entirely)
      (an empty group contributes nothing and is skipped)
    Return nothing (void).

  accumulate(base, element)  -- the leaf 0x5f6b590, all wrapping
  64-bit arithmetic, no calls, no return value:
    base + 0xf88 += element + 0x10
    base + 0xf90 += element + 0x90
    base + 0xf98 += element + 0x98
    base + 0xfa0 = base + 0xfa0 + element + 0x80 - element + 0x88
    base + 0xfa8 += element + 0x88
    base + 0xfb0 = base + 0xfb0 + element + 0x80 - element + 0x88
    base + 0xfc0 += 1
    base + 0xfb8 += element + 0x88
  In caller terms the base is obj + 0x40, so the counters land at
  obj + 0xfc8, +0xfd0, +0xfd8, +0xfe0, +0xfe8, +0xff0, +0xff8 and
  +0x1000; the phase-2 gate reads obj + 0xfd8, which is exactly
  base + 0xf98.

  virtual_chain(obj) -- oracle. The native code walks a link chain
  from obj + 0x1020, compares +0x70 tags along it against a global
  tag, and calls a virtual method on the first node whose tag
  differs (or on the chain head when all tags match); the returned
  qword is compared against the sentinel 0x400000. The chain walk
  and the virtual method are NOT modelled: only the sentinel
  comparison and the 20-hit cap are pinned. The predicate
  0x5f77190 is likewise an oracle returning nonzero for a match.

Assumptions recorded explicitly:
  * The group table and the count do not change while the scan
    runs; an oracle that mutated them would break the native loop
    bounds in ways the model does not reproduce.
  * Element dictionaries must carry the five fields the leaf reads
    (+0x10, +0x80, +0x88, +0x90, +0x98); a missing field raises
    ValueError instead of faulting, which is model-only.
  * A group whose byte span is not a multiple of 8, or whose end
    precedes its begin, is out of contract; the model takes the
    element list as given, so it treats any list (including an
    empty one) as the group's elements.
"""

MASK64 = (1 << 64) - 1
SENTINEL = 0x400000
SPECIAL_CAP = 20

# Element fields the accumulator leaf reads, by native offset.
LEAF_FIELDS = ("f10", "f80", "f88", "f90", "f98")


def u64(value):
    return value & MASK64


def new_acc():
    """A fresh accumulator block, keyed by leaf-relative offset."""
    return {"f88": 0, "f90": 0, "f98": 0, "fa0": 0,
            "fa8": 0, "fb0": 0, "fb8": 0, "fc0": 0}


def accumulate(acc, elt):
    """The leaf 0x5f6b590, exactly as the native code applies it."""
    for field in LEAF_FIELDS:
        if field not in elt:
            raise ValueError("element is missing field %s" % field)
    acc["f88"] = u64(acc["f88"] + elt["f10"])
    acc["f90"] = u64(acc["f90"] + elt["f90"])
    acc["f98"] = u64(acc["f98"] + elt["f98"])
    acc["fa0"] = u64(acc["fa0"] + elt["f80"] - elt["f88"])
    acc["fa8"] = u64(acc["fa8"] + elt["f88"])
    acc["fb0"] = u64(acc["fb0"] + elt["f80"] - elt["f88"])
    acc["fc0"] = u64(acc["fc0"] + 1)
    acc["fb8"] = u64(acc["fb8"] + elt["f88"])
    return acc


def scan(groups, predicate, virtual_chain, acc=None):
    """The scan 0x5f77330 end to end.

    groups: a list of groups, each a list of element dicts, in
    native order; len(groups) is the signed count at obj + 0x50.
    predicate: callable(element) -> truthy for a match.
    virtual_chain: callable() -> int, the oracle qword.
    Returns a dict with the accumulator block, the number of
    non-sentinel virtual results, how phase 2 ended, and a call
    log (predicate outcomes in order, virtual results in order,
    accumulated elements in order).
    """
    if acc is None:
        acc = new_acc()
    log = {"predicate": [], "virtual": [], "accumulate": []}
    count = len(groups)
    if count <= 0:
        return {"acc": acc, "special": 0, "phase2": "not-run",
                "log": log}
    special = 0
    capped = False
    for group in groups:
        for elt in group:
            matched = bool(predicate(elt))
            log["predicate"].append(matched)
            if not matched:
                continue
            accumulate(acc, elt)
            log["accumulate"].append(elt)
            value = virtual_chain()
            log["virtual"].append(value)
            if value == SENTINEL:
                continue
            special += 1
            if special >= SPECIAL_CAP:
                capped = True
                break
        if capped:
            break
    if acc["f98"] != 0:
        return {"acc": acc, "special": special,
                "phase2": "skipped-f98-nonzero", "log": log}
    for group in reversed(groups):
        for elt in reversed(group):
            matched = bool(predicate(elt))
            log["predicate"].append(matched)
            if matched:
                accumulate(acc, elt)
                log["accumulate"].append(elt)
            if acc["f98"] != 0:
                return {"acc": acc, "special": special,
                        "phase2": "stopped-at-nonzero-f98",
                        "log": log}
    return {"acc": acc, "special": special, "phase2": "complete",
            "log": log}
