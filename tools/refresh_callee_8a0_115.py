"""Model of node #115 routine 0x5eef8a0: stats-snapshot refresh.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes an owner pointer in rdi and a flag byte in sil.
It reads a subobject pointer from owner+0x128; when that pointer
is null it returns at once. Otherwise, while holding the mutex at
subobject+0x160, it computes a budget, walks the handler chain
(slot +0x98, identity 0x5d4d490), and either fills the snapshot
at subobject+0x188 (progress path) or bumps a no-progress counter
(no-progress path). It then locks the mutex at subobject+0x0,
copies the 312-byte snapshot to the published location at
subobject+0x28 (the string member is assigned, not bitwise
copied), unlocks both mutexes and returns nothing.

Budget (unsigned 64-bit): sil == 0 is slow (500 ns per unit,
180,000,000 ns cap); sil != 0 is fast (10 ns per unit,
10,000,000 ns cap). allowed = min(cap, (counter_hi -
counter_lo) * per_unit) when counter_lo < counter_hi, else
allowed = cap.

Progress: after the slot call returns V, delta = V -
counter_hi (unsigned); when delta < allowed the routine stores
V at counter_lo, fills the snapshot (sequence +1, chain head,
name string name@0x<ptr>#<pid>, four virtual-produced header
values), calls the slot a second time and stores that return at
counter_hi and at snapshot+0x130. Otherwise it increments the
no-progress counter at snapshot+0x124 and publishes the
existing snapshot.

Chain walks: the +0x98 walk follows link+0x20 while the slot
matches the walker, up to four links; the +0xb8 produce walk
follows link+0x38 while the slot matches the identity
0x5d427e0, up to ten links; the +0x70/+0x78 fill chains follow
link+0x38 up to five links. In each walk the first link whose
slot differs is called, or the last link's slot unconditionally.

NOT modelled: what the owner, the subobject, or the snapshot
fields denote beyond the pinned offsets; what any slot handler
or producer computes; what the consumers at 0x5eefda0 and
0x5ef8360 do with the copied snapshot; the exact throw-site
mapping of the three landing pads. A null owner, a null
subobject (modelled as the early-return path), a chain that
ends before a dispatch, or a mutex failure raises in the model
instead of inventing behaviour; the binary would fault on the
same reads.
"""

MASK64 = 0xFFFFFFFFFFFFFFFF

REFRESH = 0x5EEF8A0
FILLER = 0x5EEF380
STRING_MOVE = 0x5EEBB20
PRODUCE_IDENTITY = 0x5D427E0
WALKER = 0x5D4D490
WALKER70 = 0x5D2EFC0
WALKER78 = 0x5D2EF10
CONST_MINUS1 = 0x5D3EF70
CONST_ZERO = 0x5D3EF80
PID_WRAPPER = 0x60D5E80

SLOW_PER_UNIT_NS = 500
SLOW_CAP_NS = 180000000
FAST_PER_UNIT_NS = 10
FAST_CAP_NS = 10000000

SNAPSHOT_SIZE = 312
SNAPSHOT_STRING_OFFSET = 0x20
SNAPSHOT_SEQ_OFFSET = 0x120
SNAPSHOT_NO_PROGRESS_OFFSET = 0x124
SNAPSHOT_HEAD_OFFSET = 0x128
SNAPSHOT_LAST_VALUE_OFFSET = 0x130


def budget(flag, gap):
    """Return (per_unit_ns, cap_ns, allowed_ns) for a flag byte
    and an entry gap (counter_hi - counter_lo), or None for the
    gap when counter_lo >= counter_hi (allowed is then the cap).
    """
    if flag == 0:
        per_unit, cap = SLOW_PER_UNIT_NS, SLOW_CAP_NS
    else:
        per_unit, cap = FAST_PER_UNIT_NS, FAST_CAP_NS
    if gap is None:
        allowed = cap
    else:
        allowed = min(cap, (gap * per_unit) & MASK64)
    return per_unit, cap, allowed


def is_progress(delta, allowed):
    """True exactly when the new delta is below the budget."""
    return (delta & MASK64) < allowed


def walk_slots(slots, identity):
    """Walk a chain of slot values; return (index, value) of the
    first slot that differs from identity, or the last link when
    every compared slot matches. `slots` is the link list in
    walk order."""
    if not slots:
        raise ValueError("empty chain")
    for index, value in enumerate(slots):
        if value != identity:
            return index, value
    return len(slots) - 1, slots[-1]


def format_name(name, ptr, pid):
    """The filler's ostringstream format: name@0x<ptr>#<pid>."""
    return "%s@0x%x#%d" % (name, ptr, pid)


def move_string(src):
    """Model of 0x5eebb20: move a std::string from source to
    destination. Returns (destination_value, source_value):
    the destination takes the source contents and the source
    becomes empty, for both short (SSO) and heap strings."""
    return src, ""


def fill_snapshot(seq, chain_head, name, ptr, pid, produce70,
                  produce78, produce88=None, produce80=None):
    """Model of 0x5eef380: reset the snapshot record. The body
    is zeroed, the sequence increments by one, the chain head is
    stored, the name string is built, and the four header values
    come from the slot chains (produce88 defaults to 0 and
    produce80 to -1, the constant identities)."""
    snapshot = {
        "produce70": produce70,
        "produce78": produce78,
        "produce88": 0 if produce88 is None else produce88,
        "produce80": -1 if produce80 is None else produce80,
        "name": format_name(name, ptr, pid),
        "body_zero": True,
        "seq": seq + 1,
        "no_progress": 0,
        "head": chain_head,
        "last_value": 0,
    }
    return snapshot


def publish_copy(snapshot):
    """Model of the publish copy: a 312-byte copy of the working
    snapshot to the published location, with the string member
    assigned by value, so the published copy is independent of
    later writes to the working snapshot."""
    return dict(snapshot)


def refresh_step(state, flag, walk_results, produce, name, ptr, pid):
    """One refresh of the modelled owner state.

    state: dict with subobject_present (bool), counter_lo,
    counter_hi, snapshot (dict or None), published (dict or
    None), no_progress (int), last_value (int).
    walk_results: iterator of successive slot +0x98 returns.
    produce: dict with produce70, produce78, produce88,
    produce80 for the fill (only consumed on the progress path).
    Returns a dict describing the path taken.
    """
    if not state["subobject_present"]:
        return {"path": "noop"}
    gap = None
    if state["counter_lo"] < state["counter_hi"]:
        gap = state["counter_hi"] - state["counter_lo"]
    _per_unit, _cap, allowed = budget(flag, gap)
    value = next(walk_results)
    delta = (value - state["counter_hi"]) & MASK64
    if not is_progress(delta, allowed):
        state["no_progress"] += 1
        if state["snapshot"] is not None:
            state["snapshot"]["no_progress"] = state["no_progress"]
        state["published"] = publish_copy(state["snapshot"]) \
            if state["snapshot"] is not None else None
        return {"path": "no-progress", "allowed": allowed,
                "delta": delta}
    state["counter_lo"] = value
    seq = state["snapshot"]["seq"] if state["snapshot"] else 0
    state["snapshot"] = fill_snapshot(
        seq, state["head"], name, ptr, pid,
        produce["produce70"], produce["produce78"],
        produce.get("produce88"), produce.get("produce80"))
    state["snapshot"]["no_progress"] = state["no_progress"]
    observed = next(walk_results)
    state["counter_hi"] = observed
    state["snapshot"]["last_value"] = observed
    state["last_value"] = observed
    state["published"] = publish_copy(state["snapshot"])
    return {"path": "progress", "allowed": allowed, "delta": delta,
            "produced": value, "observed": observed}


def caller_flag(caller_flag_value):
    """Both new callers pass the inverted low bit of their own
    flag argument to the refresh routine."""
    return caller_flag_value ^ 1
