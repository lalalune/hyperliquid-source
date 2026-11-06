"""Model of the node #115 canonical-identity chain walk.

The canonical continuation 0x5d4b100 is virtual slot 24
(offset 0xc0) of the rocksdb::SystemClockWrapper vtable at
0x64cdd88 (installed at 0x64cde48 by a RELATIVE record, and
in the GOT slot 0x64ed3e8). Four routines take the
canonical's address with lea and unroll its chain walk
inline instead of calling it:

  site A 0x5dc9d70: 11 levels compared, 12th level's slot 24
    called; chain head *(arg+8)+0x210 after a SIMD sum over
    a pointer range's +0x10 fields.
  site B 0x5e18d20: 9 levels compared, 10th level's slot 24
    called; chain head *(obj+0x240) behind an entry gate.
  site C 0x5f7d7d0: 11 levels compared, 12th level's slot 24
    called; chain head *(arg2+0x210) after a prologue sync.
  site D 0x5f865d0: 11 levels compared, 12th level's slot 24
    called; chain head is arg4, after a stack config build.

The walk rule is the same in all four and in the canonical
itself (#3322): compare each level's vtable slot 24 against
the canonical; the first level whose slot 24 differs has
THAT slot called; if every compared level matches, advance
one more node and call its slot 24 unconditionally. The
slot-24 contract is (bool_out, node, value_out): the callee
fills a Status-shaped triple {u32 code, u16 code2, ptr} at
bool_out and the value at value_out.

EmulatedSystemClock (vtable 0x64d1650) overrides slot 24
with 0x6025eb0, so the walk is a dynamic-dispatch probe:
a chain of plain wrappers resolves through the canonical,
a chain reaching an emulated clock resolves through
0x6025eb0, which answers from its own node (+0x48 flag,
+0x30 value, +0x40 scaled add) or recurses down the chain.

Chain nodes are modelled as dicts {'slot24': callable |
None, 'next': node id | None, 'flag48': bool, 'v30': int,
'v40': int}; slot24 None means the canonical 0x5d4b100.
A null chain link where the binary would dereference it is
a model error (ValueError), matching the binary faulting.
"""

CANONICAL = 0x5D4B100
RESOLVER = 0x5F074E0
SLOT24 = 0xC0
CHAIN_LINK = 0x20

WRAPPER_VTABLE = 0x64CDD88
WRAPPER_VTABLE_HEADER = 0x64CDD78
WRAPPER_SLOT24_ADDR = 0x64CDE48
WRAPPER_TYPEINFO = 0x64CD960
GOT_CANONICAL_SLOT = 0x64ED3E8

EMULATED_VTABLE = 0x64D1650
EMULATED_SLOT24 = 0x6025EB0
EMULATED_TYPEINFO = 0x64D1240

# rocksdb::SystemClockWrapper vtable, 26 slots, from the
# RELATIVE records at 0x64cdd88..0x64cde50. None = a null
# slot (slots 0, 1 and 14 hold no RELATIVE record).
WRAPPER_SLOTS = [
    None, None, 0x609D760, 0x609DC40, 0x5D32560, 0x5FCF590,
    0x6096790, 0x5D2E090, 0x60956F0, 0x609D0E0, 0x60986B0,
    0x6095710, 0x5FCDAE0, 0x609D980, None, 0x5D32A30,
    0x5D2E770, 0x5FCC3F0, 0x5D2CA10, 0x5D4D490, 0x5FCC340,
    0x5FCC360, 0x5FCC380, 0x5DD41A0, 0x5D4B100, 0x5FCC3A0,
]

# rocksdb::EmulatedSystemClock vtable, 26 slots, from the
# RELATIVE records at 0x64d1650..0x64d1718. It shares the
# wrapper's slots 2..13, 15..18 and 25, overrides slots 0,
# 1, 14, 19..24.
EMULATED_SLOTS = [
    0x6029110, 0x6029620, 0x609D760, 0x609DC40, 0x5D32560,
    0x5FCF590, 0x6096790, 0x5D2E090, 0x60956F0, 0x609D0E0,
    0x60986B0, 0x6095710, 0x5FCDAE0, 0x609D980, 0x60257A0,
    0x5D32A30, 0x5D2E770, 0x5FCC3F0, 0x5D2CA10, 0x60259E0,
    0x60259A0, 0x6025A30, 0x6025A10, 0x6025B40, 0x6025EB0,
    0x5FCC3A0,
]

# The three FactoryEntry vtables installed by the entry
# thunks 0x5fcc5d0/0x5fcc600/0x5fcc630 (mode 0 arm).
ENTRY_VTABLES = [0x64CD9D0, 0x64CD9E0, 0x64CD9F0]

# Site walk depths: (compared levels, terminal level).
SITE_DEPTHS = {
    "A": (11, 12),
    "B": (9, 10),
    "C": (11, 12),
    "D": (11, 12),
}

# The scaled-add constant in the emulated slot 24
# (0x6025eb0): value += ((0x431bde82d7b634db * v40) >> 64
# >> 18) - sign(v40), all signed arithmetic.
SCALE = 0x431BDE82D7B634DB


def scaled_add(v40):
    """Mirror the imul/sar sequence at 0x6025f92..0x6025fae."""
    product = SCALE * v40  # signed 128-bit product
    high = product >> 64  # arithmetic shift, floor for negatives
    return (high >> 18) + (1 if v40 < 0 else 0)


def fresh_out():
    """The Status-shaped triple a slot-24 callee fills."""
    return {"code": 0, "code2": 0, "ptr": 0}


def fresh_value():
    return {"value": 0}


def emulated_slot24(chain, node_id, out, value, invoked):
    """Mirror 0x6025eb0 (EmulatedSystemClock slot 24).

    Zeroes the out triple. When the node's +0x48 flag is
    set the value is *(node+0x30) and the scaled +0x40 add
    runs. When the flag is clear it recurses to the next
    node's slot 24 with a temp triple, merges the temp
    triple into out, then runs the scaled add when the
    merged bool (code field) is 0.
    """
    invoked.append(node_id)
    node = chain[node_id]
    out["code"] = 0
    out["code2"] = 0
    out["ptr"] = 0
    if node["flag48"]:
        value["value"] = node["v30"]
        value["value"] += scaled_add(node["v40"])
        return out
    nxt = node["next"]
    if nxt is None:
        raise ValueError("emulated slot 24 recursed past the chain end")
    temp_out = fresh_out()
    temp_value = fresh_value()
    call_slot24(chain, nxt, temp_out, temp_value, invoked)
    out["code"] = temp_out["code"]
    out["code2"] = temp_out["code2"]
    out["ptr"] = temp_out["ptr"]
    value["value"] = temp_value["value"]
    if out["code"] == 0:
        value["value"] += scaled_add(node["v40"])
    return out


def canonical_walk(chain, node_id, out, value, invoked):
    """Mirror 0x5d4b100. The caller already found node_id's
    slot 24 canonical, so advance past it first, compare
    eight more levels, and call the ninth level's slot
    unconditionally (recursing when that slot is canonical
    too)."""
    invoked.append(("canonical", node_id))
    node = chain[node_id]
    nxt = node["next"]
    if nxt is None:
        raise ValueError("canonical walked past the chain end")
    current = nxt
    for _ in range(8):
        slot = chain[current]["slot24"]
        if slot is not None:
            return call_slot24(chain, current, out, value, invoked)
        nxt = chain[current]["next"]
        if nxt is None:
            raise ValueError("canonical walked past the chain end")
        current = nxt
    return call_slot24(chain, current, out, value, invoked)


def call_slot24(chain, node_id, out, value, invoked):
    """Invoke one node's slot 24. None is the canonical."""
    slot = chain[node_id]["slot24"]
    if slot is None:
        return canonical_walk(chain, node_id, out, value, invoked)
    return slot(chain, node_id, out, value, invoked)


def walk_dispatch(chain, head, site, out=None, value=None):
    """Mirror one lea site's unrolled walk. `site` is one of
    A/B/C/D. Compares `compared` levels against the
    canonical; the first mismatch has its own slot 24
    called; all matching advances one more node and calls
    ITS slot 24. Returns (how, node_id, invoked) where how
    is 'mismatch' or 'terminal'."""
    compared, _terminal = SITE_DEPTHS[site]
    if out is None:
        out = fresh_out()
    if value is None:
        value = fresh_value()
    invoked = []
    current = head
    for _ in range(compared):
        if current is None:
            raise ValueError("walk ran past the chain end")
        if chain[current]["slot24"] is not None:
            call_slot24(chain, current, out, value, invoked)
            return ("mismatch", current, invoked, out, value)
        current = chain[current]["next"]
    if current is None:
        raise ValueError("walk ran past the chain end")
    call_slot24(chain, current, out, value, invoked)
    return ("terminal", current, invoked, out, value)


def site_a_sum(records):
    """Mirror site A's pre-walk SIMD sum: the +0x10 field of
    each record a pointer range points at. `records` is the
    list of +0x10 values in range order; an empty range sums
    to 0 (the binary jumps past the loop with rbx 0)."""
    total = 0
    for v in records:
        total = (total + v) & 0xFFFFFFFFFFFFFFFF
    return total


def site_b_gate(obj):
    """Mirror site B's entry gate: *(obj+0x270) byte 0,
    *(obj+0x271) byte 3, *(obj+0x438) nonzero, the
    (+0x1068 - +0x1060) span above 0x38, *(obj+0x10e0)
    byte 0. Any failure returns without walking."""
    return (obj["b270"] == 0 and obj["b271"] == 3
            and obj["x438"] != 0
            and (obj["x1068"] - obj["x1060"]) > 0x38
            and obj["b10e0"] == 0)


def site_c_prologue(owner):
    """Mirror site C's prologue: *(owner+0xc88) is zeroed
    when set; *(owner+0xd20) is synced to *(owner+0xd18)
    when they differ."""
    if owner["c88"] != 0:
        owner["c88"] = 0
    if owner["d18"] != owner["d20"]:
        owner["d20"] = owner["d18"]
    return owner


def site_d_config():
    """Mirror site D's stack config built before the walk:
    1 at -0x68, 0 at -0x60/-0x58, 1.0f (0x3f800000) at
    -0x50, 0 at -0x48/-0x40."""
    return {"neg68": 1, "neg60": 0, "neg58": 0,
            "neg50": 0x3F800000, "neg48": 0, "neg40": 0}


def site_a_first_use(bool_out, ptr_out, owner):
    """First use of the dispatch result in site A: bool
    nonzero goes to 0x5dca750; otherwise the pointer is
    stored and *(owner+0x38) nonzero goes to 0x5dca6f8."""
    if bool_out != 0:
        return "alt-0x5dca750"
    if owner["x38"] != 0:
        return "alt-0x5dca6f8"
    return ("continue", ptr_out)


def site_b_first_use(bool_out, ptr_out, limit438):
    """First use in site B: bool nonzero, or the pointer
    below *(obj+0x438), goes to 0x5e19038; otherwise the
    pointer is reduced by limit/2."""
    if bool_out != 0 or ptr_out < limit438:
        return "alt-0x5e19038"
    return ("continue", ptr_out - (limit438 >> 1))


def site_c_first_use(bool_out, ptr_out, arg3):
    """First use in site C: bool nonzero, or the pointer
    below arg3, goes to 0x5f7daec; otherwise the pointer
    is reduced by arg3."""
    if bool_out != 0 or ptr_out < arg3:
        return "alt-0x5f7daec"
    return ("continue", ptr_out - arg3)


def site_d_first_use(bool_out, ptr_out):
    """First use in site D: bool nonzero goes to
    0x5f86fcc; otherwise the pointer is stored and the
    pair iteration begins."""
    if bool_out != 0:
        return "alt-0x5f86fcc"
    return ("continue", ptr_out)


def install_wrapper_vtable(obj):
    """Mirror the five vtable installers (0x5fd0090,
    0x6029110, 0x6029230, 0x6029500, 0x6029620): lea the
    vtable header 0x64cdd78, add 0x10, store the result as
    the object's vptr."""
    obj["vptr"] = WRAPPER_VTABLE
    return obj


def entry_install(mode, obj, src_ptr, vtable):
    """Mirror one entry thunk (0x5fcc5d0/0x5fcc600/
    0x5fcc630) for its vtable: mode 0 installs the thunk's
    vtable (0x64cd9d0, 0x64cd9e0 or 0x64cd9f0), mode 1
    stores the given pointer, any other mode leaves the
    object alone. Returns 0 in every path."""
    if mode == 0:
        obj["slot0"] = vtable
    elif mode == 1:
        obj["slot0"] = src_ptr
    return 0


def resolver_fast_path(owner):
    """Mirror the resolver's first read (#3322): a cb8
    other than -1 returns at once without walking."""
    return owner["cb8"] != 0xFFFFFFFFFFFFFFFF
