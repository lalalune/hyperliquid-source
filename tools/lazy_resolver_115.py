"""Model of the node #115 lazy one-time resolver 0x5f074e0 and
its canonical chain-walk continuation 0x5d4b100.

The resolver pins one owner field, owner+0xcb8, the first time
it is needed. The field starts at the -1 sentinel (the low
qword of the 16-byte constant at 0x456590, installed by the
owner-tail init in #3304); the chain head sits at owner+0xc70
(the pair {*(options+0x210), *(options+0x300)} from #3304).
The resolver walks the chain linked through each node's +0x20
field, comparing each node's vtable slot 0xc0 against the
canonical resolver 0x5d4b100 (held in GOT slot 0x64ed3e8), and
calls the first non-canonical slot 0xc0 with
(bool_out, node, value_out). The callee fills the value, a
skip-cache bool, and an owned heap pointer. When the bool is
false the value is installed into owner+0xcb8 with a lock
cmpxchg against the -1 sentinel; when true nothing is
installed. The owned pointer, when present, is freed with
delete[] either way. A later call returns at once because
owner+0xcb8 is no longer -1.

The canonical continuation 0x5d4b100 is the same walk resumed
one node further down: it advances past the node it was called
on, compares eight more levels, and calls the ninth level's
slot unconditionally (which recurses into itself when that
slot is canonical too).

Chain nodes are modelled as {'slot24': callable | None,
'next': node id | None}; None means the canonical 0x5d4b100.
A slot-24 callback takes (node id, out dict) and fills out
with {'value': int, 'skip_cache': bool, 'owned': object|None}.
A null chain link where the binary would dereference it is a
model error (ValueError), matching the binary faulting.
"""

SENTINEL = 0xFFFFFFFFFFFFFFFF
RESOLVER = 0x5F074E0
CANONICAL = 0x5D4B100
ONCE_HELPER = 0x5F07490
ONCE_PREDICATE = 0x5F07300
GOT_CANONICAL_SLOT = 0x64ED3E8
CHAIN_LINK = 0x20
SLOT24 = 0xC0
CB8 = 0xCB8
C70 = 0xC70
SENTINEL_CONSTANT = 0x456590
# The 16 bytes at 0x456590: {0xffffffffffffffff, 0}.
SENTINEL_CONSTANT_BYTES = bytes.fromhex("ffffffffffffffff0000000000000000")

INLINE_LEVELS = 4
CANONICAL_LEVELS = 8


def fresh_owner(chain_head=None):
    """An owner as the tail init leaves it: cb8 unresolved."""
    return {"cb8": SENTINEL, "c70": chain_head,
            "c18": 0, "c60": 0, "c30": 0}


def callsite_gate(owner):
    """Whether 0x5f0e890 runs the once helper + resolver on the
    owner: *(owner+0xc18) != 0, and not (*(owner+0xc60) != 0
    and *(owner+0x30) != 0), which takes the 0x5f0f0a7 path
    instead. The +0xc18 writer is an open unknown."""
    return owner["c18"] != 0 and not (
        owner["c60"] != 0 and owner["c30"] != 0)


def _call_slot(chain, node_id, out, invoked):
    """Invoke one node's slot 0xc0; record the invocation."""
    invoked.append(node_id)
    slot = chain[node_id]["slot24"]
    if slot is None:
        raise ValueError("canonical slot called directly")
    slot(node_id, out)
    return out


def canonical_walk(chain, node_id, out, invoked):
    """Mirror 0x5d4b100. Advances past node_id first (the
    caller already found that node's slot canonical), then
    compares eight levels and calls the ninth unconditionally,
    recursing when that slot is canonical too."""
    node = chain[node_id]["next"]
    if node is None:
        raise ValueError("null chain link in canonical walk")
    for _level in range(CANONICAL_LEVELS):
        if chain[node]["slot24"] is not None:
            return _call_slot(chain, node, out, invoked)
        node = chain[node]["next"]
        if node is None:
            raise ValueError("null chain link in canonical walk")
    if chain[node]["slot24"] is not None:
        return _call_slot(chain, node, out, invoked)
    return canonical_walk(chain, node, out, invoked)


def resolve(owner, chain, invoked=None, lock=None):
    """Mirror 0x5f074e0. Returns (installed, freed) where
    installed is True when the value was cmpxchg-installed
    into owner+0xcb8, and freed lists the owned pointers the
    resolver released with delete[]. Already-resolved owners
    return at once with no slot invoked. The optional lock
    serialises only the check-and-install, mirroring the
    binary's atomic lock cmpxchg: two racing resolvers may
    both run the slot call, but exactly one installs."""
    if invoked is None:
        invoked = []
    if owner["cb8"] != SENTINEL:
        return (False, [])
    head = owner["c70"]
    if head is None:
        raise ValueError("null chain head with unresolved cb8")
    out = {"value": 0, "skip_cache": False, "owned": None}
    node = head
    called = False
    for _level in range(INLINE_LEVELS):
        if chain[node]["slot24"] is not None:
            _call_slot(chain, node, out, invoked)
            called = True
            break
        node = chain[node]["next"]
        if node is None:
            raise ValueError("null chain link in resolver walk")
    if not called:
        if chain[node]["slot24"] is not None:
            _call_slot(chain, node, out, invoked)
        else:
            canonical_walk(chain, node, out, invoked)
    freed = []
    installed = False
    if not out["skip_cache"]:
        if lock is not None:
            with lock:
                if owner["cb8"] == SENTINEL:
                    owner["cb8"] = out["value"] & SENTINEL
                    installed = True
        elif owner["cb8"] == SENTINEL:
            owner["cb8"] = out["value"] & SENTINEL
            installed = True
    if out["owned"] is not None:
        freed.append(out["owned"])
    return (installed, freed)


def chain_depth_to_winner(chain, head):
    """Number of canonical nodes skipped before the first
    non-canonical slot, or None when the chain has no winner
    before a null link."""
    depth = 0
    node = head
    while node is not None:
        if chain[node]["slot24"] is not None:
            return depth
        node = chain[node]["next"]
        depth += 1
    return None


def winner_at_level(chain, head, level):
    """The node id at a 1-based chain level, or None."""
    node = head
    for _ in range(level - 1):
        if node is None:
            return None
        node = chain[node]["next"]
    return node
