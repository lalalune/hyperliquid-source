"""Model of the bitmap-node ctor 0x60f4a00 and its nine callers (node #115).

Pure-Python model of the pinned semantics in
research/work-items/RE-001-bitmap-node-callers-115/. Every function
mirrors one routine or one host decision from the raw objdump
excerpts; the layout constants come from the packet's records.json.

Node layout (0x48 bytes):
    +0x00/+0x08/+0x10/+0x18  arg2 struct, moved in (4 x u64)
    +0x20                   arg2+0x00 again (buffer pointer)
    +0x28                   arg2+0x08 again (buffer size)
    +0x30                   adjusted size (u32)
    +0x34                   magnitude (u32)
    +0x38                   inner 0x28-byte node, or None
    +0x40                   trailing u16 tag (u16)
"""

MOD = 0x7FFFFFFF
SEED_MULT = 0x41A7
DESCRIPTOR_LOW = 4
DESCRIPTOR_HIGH = 32  # bitmap-word divisor
INNER_SIZE = 0x28
NODE_SIZE = 0x48
SMALL_ARG_LIMIT = 3
KIND1_SMALL_LIMIT = 5
BIG_SIZE_LIMIT = 0x10000
MAX_BITMAP_WORDS = 0x1FFFFFFFFFFFFFFE


def seed_advance(seed):
    """Shared LCG fold from the ctor: seed = seed * 0x41a7 folded mod
    0x7fffffff (see the 0x60f4b2a..0x60f4b54 sequence)."""
    prod = (seed * SEED_MULT) & 0xFFFFFFFFFFFFFFFF
    total = (prod & MOD) + ((prod >> 31) & 0xFFFFFFFF)
    if total & 0x80000000:
        total = (total - MOD) & 0xFFFFFFFF
    return total & 0xFFFFFFFF


def shift_for_count(count):
    """Inner +0x10 byte: floor(log2(count >> 1)) + 1 when count >= 2,
    else 0."""
    if count < 2:
        return 0
    return (count >> 1).bit_length()


def bitmap_words(adjusted_size, shift):
    """Number of u32 bitmap words: ((size - 1) >> shift) / 32 + 1."""
    return ((adjusted_size - 1) >> shift) // DESCRIPTOR_HIGH + 1


def magnitude(trailing_u32, size):
    """0x60f4840: trailing u32 & 0x7fffffff when size <= 0x10000,
    else the raw trailing u32."""
    if size > BIG_SIZE_LIMIT:
        return trailing_u32 & 0xFFFFFFFF
    return trailing_u32 & MOD


def kind(trailing_u32, size):
    """0x60f48a0: sign bit of the trailing u32 when size <= 0x10000,
    else 0."""
    if size > BIG_SIZE_LIMIT:
        return 0
    return (trailing_u32 >> 31) & 1


def split_value(value):
    """0x612ceb0: (value >> 31, value & 0x7fffffff)."""
    return ((value >> 31) & 1, value & MOD)


def trailing_u16(src, length):
    """0x612ce30: T = *(u16)(src + length - 2); returns (T, length - 2 - T)."""
    t = src[length - 2] | (src[length - 1] << 8)
    return t, (length - 2 - t) & 0xFFFF


class BitmapNode:
    """A 0x48-byte bitmap node as the ctor leaves it."""

    def __init__(self):
        self.buf = None       # +0x20
        self.size = 0         # +0x28
        self.adj = 0          # +0x30 (u32)
        self.mag = 0          # +0x34 (u32)
        self.inner = None     # +0x38
        self.tag = 0          # +0x40 (u16)
        self.arg0 = 0         # +0x00
        self.arg8 = 0         # +0x08
        self.arg10 = 0        # +0x10
        self.arg18 = 0        # +0x18

    def __repr__(self):
        return ("BitmapNode(buf=%r size=%#x adj=%#x mag=%#x "
                "inner=%r tag=%#x)" % (self.buf, self.size, self.adj,
                                       self.mag, self.inner, self.tag))


class InnerNode:
    """The 0x28-byte inner node the ctor allocates for a bitmap."""

    def __init__(self, descriptor_low, descriptor_high, arg4, seed_mod,
                 shift, bitmap):
        self.descriptor = (descriptor_low, descriptor_high)
        self.bitmap = bitmap      # list of u32, zeroed
        self.shift = shift        # +0x10 byte
        self.arg4 = arg4          # +0x18
        self.seed_mod = seed_mod  # +0x20

    def __repr__(self):
        return ("InnerNode(shift=%d words=%d seed_mod=%d)"
                % (self.shift, len(self.bitmap), self.seed_mod))


def ctor(arg2, count, arg4, seed, trailing_u32, tag=None, observer=None):
    """The bitmap-node ctor 0x60f4a00.

    arg2: dict with keys 0x00/0x08/0x10/0x18 (the 0x20-byte struct).
    trailing_u32: the trailing u32 of the buffer (buffer + size - 4),
    supplied by the caller of this model (the binary reads it from
    the buffer itself).
    tag: the trailing u16 tag T, required only on the kind-1-large
    path (the binary reads it from the buffer tail at
    buffer + (u16)(arg2+0x08 - 4) - 2).
    observer: optional callable(arg4, 0x57, adjusted_size) modelling
    the *(arg4 vtable + 0xb0) call.
    Returns (node, new_seed, moved_from_arg2). The moved-from arg2 has
    +0x18 cleared; the caller keeps the rest.
    """
    node = BitmapNode()
    node.arg0 = arg2[0x00]
    node.arg8 = arg2[0x08]
    node.arg10 = arg2[0x10]
    node.arg18 = arg2[0x18]
    node.buf = arg2[0x00]
    node.size = arg2[0x08]
    moved_from = dict(arg2)
    moved_from[0x18] = 0

    if arg2[0x08] <= SMALL_ARG_LIMIT:
        node.size = 0
        return node, seed, moved_from

    node.mag = magnitude(trailing_u32, node.size)
    k = kind(trailing_u32, node.size)

    if k == 0:
        size32 = (node.size - (4 * node.mag + 4)) & 0xFFFFFFFF
        node.adj = size32
        if (node.size - 4) & 0xFFFFFFFFFFFFFFFF < size32:
            node.size = 0
    elif k == 1:
        if node.size <= KIND1_SMALL_LIMIT:
            node.size = 0
        else:
            if tag is None:
                raise ValueError(
                    "kind-1-large needs the trailing u16 tag")
            length = (arg2[0x08] - 4) & 0xFFFF
            out = (length - 2 - tag) & 0xFFFF
            node.tag = tag & 0xFFFF
            node.adj = (out - 4 * node.mag) & 0xFFFFFFFF
            if out < 4 * node.mag:
                node.size = 0
    else:
        node.size = 0
        return node, seed, moved_from

    new_seed = _allocate_bitmap(node, count, arg4, seed, observer)
    return node, new_seed, moved_from


def ctor_with_tag(arg2, count, arg4, seed, trailing_u32, tag,
                  observer=None):
    """Ctor variant for the kind-1-large path, where the trailing u16
    tag T is supplied explicitly. Same as ctor(..., tag=tag)."""
    return ctor(arg2, count, arg4, seed, trailing_u32, tag=tag,
                observer=observer)


def _allocate_bitmap(node, count, arg4, seed, observer):
    """The bitmap-allocation tail of the ctor (0x60f4aed onward).
    Returns the (possibly advanced) seed; the node is mutated in
    place. Returns the seed unchanged when no bitmap is built."""
    if count == 0 or arg4 == 0 or node.size == 0:
        return seed
    new_seed = seed_advance(seed)
    shift = shift_for_count(count)
    words = bitmap_words(node.adj, shift)
    if words > MAX_BITMAP_WORDS:
        raise ValueError("bitmap too large: %d words" % words)
    inner = InnerNode(DESCRIPTOR_LOW, DESCRIPTOR_HIGH, arg4,
                      new_seed % count, shift, [0] * words)
    if observer is not None:
        observer(arg4, 0x57, node.adj)
    node.inner = inner
    return new_seed


def dtor_actions(node):
    """The dtor 0x60f4900: which allocations it frees, in order.
    Returns a list of ("delete_array", ptr) / ("delete_sized", ptr, size)
    / ("vtable_call", slot, obj) actions."""
    actions = []
    if node.inner is not None:
        if node.inner.bitmap is not None:
            actions.append(("delete_array", "inner+0x08"))
        actions.append(("delete_sized", "inner", INNER_SIZE))
    if node.arg18 != 0:
        if node.arg10 != 0:
            actions.append(("vtable_call", 0xA0, "node+0x10"))
        else:
            actions.append(("delete_array", "node+0x18"))
    return actions


def factory_path(node):
    """The factory 0x60f4d10 path selection: 'A' (node+0x28 > 7 and
    node+0x34 != 0), 'B' (node+0x28 > 7 and node+0x34 == 0), or 'C'
    (node+0x28 <= 7, the 'bad block contents' report)."""
    if node.size > 7:
        return "A" if node.mag != 0 else "B"
    return "C"


def materialize_path(node, has_arg4):
    """The materialize 0x60f50c0 path selection: 'fresh' (no arg4),
    'fill' (arg4, node+0x28 > 7, node+0x34 != 0), 'teardown' (arg4,
    node+0x28 > 7, node+0x34 == 0), or 'report' (arg4,
    node+0x28 <= 7)."""
    if not has_arg4:
        return "fresh"
    if node.size > 7:
        return "fill" if node.mag != 0 else "teardown"
    return "report"


def slot_release(slot):
    """The slot-release 0x6106790 decision: 'chain' (slot+0x10 != 0),
    'flag_delete' (slot+0x10 == 0 and slot+0x18 flag != 0), or
    'nothing'."""
    if slot[0x10] != 0:
        return "chain"
    if slot[0x18] != 0:
        return "flag_delete"
    return "nothing"


def reset_helper(old_ptr, new_node):
    """The five reset helpers 0x612a800..0x612aa80: store the fresh node
    into the unique_ptr slot; the old node is destroyed (dtor + sized
    delete 0x48) when non-null. Returns the actions taken."""
    actions = [("store", new_node)]
    if old_ptr is not None:
        actions.append(("dtor", old_ptr))
        actions.append(("delete_sized", old_ptr, NODE_SIZE))
    return actions


def poll_copy(result_byte, arg2_0, arg2_8):
    """The poll-copy 0x61841a0 decision: 'copy' when the result byte or
    either arg2 qword is non-zero, else 'report_then_copy' (the
    'Cannot find the meta block' report first)."""
    if result_byte != 0 or arg2_0 != 0 or arg2_8 != 0:
        return "copy"
    return "report_then_copy"


def reset_helper_args(helper, arg1, arg3):
    """The reset helpers' (count, arg4) mapping from their arguments.
    helper: 'a'..'e'; arg1: the first argument; arg3: the third."""
    if helper == "a":
        return (arg1[0xCC], arg1[0x08])
    return (0, arg1[0x08])
