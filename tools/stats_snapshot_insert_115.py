"""Model of node #115's stats-snapshot insert and its caller.

Reconstruction of the pipeline pinned by
research/work-items/RE-001-stats-snapshot-insert-115/ (RE-001):

  caller 0x5d4cc80 (builds the 0x70-byte snapshot node, two
  vtable types selected by the flag at source+0x4c9)
    -> type A: node_init 0x606c680 (locked lookup 0x5d52660)
    -> type B: insert 0x606ef50 (drives the source iterator,
       parses #-delimited keys, rebuilds the embedded map)
    -> owner vtable slot 7 (copies the node's header into the owner)

The node holds an embedded std::map<std::string, u64> at +0x28,
a flag byte at +0x60 and a back-pointer to the source at +0x68.
The insert replaces the node's map with a freshly built one; the
old tree is freed. The iterator behind the source object is
virtual, so the model takes its entries as (key view, value
view) pairs in iteration order and pins everything else from
the binary: the state-init bytes, the %010d seek format, the
delimited-key parse, the version-key skip, the decimal value
parse, the lower-bound duplicate rule (first occurrence wins),
the map-node layout and the three merge cases.

Status is the 16-byte layout pinned by PR #3202: code at +0x00
(u16), subcode at +0x02 (u32), message pointer at +0x08.
Code 4 is InvalidArgument. The only Status this work item
produces is the caller's "stats_iterator not preallocated."
"""

import functools

FORMAT_VERSION_KEY = b"__persistent_stats_format_version__"
COMPATIBLE_VERSION_KEY = b"__persistent_stats_compatible_version__"
SEEK_FORMAT = "%010d"
NOT_PREALLOCATED_MSG = "stats_iterator not preallocated."
DELIMITER = b"#"
MAX_U64 = (1 << 64) - 1
NODE_SIZE = 0x70
MAP_NODE_SIZE = 0x48
SSO_LIMIT = 15

INSERT_ADDR = 0x606EF50
CALLER_ADDR = 0x5D4CC80
WRAPPER_ADDR = 0x606F920
VTABLE_A = 0x64D2C28
VTABLE_B = 0x64D2C90
SLOTS_A = [0x606C5E0, 0x606C660, 0x606C180, 0x606C6B0,
           0x606C190, 0x606C170, 0x606C1A0, 0x606C1E0]
SLOTS_B = [0x606E250, 0x606E2D0, 0x606DDF0, 0x606F920,
           0x606DE00, 0x606C170, 0x606DE10, 0x606DE50]

OK = 0
INVALID_ARGUMENT = 4


class Status:
    """The 16-byte Status: code, subcode, message (or None)."""

    def __init__(self, code=OK, subcode=0, message=None):
        self.code = code
        self.subcode = subcode
        self.message = message

    def ok(self):
        return self.code == OK

    def copy(self):
        return Status(self.code, self.subcode,
                      None if self.message is None else str(self.message))


def state_init_bytes():
    """The 0x90-byte struct 0x60b21f0 writes: all zero except
    +0x2c = 0x101, +0x78 = -1, +0x84 = 4, +0x88 = 0x100.
    Its second argument is never read."""
    buf = bytearray(0x90)
    buf[0x2C:0x34] = (0x101).to_bytes(8, "little")
    buf[0x78:0x80] = MAX_U64.to_bytes(8, "little")
    buf[0x84:0x88] = (4).to_bytes(4, "little")
    buf[0x88:0x8A] = (0x100).to_bytes(2, "little")
    return bytes(buf)


def format_seek_bound(node_count, bound):
    """The %010d seek key: max(node+0x8, bound) as 10 digits."""
    return (SEEK_FORMAT % max(node_count, bound)).encode("ascii")


def compare_keys(a, b):
    """0x5d498c0: memcmp on the common prefix, else the length
    difference clamped to the int32 range."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return a[i] - b[i]
    diff = len(a) - len(b)
    if diff > 0x7FFFFFFF:
        return 0x7FFFFFFF
    if diff < -0x80000000:
        return -0x80000000
    return diff


_SUFFIX_SHIFTS = {ord("K"): 10, ord("M"): 20, ord("G"): 30, ord("T"): 40,
                  ord("k"): 10, ord("m"): 20, ord("g"): 30, ord("t"): 40}


def parse_decimal(text):
    """0x61d1540: decimal parser built on strtoull. Leading
    whitespace is skipped, an optional + or - sign applies (a
    leading - wraps modulo 2**64), then digits are consumed. The
    single character right after the digits may be a suffix
    letter (K/M/G/T, case-insensitive) shifting left by
    10/20/30/40 with bits shifted out lost; anything else, and
    anything after the suffix, is ignored. No digits at all
    raises ValueError (invalid_argument); a strtoull overflow
    raises OverflowError (out_of_range)."""
    if isinstance(text, bytes):
        text = text.decode("latin-1")
    i = 0
    while i < len(text) and text[i] in " \t\n\v\f\r":
        i += 1
    negative = False
    if i < len(text) and text[i] in "+-":
        negative = text[i] == "-"
        i += 1
    start = i
    while i < len(text) and text[i].isdigit():
        i += 1
    if i == start:
        raise ValueError("invalid_argument: no digits in %r" % text)
    value = int(text[start:i])
    if value > MAX_U64:
        raise OverflowError("out_of_range: %r" % text)
    if i < len(text):
        shift = _SUFFIX_SHIFTS.get(ord(text[i]))
        if shift is not None:
            value = (value << shift) & MAX_U64
    if negative:
        value = (-value) & MAX_U64
    return value


def parse_delimited_key(text, bound):
    """0x606eb60: parse a #-delimited versioned key. Returns
    (sequence, key). No '#' -> (2**64-1, b''). The prefix before
    the first '#' is decimal-parsed; a parsed value below the
    bound (unsigned) -> (2**64-1, b''). Otherwise the sequence
    is the parsed value and the key is the suffix after '#'
    (empty when '#' is the last byte)."""
    if isinstance(text, str):
        text = text.encode("latin-1")
    pos = text.find(DELIMITER)
    if pos < 0:
        return MAX_U64, b""
    sequence = parse_decimal(text[:pos])
    if sequence < bound:
        return MAX_U64, b""
    return sequence, text[pos + 1:]


class MapNode:
    """One 0x48-byte map entry: key string at +0x20 (SSO inline
    at +0x30 when len <= 15, heap otherwise, NUL at +0x30+len),
    value u64 at +0x40."""

    def __init__(self, key, value):
        self.key = bytes(key)
        self.value = value & MAX_U64
        self.heap = len(self.key) > SSO_LIMIT

    def __repr__(self):
        return "MapNode(key=%r, value=%d, heap=%s)" % (
            self.key, self.value, self.heap)


class SnapshotNode:
    """The 0x70-byte snapshot node. `fields` holds the scalar
    slots; `entries` is the embedded map (key bytes -> value),
    kept in first-insertion order for the model and compared
    with compare_keys wherever order matters."""

    def __init__(self, node_type, source, lower, upper):
        self.node_type = node_type  # "A" or "B"
        self.source = source
        self.fields = {
            "bound": 0,          # +0x08
            "lower": lower,      # +0x10
            "upper": upper,      # +0x18
            "payload": None,     # +0x20 (fresh-allocation contents)
            "header_u32": 0,     # +0x50
            "header_u16": 0,     # +0x54
            "header_ptr": None,  # +0x58
            "flag": 1,           # +0x60
        }
        self.entries = {}
        self.released = False

    @property
    def vtable(self):
        return VTABLE_A if self.node_type == "A" else VTABLE_B

    @property
    def flag(self):
        return self.fields["flag"]

    def slot2_flag(self):
        return self.fields["flag"]

    def slot4_bound(self):
        return self.fields["bound"]

    def slot5(self):
        return -1

    def slot6_payload_ptr(self):
        return "node+0x20"

    def delete(self):
        """Slot 0 destructor: free +0x58, free every map entry."""
        self.fields["header_ptr"] = None
        self.entries = {}
        self.released = True

    def deleting_delete(self):
        self.delete()

    def slot7_copy_header(self, owner):
        """Slot 7: copy the node's header into the owner."""
        owner["header_u32"] = self.fields["header_u32"]
        owner["header_u16"] = self.fields["header_u16"]
        owner["header_ptr"] = (None if self.fields["header_ptr"] is None
                               else str(self.fields["header_ptr"]))
        return owner


def node_init(node, lower, upper, source_tree):
    """0x606c680 + 0x5d52660: the flag-0 (type A) fill. Looks up
    the first tree node with key in [lower, upper); on a hit
    writes the key into node+0x08 and deep-copies that node's
    map into node+0x20's map slot, returning 1; on a miss
    returns 0 and writes nothing. `source_tree` is a sorted
    list of (key, map-dict) pairs. Sets node+0x60 to the result."""
    found_key, found_map = locked_lookup(source_tree, lower, upper)
    if found_key is None:
        node.fields["flag"] = 0
        return 0
    node.fields["bound"] = found_key
    node.fields["payload"] = dict(found_map)
    node.fields["flag"] = 1
    return 1


def locked_lookup(tree, lower, upper):
    """0x5d52660: first tree node with key in [lower, upper).
    Returns (key, map) on a hit, (None, None) on a miss."""
    for key, entries in tree:
        if lower <= key < upper:
            return key, dict(entries)
    return None, None


def map_copy(dst, src):
    """0x5d4e140: deep-copy the src map into dst (old dst tree
    cleared first)."""
    dst.clear()
    dst.update(dict(src))


def lower_bound_position(entries, key):
    """0x5d6c600: returns (parent_key, insert_pos) where
    insert_pos is None when the key already exists, the string
    'header' when it sorts after every entry, else the first
    entry key >= the new key."""
    ordered = sorted(entries, key=functools.cmp_to_key(compare_keys))
    for existing in ordered:
        if compare_keys(key, existing) == 0:
            return existing, None
        if compare_keys(key, existing) < 0:
            return existing, existing
    return None, "header"


def insert(node, bound, upper, source_bound, entries):
    """0x606ef50: rebuild the node's map from the iterator's
    entries. `entries` is the iterator's (key view, value view)
    pairs in iteration order; `source_bound` is *(source+0xac0).
    Returns the node. The state struct, the seek key and the
    produce call are recorded, not executed (the iterator is
    virtual)."""
    if node.source is None:
        node.fields["flag"] = 0
        return node
    _state = state_init_bytes()
    _seek = format_seek_bound(node.fields["bound"], bound)
    _produced = (node.source, _state, source_bound)
    if not entries:
        node.fields["flag"] = 0
        node.released = True
        return node
    first_key, _first_value = entries[0]
    first_seq, _first_suffix = parse_delimited_key(first_key, bound)
    node.fields["bound"] = first_seq
    if first_seq > upper:
        node.fields["flag"] = 0
        node.released = True
        return node
    node.fields["flag"] = 1
    local = {}
    for key_view, value_view in entries:
        _seq, suffix = parse_delimited_key(key_view, bound)
        if suffix == FORMAT_VERSION_KEY and len(suffix) == 35:
            continue
        sequence = parse_decimal(value_view)
        _parent, pos = lower_bound_position(list(local), suffix)
        if pos is None:
            continue
        local[suffix] = sequence
    node.entries = local
    node.released = True
    return node


def wrapper_refresh(node, source_bound, entries):
    """Type B slot 3 (0x606f920): insert(node, 1+*(node+0x8),
    *(node+0x18))."""
    return insert(node, 1 + node.fields["bound"],
                  node.fields["upper"], source_bound, entries)


def slot3_a_refresh(node, lower, upper, source_tree):
    """Type A slot 3 (0x606c6b0): node_init(node, 1+*(node+0x8),
    *(node+0x18))."""
    return node_init(node, 1 + node.fields["bound"],
                     node.fields["upper"], source_tree)


def caller_build(owner, source, lower, upper, slot, source_tree=None,
                 source_bound=0, entries=None):
    """0x5d4cc80: build the snapshot node and hand it off.
    `source` is None when the source object is absent; `slot`
    is a dict with a 'node' key (the snapshot slot, r8). When
    the slot itself is None the InvalidArgument Status is
    returned. Returns (status, node_or_None)."""
    if slot is None:
        return Status(INVALID_ARGUMENT, 0, NOT_PREALLOCATED_MSG), None
    flag_nonzero = bool(source.get("flag_4c9", 0)) if source else False
    node_type = "B" if flag_nonzero else "A"
    node = SnapshotNode(node_type, source, lower, upper)
    if not flag_nonzero:
        node_init(node, lower, upper, source_tree or [])
    else:
        insert(node, lower, upper, source_bound, entries or [])
    old = slot.get("node")
    slot["node"] = node
    if old is not None:
        old.deleting_delete()
    node.slot7_copy_header(owner)
    return Status(), node
