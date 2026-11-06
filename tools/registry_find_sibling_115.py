"""RE-001: pin node #115 registry Find through the sibling entry
point 0x609a740: the flag-chain node resolution, the name dispatch
(exact name, 'id', the '.id' suffix, the node-name-plus-dot
compare), the '=' / ';' helper 0x6099e70, the no-'=' helper
0x609ba30, the kind dispatcher 0x609b700 with its recursive
kind-0x16 call, the element scan 0x6096f40 and the name lookup
0x60ba0b0 with its dotted-name fallback.

Bounded question: after the host 0x6077820 has decided a name is
not the default and not "BasicStatistics", how does node #115
resolve that name through the sibling Find entry point
0x609a740 -- the second entry point next to find_entry
0x609e510, left open by #3485 -- and what does it report when
the name cannot be resolved?

Behaviour, pinned from the node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

  * Entry 0x609a740 (out, value, delegate, desc, name5, key6,
    arg7, base8): the node address is base8 + the i64 at
    desc+0x00 (null when base8 is null), followed through one
    pointer load when any of desc+0xb0 flags 0x200/0x400/0x800
    is set. The 0x50-byte value struct is copied (the +0x48
    control use-count incremented; the copy is released on
    every exit path). When desc+0xb1 bit 0 is set, the copy's
    +0x04 byte is cleared. The name dispatch: name5 == key6
    -> the delegate's slot-0x50; key6 == "id" (length 2,
    first two bytes 0x6469) -> slot-0x50; otherwise the '.id'
    path. When desc+0xb1 is clear and the value's +0x04 byte
    is 0 the same dispatch runs; when it is non-zero, a
    non-null node takes the '.id' variant-2 path, a null node
    with a non-empty arg7 reports Status code 4
    "Option not changeable: " + name5, and a null node with
    an empty arg7 clears out and returns success.
  * The '.id' path, variant 1: name5 ends with ".id"
    (0x61d1390) -> slot-0x50; arg7 empty -> clear out,
    success; node null -> slot-0x50; otherwise the node's
    slot-0x78 name plus "." is compared with key6
    (0x61d13e0): unequal -> slot-0x50; equal -> arg7 with '='
    runs the '=' helper 0x6099e70, arg7 without '=' runs the
    no-'=' helper 0x609ba30.
  * The '.id' path, variant 2: name5 ends with ".id", or
    key6 == "id" -> the node-name compare: the node's
    slot-0x78 name is compared with arg7; equal -> when the
    parsed map is empty clear out and return success,
    otherwise the fallback delegate 0x6097150 runs
    (delegate_impl with the value copy and the map); unequal
    -> Status code 4 "Option not changeable: " + name5.
    name5 == key6 (and neither of the above) -> the
    find_norm path: an empty options map and an empty
    out-string are built, the node's slot-0x78 name is the
    fallback, find_norm 0x609a410 runs on arg7; a non-zero
    find_norm status is copied into out and returned; on
    success the slot-0x78 name is fetched again and compared
    with find_norm's out-string: equal -> the map-empty
    check above, unequal -> the code-4 error. Otherwise
    (name5 != key6, not "id", no ".id" suffix) -> the no-'='
    helper 0x609ba30.
  * The slot-0x50 call is slot(out, delegate, value-copy,
    desc, key6, arg7, base8) through the delegate's vtable.
    The entry has exactly one direct call site in the binary
    (0x609b80f inside kind_dispatch 0x609b700, the recursive
    kind-0x16 call); its top-level reach is through an
    indirect slot that is not pinned here.
  * find_e70 0x6099e70 (out, node, value, arg7): out zeroed;
    arg7 empty, or a step that leaves out with code 0, falls
    to the value's +0x03 byte check: 0 -> return; non-zero
    -> the node's vtable slot 0x28 fills a temp Status from
    (node, value) and the temp is moved into out. A ';' or
    '=' anywhere in arg7 takes the parse path: a fresh empty
    options map, the parser 0x60c1190 on arg7 into that map,
    the parser Status moved into out, and only on parser
    success the delegate implementation 0x6097110 runs with
    (node, value, map, flag 0), i.e. the node's vtable slot
    0x48; the map is then destroyed. Neither ';' nor '=':
    the node's vtable slot 0x40 is compared with the zero
    stub 0x60956f0; when it IS the stub, out is zeroed
    outright; otherwise slot 0x40 fills a temp Status from
    (node, value), the six bytes plus the message pointer
    are copied into out, and a non-zero code returns at once.
  * no_equals 0x609ba30 (out, node, value, key6, arg7):
    forwards to resolve_no_equals 0x609b8a0 and returns out.
  * resolve_no_equals 0x609b8a0 (out, value, node, key6,
    arg7): the node's vtable slot 0x68 fills a string from
    (node, key6); that string is the key for the element scan
    0x6096f40 over the node's +0x08 vector, with a fresh
    empty string as the lookup out-string and an 8-byte slot
    that receives the matched element's +0x20 field. A null
    scan result builds Status code 1 with msg1
    "Could not find option: " and msg2 = key6; otherwise
    kind_dispatch 0x609b700 runs with (out, value, node,
    found, slot-0x68 string, lookup out-string, arg7, the
    element's +0x20 field).
  * kind_dispatch 0x609b700 (out, value, node, found, str_a,
    str_b, arg7, extra): kind = the u32 at found+0xa8 (the
    matched node+0xd0). Kind 0x16 recurses into the entry
    0x609a740 with (out, value, node, found, str_b, str_b,
    arg7, extra). Otherwise, when str_a equals str_b the
    node's vtable slot 0x50 is called with (out, node,
    value, found, str_b, arg7, extra). Otherwise kind 0x13
    or 0x15 takes the same slot-0x50 call, and any other
    kind builds Status code 1 with msg1
    "Could not find option: " and msg2 = str_b.
  * element_scan 0x6096f40 (vector, key, out3, found_out):
    walks the 0x30-byte elements (stride 0x30); per element
    the name string at +0x00/+0x08 is copied; when the
    element's +0x28 pointer is non-null the name lookup
    0x60ba0b0 runs with (key, element+0x28, out3); on a
    non-null lookup result the element's +0x20 field (8
    bytes) is stored into found_out and the lookup result
    is returned; no element matching returns null.
  * name_lookup 0x60ba0b0 (key, table, out): while the table
    count is <= 20 a linear list walk (node+0x10 length,
    then memcmp on node+0x08), otherwise the hash-bucket
    find 0x60b84b0. On an exact match the key string is
    move-assigned into out (0x60b79e0) and the matched
    node's +0x28 field address is returned. On a miss the
    key is searched for '.': no '.' or '.' at position 0
    returns null. Otherwise the prefix key[0..pos] is
    searched the same way; when the prefix matches a node
    whose kind at +0xd0 is 0x13, 0x15 or 0x16, the suffix
    key[pos+1..] is move-assigned into out and the matched
    node's +0x28 field address is returned; a prefix match
    of any other kind returns null.
  * hash_name_find 0x60b84b0 (key, table): _Hash_bytes(key,
    len, 0xc70f6907) % the bucket count selects the bucket;
    the chain is walked comparing the stored hash at
    node+0xe0, then the name length at node+0x10, then
    memcmp on node+0x08. A node whose hash falls in a
    different bucket ends the walk.
  * move_assign 0x60b79e0 (dst, src): std::string
    move-assignment; the model copies the value (Python
    strings are immutable, so the transfer is
    observationally identical).
  * ends_with 0x61d1390 (haystack, suffix): 1 when the
    suffix fits and the haystack's last len(suffix) bytes
    equal it, else 0; an empty suffix returns 1.
  * str_compare 0x61d13e0 (a, b): lexicographic compare:
    memcmp over the shorter length, else the signed length
    difference (clamped to int32).
  * zero_stub 0x60956f0 (out): the default vtable slot-0x40
    implementation; zeroes the 16-byte Status and returns
    out. find_e70 compares a node's slot 0x40 against this
    address (lea at 0x609a0d7) to decide whether to call the
    slot or zero out directly.
  * delegate_impl 0x6097110 (out, obj, value, ctx_map,
    flag): calls the object's vtable slot 0x48 with all five
    arguments. fallback_delegate 0x6097150 (out, obj, value,
    ctx_map): calls delegate_impl with flag 0.
  * find_norm 0x609a410, the parser 0x60c1190, the options
    map and the Status builder 0x61cf670 are re-used from
    the RE-001-registry-find-115 model (#3485); the
    find_norm argument order recorded here is corrected to
    (out, name, fallback, out-string, ctx-map). The
    serializer 0x60ba600 stays a boundary.

Open unknowns carried in the packet (see README): the
entry's top-level reach (one direct call site only, the
recursive kind-0x16 call); the recursive call's flag-chain
inputs (the matched record's +0x28 first field and its
+0xb0/+0xb1 descriptor fields); the runtime contents of
the global default name at 0x6508980; the delegate vtable
base; the serializer's per-kind rules; the value struct's
+0x48 control vtable base; which construction paths
install a non-null +0x28 delegate.
"""

# --- Pinned addresses (node #115) -------------------------------------

ENTRY = 0x609A740
FIND_E70 = 0x6099E70
NO_EQUALS = 0x609BA30
RESOLVE_NO_EQUALS = 0x609B8A0
KIND_DISPATCH = 0x609B700
ELEMENT_SCAN = 0x6096F40
NAME_LOOKUP = 0x60BA0B0
HASH_NAME_FIND = 0x60B84B0
MOVE_ASSIGN = 0x60B79E0
ENDS_WITH = 0x61D1390
STR_COMPARE = 0x61D13E0
FALLBACK_DELEGATE = 0x6097150
DELEGATE_IMPL = 0x6097110
ZERO_STUB = 0x60956F0
FIND_NORM = 0x609A410
PARSER = 0x60C1190
MAP_CLEAR = 0x5D5B300
STATUS_BUILDER = 0x61CF670
SHARED_RELEASE = 0x5D35070

# __libc_single_threaded, consulted by the shared-control release
# paths (0x64ed290, R_X86_64_GLOB_DAT).
LIBC_SINGLE_THREADED = 0x64ED290

LINEAR_WALK_LIMIT = 20
HASH_SEED = 0xC70F6907
VALUE_SIZE = 0x50
MAX_STRING_LEN = 0x3FFFFFFFFFFFFFFF

NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4
OPTION_NOT_FOUND = 1

# The global default name at 0x6508980: its runtime contents are
# set by static init and were not located in this cycle (open
# unknown carried from #3440). The model takes the value as a
# parameter; "default" is the documented assumption (a "default"
# literal sits at 0x44371c in .rodata).
DEFAULT_NAME = "default"

DELIMITERS = "={};"
MSG_MISMATCHED_PAIR = "Mismatched key value pair, '=' expected"
MSG_UNEXPECTED_CHAR = "Unexpected char in key"
MSG_EMPTY_KEY = "Empty key found"
MSG_MISMATCHED_BRACES = "Mismatched curly braces for nested options"
MSG_UNEXPECTED_AFTER_NESTED = "Unexpected chars after nested options"
MSG_CANNOT_SERIALIZE = "Cannot serialize option: "
MSG_CANNOT_CONFIGURE_NULL = "Cannot configure null object "
# Both message literals already end in ": " (23 chars each, read
# back from .rodata), and the status builder 0x61cf670 appends
# ": " before a non-empty second string, so the messages the
# binary actually produces contain ": : " -- e.g. "Could not
# find option: : foo". That is the binary's own quirk, not a
# model typo; the tests pin it.
MSG_COULD_NOT_FIND = "Could not find option: "
MSG_OPTION_NOT_CHANGEABLE = "Option not changeable: "

MASK64 = (1 << 64) - 1


def hash_bytes(data, seed=HASH_SEED):
    """libstdc++ _Hash_bytes (MurmurHash64A, m 0xc6a4a7935bd1e995,
    r 47). Same implementation as tools/registry_create_115.py,
    verified there against the system libstdc++."""
    if isinstance(data, str):
        data = data.encode()
    m = 0xC6A4A7935BD1E995
    r = 47
    h = (seed ^ ((len(data) * m) & MASK64)) & MASK64
    i = 0
    n = len(data)
    while i + 8 <= n:
        k = int.from_bytes(data[i:i + 8], "little")
        k = (k * m) & MASK64
        k ^= k >> r
        k = (k * m) & MASK64
        h ^= k
        h = (h * m) & MASK64
        i += 8
    if i < n:
        k = int.from_bytes(data[i:], "little")
        h ^= k
        h = (h * m) & MASK64
    h ^= h >> r
    h = (h * m) & MASK64
    h ^= h >> r
    return h


class Status:
    """The 16-byte result struct written by 0x61cf670: {code u8
    +0x00, subcode u8 +0x01, severity u8 +0x02, u16 zero +0x03,
    u8 zero +0x05, msg char* +0x08}. The message is msg1, or
    msg1 + ": " + msg2 when the second string is non-empty."""

    def __init__(self, code=0, subcode=0, msg=None, severity=0):
        self.code = code
        self.subcode = subcode
        self.severity = severity
        self.msg = msg

    @classmethod
    def ok(cls):
        return cls(0, 0, None, 0)

    @classmethod
    def build(cls, code, subcode, msg1, msg2=None, severity=0):
        """0x61cf670: msg1 + ": " + msg2 when msg2 is non-empty."""
        if msg2:
            msg = msg1 + ": " + msg2
        else:
            msg = msg1
        return cls(code, subcode, msg, severity)

    def is_ok(self):
        return self.code == 0

    def __eq__(self, other):
        return (isinstance(other, Status)
                and self.code == other.code
                and self.subcode == other.subcode
                and self.severity == other.severity
                and self.msg == other.msg)

    def __repr__(self):
        return "Status(code=%d, subcode=%d, severity=%d, msg=%r)" % (
            self.code, self.subcode, self.severity, self.msg)


class MapNode:
    """One 0x50-byte options-map node: {next +0x00, key string
    +0x08, value string +0x28, hash +0x48}. The single next
    pointer serves both the before-begin list and the bucket
    chains (libstdc++ buckets point into the same list)."""

    def __init__(self, key, value=""):
        self.key = key
        self.value = value
        self.hash = hash_bytes(key)
        self.next = None


class OptionsMap:
    """An unordered_map<string, string> in the binary's layout:
    buckets, bucket_count, before-begin list, element count,
    max_load_factor 1.0, next_resize, single_bucket. find
    0x609a1b0, erase 0x609a2f0, operator[] 0x60c0e90, clear
    0x5d5b300. Buckets hold the node *before* the first node of
    the bucket (the libstdc++ before-begin trick); the bucket
    for a list-head first node holds the before-begin sentinel
    (the map's +0x10 field), and an empty bucket holds None.
    Same-bucket nodes stay contiguous in the list."""

    PRIMES = [2, 3, 5, 7, 11, 13, 17, 23, 29, 37, 47, 59, 71, 89,
              109, 131, 163, 197, 239, 293, 353, 431, 521, 631,
              761, 919, 1103, 1327, 1597, 1931, 2333, 2801, 3371,
              4049, 4861, 5839, 7013, 8419, 10103, 12143, 14591,
              17519, 21023, 25229, 30293, 36353, 43627, 52361,
              62851, 75431, 90523, 108631, 130363, 156437, 187751,
              225307, 270371, 324449, 389357, 467237, 560689]

    # The before-begin sentinel: the map's +0x10 field address.
    SENTINEL = object()

    def __init__(self, bucket_count=1):
        self.bucket_count = bucket_count
        self.buckets = [None] * bucket_count
        self.first = None
        self.element_count = 0
        self.max_load_factor = 1.0
        self.next_resize = 0

    def _nodes(self):
        node = self.first
        while node is not None:
            yield node
            node = node.next

    def _bucket_first(self, bucket):
        """The first node of ``bucket`` in list order, or None."""
        before = self.buckets[bucket]
        if before is None:
            return None
        if before is self.SENTINEL:
            return self.first
        return before.next

    def _find_node(self, key):
        """0x609a1b0: a linear before-begin walk while the
        element count is <= 20 (key length, then memcmp), else
        a hash-bucket walk (stored hash, length, memcmp)."""
        if self.element_count <= LINEAR_WALK_LIMIT:
            for node in self._nodes():
                if len(node.key) == len(key) and node.key == key:
                    return node
            return None
        h = hash_bytes(key)
        bucket = h % self.bucket_count
        node = self._bucket_first(bucket)
        while node is not None and node.hash % self.bucket_count == bucket:
            if node.hash == h and len(node.key) == len(key) \
                    and node.key == key:
                return node
            node = node.next
        return None

    def find(self, key):
        node = self._find_node(key)
        return None if node is None else node.value

    def _need_rehash(self):
        """_Prime_rehash_policy::_M_need_rehash for one more
        element: rehash when the count would exceed
        bucket_count * max_load_factor."""
        return (self.element_count + 1) > \
            self.bucket_count * self.max_load_factor

    def _rehash(self):
        """0x5d38260: grow to the smallest libstdc++ prime >=
        the element count + 1, re-link the list so same-bucket
        nodes stay contiguous (in old-list order within a
        bucket), and re-derive every bucket's before-begin node
        from the new list order."""
        target = self.element_count + 1
        new_count = next(p for p in self.PRIMES if p >= target)
        nodes = list(self._nodes())
        groups = {}
        order = []
        for node in nodes:
            bucket = node.hash % new_count
            if bucket not in groups:
                groups[bucket] = []
                order.append(bucket)
            groups[bucket].append(node)
        new_list = []
        for bucket in order:
            new_list.extend(groups[bucket])
        for i, node in enumerate(new_list):
            node.next = new_list[i + 1] if i + 1 < len(new_list) else None
        self.first = new_list[0] if new_list else None
        self.bucket_count = new_count
        self.buckets = [None] * new_count
        prev = self.SENTINEL
        for node in new_list:
            bucket = node.hash % new_count
            if self.buckets[bucket] is None:
                self.buckets[bucket] = prev
            prev = node

    def _predecessor(self, node):
        """The node before ``node`` in the list, or SENTINEL
        when ``node`` is the list head."""
        prev = self.SENTINEL
        cur = self.first
        while cur is not None and cur is not node:
            prev = cur
            cur = cur.next
        return prev

    def index(self, key):
        """0x60c0e90 (operator[]): the node's value string,
        inserting a 0x50-byte node (key copied, value "", hash
        stored, count incremented) when the key is absent.
        Without a rehash the node is linked right after its
        bucket's before-begin node (the head of that bucket's
        chain); for an empty bucket it goes at the list head,
        the old first node's bucket pointer moves to it, and
        its own bucket pointer becomes the sentinel. Returns a
        one-element holder so the caller can assign through it
        like &node->value."""
        node = self._find_node(key)
        if node is None:
            if self._need_rehash():
                self._rehash()
            node = MapNode(key)
            bucket = node.hash % self.bucket_count
            before = self.buckets[bucket]
            if before is None:
                # Empty bucket: insert at the list head.
                old_first = self.first
                node.next = old_first
                self.first = node
                if old_first is not None:
                    self.buckets[old_first.hash
                                 % self.bucket_count] = node
                self.buckets[bucket] = self.SENTINEL
            else:
                # Insert after the bucket's before-begin node.
                first_of_bucket = self._bucket_first(bucket)
                node.next = first_of_bucket
                if before is self.SENTINEL:
                    self.first = node
                else:
                    before.next = node
            self.element_count += 1
        return _ValueRef(self, node)

    def erase(self, key):
        """0x609a2f0: unlink the node for ``key``, destroy both
        strings and sized-delete the 0x50-byte node, fixing any
        bucket pointer that pointed at it (as its before-begin)
        and clearing its bucket when it held the last node.
        Returns the next node (None here -- the callers ignore
        it)."""
        node = self._find_node(key)
        if node is None:
            return None
        bucket = node.hash % self.bucket_count
        prev = self._predecessor(node)
        nxt = node.next
        if prev is self.SENTINEL:
            self.first = nxt
        else:
            prev.next = nxt
        # Any bucket whose before-begin was this node now
        # points at the node's predecessor.
        for b in range(self.bucket_count):
            if self.buckets[b] is node:
                self.buckets[b] = prev
        # The erased node's own bucket is empty when no node
        # of that bucket is left in the list.
        if not any(n.hash % self.bucket_count == bucket
                   for n in self._nodes()):
            self.buckets[bucket] = None
        self.element_count -= 1
        node.key = None
        node.value = None
        node.next = None
        return nxt

    def clear(self):
        """0x5d5b300: destroy both strings of every node,
        sized-delete each 0x50-byte node, zero the buckets,
        the first node and the element count."""
        for node in self._nodes():
            node.key = None
            node.value = None
            node.next = None
        self.buckets = [None] * self.bucket_count
        self.first = None
        self.element_count = 0

    def items(self):
        return [(node.key, node.value) for node in self._nodes()]

    def __len__(self):
        return self.element_count


class _ValueRef:
    """A reference to one map node's value string, standing in
    for the &node->value pointer operator[] returns."""

    def __init__(self, owner, node):
        self._owner = owner
        self._node = node

    def get(self):
        return self._node.value

    def set(self, value):
        self._node.value = value


class SharedControl:
    """A shared_ptr control block (0x18 bytes) for the value
    struct's +0x48 field: use/weak counts packed as
    0x100000001, released via 0x5d35070."""

    def __init__(self, obj=None):
        self.obj = obj
        self.use_count = 1
        self.weak_count = 1
        self.disposed = False

    def acquire(self):
        self.use_count += 1

    def release(self):
        self.use_count -= 1
        if self.use_count == 0:
            self.disposed = True
            self.obj = None


class Value:
    """The 0x50-byte value struct carried by Find entry and the
    worker: {u32 +0x00, u8 +0x04, std::string +0x08, u32 +0x28,
    u8 +0x2c, u64 +0x30, 16 bytes +0x38, shared_ptr control
    +0x48}."""

    def __init__(self, code=0, has_value=0, name="", field28=0,
                 flag2c=0, field30=0, field38=b"\x00" * 16,
                 shared=None):
        self.code = code
        self.has_value = has_value
        self.name = name
        self.field28 = field28
        self.flag2c = flag2c
        self.field30 = field30
        self.field38 = field38
        self.shared = shared

    def copy(self):
        """0x60b9d70: deep-copy the 0x50 bytes (the name string
        via 0x60b7cd0, the 16 bytes at +0x38, the +0x48 control
        with its use-count incremented)."""
        shared = self.shared
        if shared is not None:
            shared.acquire()
        return Value(self.code, self.has_value, self.name,
                     self.field28, self.flag2c, self.field30,
                     self.field38, shared)

    def destroy(self):
        """0x5e33fb0: release the +0x48 control and free the
        name string's heap buffer."""
        if self.shared is not None:
            self.shared.release()
            self.shared = None
        self.name = None


def trim(text):
    """0x61d11f0: copy ``text`` with leading and trailing
    isspace() removed; empty or all-whitespace becomes ""."""
    return text.strip(" \t\n\v\f\r")


def value_extract(text, start, cursor_out):
    """0x60b97f0: extract one option value from ``text`` starting
    at ``start``. Returns (status, value, cursor): the cursor is
    the position of the ';' that ends the value, or -1 when the
    value runs to the end of the string. ``cursor_out`` is a
    one-element list receiving the cursor, mirroring the &cursor
    out-parameter."""
    n = len(text)
    if start >= n:
        # start >= len: the value-out is cleared, *cursor = -1.
        cursor_out[0] = -1
        return Status.ok(), ""
    i = start
    while i < n and text[i] in " \t\n\v\f\r":
        i += 1
    if i < n and text[i] == "{":
        # Brace group: depth +1 on '{', -1 on '}'.
        depth = 0
        j = i
        while j < n:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if depth != 0:
            return Status.build(INVALID_ARGUMENT, 0, "",
                                MSG_MISMATCHED_BRACES), ""
        value = trim(text[i + 1:j])
        k = j + 1
        while k < n and text[k] in " \t\n\v\f\r":
            k += 1
        if k >= n:
            # End of string after the group: the cursor stays
            # at or past the length; the parser ends on it.
            cursor_out[0] = k
            return Status.ok(), value
        if text[k] != ";":
            return Status.build(INVALID_ARGUMENT, 0, "",
                                MSG_UNEXPECTED_AFTER_NESTED), ""
        cursor_out[0] = k
        return Status.ok(), value
    p = text.find(";", i)
    if p == -1:
        cursor_out[0] = -1
        return Status.ok(), trim(text[i:])
    cursor_out[0] = p
    return Status.ok(), trim(text[i:p])


def parse_options(name, ctx_map):
    """0x60c1190: parse ``name`` as key=value pairs separated by
    ';' into ``ctx_map``. Returns the out Status (code 0 on
    success)."""
    text = trim(name)
    # While longer than 2 and wrapped in '{' ... '}', strip the
    # outer braces and re-trim.
    while len(text) > 2 and text.startswith("{") \
            and text.endswith("}"):
        text = trim(text[1:-1])
    cursor = 0
    n = len(text)
    while True:
        if cursor == -1 or cursor >= n:
            return Status.ok()
        p = None
        for i in range(cursor, n):
            if text[i] in DELIMITERS:
                p = i
                break
        if p is None:
            return Status.build(INVALID_ARGUMENT, 0, "",
                                MSG_MISMATCHED_PAIR)
        if text[p] != "=":
            return Status.build(INVALID_ARGUMENT, 0, "",
                                MSG_UNEXPECTED_CHAR)
        key = trim(text[cursor:p])
        if not key:
            return Status.build(INVALID_ARGUMENT, 0, "",
                                MSG_EMPTY_KEY)
        cursor_out = [None]
        status, value = value_extract(text, p + 1, cursor_out)
        if not status.is_ok():
            # The extraction failure is copied into out via
            # 0x60b7ac0 (a move of the 6-byte status + string).
            return status
        ctx_map.index(key).set(value)
        cursor = cursor_out[0]
        if cursor == -1:
            return Status.ok()
        # Advance past the ';' that ended the value.
        cursor += 1


def find_norm(name, fallback, ctx_map, default_name=DEFAULT_NAME):
    """0x609a410: normalize ``name`` into the out-string.
    Returns (status, out_string)."""
    if not name or name == default_name:
        return Status.ok(), fallback
    if "=" not in name:
        return Status.ok(), name
    status = parse_options(name, ctx_map)
    if not status.is_ok():
        # Parser failure: the out-string takes the name, the
        # map is cleared and out is reset to success.
        ctx_map.clear()
        return Status.ok(), name
    found = ctx_map.find("id")
    if found is not None:
        out_string = found
        ctx_map.erase("id")
        if out_string == default_name:
            out_string = ""
        return Status.ok(), out_string
    if fallback:
        return Status.ok(), fallback
    ctx_map.clear()
    return Status.ok(), name




def value_byte03(value):
    """The byte at value+0x03: the top byte of the +0x00 u32,
    which gates find_e70's slot-0x28 call."""
    return (value.code >> 24) & 0xFF


class TableNode:
    """One node in a name table's list: {next +0x00, name
    pointer +0x08, name length +0x10, sub-struct pointer
    +0x28 (the name lookup returns the address of this
    field), kind u32 +0xd0, state +0xd4, flags +0xd8, flag
    byte +0xd9}. The model holds the node directly; the
    returned 'found' pointer is the node itself, and kind
    is read from it as the binary reads *(found + 0xa8)."""

    def __init__(self, name, kind=0, state=0, flags=0,
                 flag_b1=False, sub_first=0):
        self.name = name
        self.kind = kind
        self.state = state
        self.flags = flags
        self.flag_b1 = flag_b1
        # The u64 at node+0x28+0x00: the recursive kind-0x16
        # call reads it as the descriptor's +0x00 offset.
        self.sub_first = sub_first
        self.next = None


class NameTable:
    """The table struct the name lookup searches: {list head
    +0x10, element count +0x18}. Buckets are derived from
    the node hashes exactly as the binary's hash-bucket
    walk does (bucket = hash % bucket_count)."""

    def __init__(self, nodes=(), bucket_count=1):
        self.nodes = list(nodes)
        self.bucket_count = bucket_count

    @property
    def count(self):
        return len(self.nodes)

    def _bucket_nodes(self, bucket):
        return [n for n in self.nodes
                if hash_bytes(n.name) % self.bucket_count == bucket]


class TableEntry:
    """One 0x30-byte element of the vector the element scan
    walks: {name pointer +0x00, name length +0x08, 16 bytes
    +0x20, table pointer +0x28}. field20 is the 8-byte value
    at +0x20 that the scan stores into found_out."""

    def __init__(self, name, table=None, field20=0):
        self.name = name
        self.table = table
        self.field20 = field20


class Desc:
    """The node descriptor the entry resolves: {i64 offset
    +0x00, u32 flags +0xb0, u8 flag +0xb1}."""

    def __init__(self, offset=0, flags=0, flag_b1=False):
        self.offset = offset
        self.flags = flags
        self.flag_b1 = flag_b1


class ConfigNode:
    """A configurable node object: the delegate the entry
    consults and the node the helpers consult. Its vtable
    slots are callables supplied by the test harness (the
    binary reaches them through the object's vtable):
    slot_0x28 (find_e70), slot_0x40 (find_e70), slot_0x48
    (delegate_impl), slot_0x50 (entry / kind_dispatch),
    slot_0x68 (resolve_no_equals), slot_0x78 (the node-name
    string). elements is the vector at +0x08 that the
    element scan walks. is_zero_stub_0x40 records whether
    slot 0x40 is the zero stub 0x60956f0."""

    def __init__(self, elements=(), slot_0x28=None,
                 slot_0x40=None, is_zero_stub_0x40=False,
                 slot_0x48=None, slot_0x50=None,
                 slot_0x68=None, slot_0x78=None):
        self.elements = list(elements)
        self.slot_0x28 = slot_0x28
        self.slot_0x40 = slot_0x40
        self.is_zero_stub_0x40 = is_zero_stub_0x40
        self.slot_0x48 = slot_0x48
        self.slot_0x50 = slot_0x50
        self.slot_0x68 = slot_0x68
        self.slot_0x78 = slot_0x78


def ends_with(haystack, suffix):
    """0x61d1390: 1 when the suffix fits and the haystack's
    last len(suffix) bytes equal it, else 0. An empty suffix
    returns 1."""
    if len(suffix) > len(haystack):
        return 0
    if not suffix:
        return 1
    return 1 if haystack[len(haystack) - len(suffix):] == suffix else 0


def str_compare(a, b):
    """0x61d13e0: lexicographic compare: memcmp over the
    shorter length, else the signed length difference
    (clamped to the int32 range, as the 0x7fffffff tail
    comparison does)."""
    n = min(len(a), len(b))
    for i in range(n):
        d = ord(a[i]) - ord(b[i])
        if d:
            return d
    d = len(a) - len(b)
    if d > 0x7FFFFFFF:
        return 0x7FFFFFFF
    if d < -0x80000000:
        return -0x80000000
    return d


def move_assign(dst_holder, src):
    """0x60b79e0: std::string move-assignment. ``dst_holder``
    is a one-element list receiving the moved value; the
    source is reset to empty by the caller when it models
    the source string object."""
    dst_holder[0] = src
    return src


def hash_name_find(key, table):
    """0x60b84b0: the >20-element path of the name lookup.
    _Hash_bytes(key, len, 0xc70f6907) % the bucket count
    selects the bucket; the chain is walked comparing the
    stored hash, then the name length, then memcmp. A node
    whose hash falls in a different bucket ends the walk.
    Returns the matched node or None."""
    h = hash_bytes(key)
    bucket = h % table.bucket_count
    for node in table._bucket_nodes(bucket):
        if hash_bytes(node.name) != h:
            continue
        if len(node.name) != len(key):
            continue
        if node.name != key:
            continue
        return node
    return None


def _lookup_walk(key, table):
    """One name search in ``table``: the linear walk while
    the count is <= 20, else the hash-bucket find."""
    if table.count <= LINEAR_WALK_LIMIT:
        for node in table.nodes:
            if len(node.name) == len(key) and node.name == key:
                return node
        return None
    return hash_name_find(key, table)


def name_lookup(key, table, out_holder):
    """0x60ba0b0: find a node by name in ``table``. On an
    exact match the key is move-assigned into out and the
    matched node is returned. On a miss, a '.' at position
    >= 1 splits the key: the prefix is searched the same
    way, and when the prefix matches a node of kind 0x13,
    0x15 or 0x16 the suffix is move-assigned into out and
    that node is returned. Otherwise None is returned and
    out is left untouched."""
    node = _lookup_walk(key, table)
    if node is not None:
        move_assign(out_holder, key)
        return node
    pos = key.find(".")
    if pos <= 0:
        return None
    prefix = key[:pos]
    node = _lookup_walk(prefix, table)
    if node is None:
        return None
    if node.kind not in (0x13, 0x15, 0x16):
        return None
    suffix = key[pos + 1:]
    move_assign(out_holder, suffix)
    return node


def element_scan(elements, key, out_holder):
    """0x6096f40: walk the 0x30-byte elements; per element
    the name string is copied and, when the element's +0x28
    table pointer is non-null, the name lookup runs with
    (key, table, out). Returns (node, field20) on the first
    match, else (None, None)."""
    for element in elements:
        if element.table is None:
            continue
        node = name_lookup(key, element.table, out_holder)
        if node is not None:
            return node, element.field20
    return None, None


def delegate_impl(out, node, value, ctx_map, flag):
    """0x6097110: calls the object's vtable slot 0x48 with
    (out, obj, value, ctx_map, flag). Returns the Status
    the slot writes into out."""
    if node.slot_0x48 is None:
        return Status.ok()
    return node.slot_0x48(out, node, value, ctx_map, flag)


def fallback_delegate(out, node, value, ctx_map):
    """0x6097150: calls delegate_impl with flag 0."""
    return delegate_impl(out, node, value, ctx_map, 0)


def zero_stub(out):
    """0x60956f0: the default vtable slot-0x40
    implementation; zeroes the 16-byte Status."""
    return Status.ok()


def find_e70(node, value, arg7, default_name=DEFAULT_NAME):
    """0x6099e70: the '=' / ';' helper. Returns the out
    Status. ``node`` supplies slot_0x28 / slot_0x40 (or
    is_zero_stub_0x40); the parser runs into a fresh empty
    options map on the ';' / '=' path."""
    out = Status.ok()
    if arg7:
        if ";" in arg7 or "=" in arg7:
            ctx_map = OptionsMap()
            status = parse_options(arg7, ctx_map)
            out = status
            if status.is_ok():
                out = delegate_impl(out, node, value, ctx_map, 0)
            ctx_map.clear()
            return out
        if node.is_zero_stub_0x40:
            out = Status.ok()
        else:
            if node.slot_0x40 is None:
                out = Status.ok()
            else:
                out = node.slot_0x40(node, value)
            if not out.is_ok():
                return out
    if value_byte03(value) == 0:
        return out
    if node.slot_0x28 is None:
        return out
    return node.slot_0x28(node, value)


def kind_dispatch(out, value, node, found, str_a, str_b,
                  arg7, extra):
    """0x609b700: kind dispatch on the matched record.
    Kind 0x16 recurses into the entry; equal names or kind
    0x13/0x15 take the node's slot-0x50; any other kind
    reports Status code 1 'Could not find option: ' +
    str_b. Returns the out Status."""
    kind = found.kind
    if kind == 0x16:
        # The recursive call passes the matched record as the
        # descriptor: its +0x00 offset is the u64 at node+0x28
        # (sub_first), its +0xb0 flags are the node's +0xd8
        # flags and its +0xb1 flag is the node's +0xd9 byte.
        desc = Desc(found.sub_first, found.flags,
                    found.flag_b1)
        return entry(out, value, node, desc, str_b, str_b,
                     arg7, extra)
    if str_a == str_b:
        return node.slot_0x50(out, node, value, found, str_b,
                              arg7, extra)
    if kind in (0x13, 0x15):
        return node.slot_0x50(out, node, value, found, str_b,
                              arg7, extra)
    return Status.build(OPTION_NOT_FOUND, 0,
                        MSG_COULD_NOT_FIND, str_b)


def resolve_no_equals(out, value, node, key6, arg7):
    """0x609b8a0: the no-'=' path. The node's slot-0x68
    fills the search name from key6; the element scan runs
    over the node's +0x08 vector; a null scan result builds
    Status code 1 'Could not find option: ' + key6, else
    kind_dispatch runs. Returns the out Status."""
    name2 = node.slot_0x68(node, key6)
    out_holder = [""]
    found, field20 = element_scan(node.elements, name2,
                                  out_holder)
    if found is None:
        return Status.build(OPTION_NOT_FOUND, 0,
                            MSG_COULD_NOT_FIND, key6)
    return kind_dispatch(out, value, node, found, name2,
                         out_holder[0], arg7, field20)


def no_equals(out, node, value, key6, arg7):
    """0x609ba30: thin wrapper around resolve_no_equals."""
    return resolve_no_equals(out, value, node, key6, arg7)


def _resolve_node(desc, base, memory):
    """The entry's flag-chain node resolution: base null ->
    None; otherwise addr = base + desc.offset, and when any
    of the desc+0xb0 flags 0x200/0x400/0x800 is set the
    address is followed through one pointer load (the
    memory entry's 'link'). ``memory`` maps synthetic
    addresses to nodes (or to {'link': addr} records)."""
    if base is None:
        return None
    addr = base + desc.offset
    if desc.flags & 0xE00:
        target = memory.get(addr)
        if target is None:
            return None
        addr = target.get("link") if isinstance(target, dict) \
            else getattr(target, "link", None)
        if addr is None:
            return None
    return memory.get(addr)


def entry(out, value, delegate, desc, name5, key6, arg7,
          base, memory=None, default_name=DEFAULT_NAME):
    """0x609a740: the sibling Find entry point. ``memory``
    is the address space the flag-chain resolution reads
    (a dict from synthetic addresses to nodes); ``base``
    is the base8 argument (None, or an int address). The
    slot-0x50 call is slot(out, delegate, value-copy, desc,
    key6, arg7, base). Returns the out Status."""
    if memory is None:
        memory = {}
    node = _resolve_node(desc, base, memory)
    local = value.copy()
    if desc.flag_b1:
        local.has_value = 0
    if not desc.flag_b1 and value.has_value:
        if node is not None:
            result = _dot_id_variant2(out, local, node, name5,
                                      key6, arg7, base, memory,
                                      default_name)
        elif arg7:
            result = Status.build(INVALID_ARGUMENT, 0,
                                  MSG_OPTION_NOT_CHANGEABLE,
                                  name5)
        else:
            result = Status.ok()
    else:
        result = _name_dispatch(out, local, node, delegate,
                                desc, name5, key6, arg7, base,
                                memory, default_name)
    # The common cleanup (0x609aaea): the local value copy's
    # shared control is released on every exit path.
    local.destroy()
    return result


def _name_dispatch(out, local, node, delegate, desc, name5,
                   key6, arg7, base, memory, default_name):
    """The entry's name dispatch (shared by the flag_b1 and
    the flag-clear/+0x04-clear paths): name5 == key6 or
    key6 == 'id' -> the delegate's slot-0x50; otherwise the
    '.id' variant-1 path."""
    if name5 == key6:
        return delegate.slot_0x50(out, delegate, local, desc,
                                  key6, arg7, base)
    if len(key6) == 2 and key6 == "id":
        return delegate.slot_0x50(out, delegate, local, desc,
                                  key6, arg7, base)
    return _dot_id_variant1(out, local, node, delegate, desc,
                            name5, key6, arg7, base, memory,
                            default_name)


def _slot50(out, delegate, local, desc, key6, arg7, base):
    return delegate.slot_0x50(out, delegate, local, desc,
                              key6, arg7, base)


def _dot_id_variant1(out, local, node, delegate, desc,
                     name5, key6, arg7, base, memory,
                     default_name):
    """The '.id' path, variant 1: name5 ends with '.id' ->
    slot-0x50; arg7 empty -> clear out, success; node null
    -> slot-0x50; otherwise the node's slot-0x78 name plus
    '.' is compared with key6: unequal -> slot-0x50; equal
    -> the '=' helper when arg7 contains '=', else the
    no-'=' helper."""
    if ends_with(name5, ".id"):
        return _slot50(out, delegate, local, desc, key6,
                       arg7, base)
    if not arg7:
        return Status.ok()
    if node is None:
        return _slot50(out, delegate, local, desc, key6,
                       arg7, base)
    node_name = node.slot_0x78(node)
    if str_compare(key6, node_name + ".") != 0:
        return _slot50(out, delegate, local, desc, key6,
                       arg7, base)
    if "=" in arg7:
        return find_e70(node, local, arg7, default_name)
    return no_equals(out, node, local, key6, arg7)


def _dot_id_variant2(out, local, node, name5, key6, arg7,
                     base, memory, default_name):
    """The '.id' path, variant 2 (desc+0xb1 clear and the
    value's +0x04 byte set): name5 ends with '.id', or key6
    == 'id' -> the node-name compare; name5 == key6 (and
    neither of the above) -> the find_norm path; otherwise
    -> the no-'=' helper."""
    if ends_with(name5, ".id") or (
            len(key6) == 2 and key6 == "id"):
        return _node_name_compare(out, local, node, name5,
                                  key6, arg7, base, memory)
    if name5 == key6:
        return _find_norm_path(out, local, node, name5, key6,
                               arg7, base, memory, default_name)
    return no_equals(out, node, local, key6, arg7)


def _node_name_compare(out, local, node, name5, key6, arg7,
                       base, memory):
    """The node-name compare shared by variant 2: the node's
    slot-0x78 name against arg7; equal (including both
    empty) -> clear out and return success (0x609aacf);
    unequal -> Status code 4 'Option not changeable: ' +
    name5. (The map-empty check at 0x609b4f0 belongs to the
    find_norm path only, not to this compare.)"""
    node_name = node.slot_0x78(node)
    if arg7 == node_name:
        return Status.ok()
    return Status.build(INVALID_ARGUMENT, 0,
                        MSG_OPTION_NOT_CHANGEABLE, name5)


def _find_norm_path(out, local, node, name5, key6, arg7,
                    base, memory, default_name):
    """The find_norm path of variant 2: an empty options map
    and an empty out-string are built, the node's slot-0x78
    name is the fallback, find_norm runs on arg7; a non-zero
    find_norm status is copied into out and returned; on
    success the slot-0x78 name is fetched again and compared
    with find_norm's out-string: equal -> the map-empty
    check, unequal -> the code-4 error."""
    ctx_map = OptionsMap()
    node_name = node.slot_0x78(node)
    status, out_string = find_norm(arg7, node_name, ctx_map,
                                   default_name)
    if not status.is_ok():
        return status
    node_name2 = node.slot_0x78(node)
    if node_name2 == out_string:
        if len(ctx_map) == 0:
            return Status.ok()
        return fallback_delegate(out, node, local, ctx_map)
    return Status.build(INVALID_ARGUMENT, 0,
                        MSG_OPTION_NOT_CHANGEABLE, name5)
