

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

# The four sibling Find-family hosts pinned by this item.
FIND_PLAIN_TABLE = 0x6080B10
FIND_BLOCK_TABLE = 0x60818F0
FIND_BY_ELEMENT_SCAN = 0x6098AD0
RESOLVE_ALL_ELEMENTS = 0x609BCB0

# Their helpers.
CSTR_CTOR = 0x607D9F0
CSTR_CTOR_SIBLING = 0x60B7D80
PLAIN_CREATOR = 0x6193B40
PLAIN_CTOR = 0x6193A00
BLOCK_CREATOR = 0x60DBD80
BLOCK_CTOR = 0x60DB710
OPTIONS_LIST_DESTROY = 0x607E020
MAP_FIND_NAME = 0x609A1B0
MAP_ERASE_NEXT = 0x609A2F0
MAP_INSERT = 0x609BAD0
CSTR_DUP = 0x61CF610
COUNTED_RELEASE = 0x5D350C0
CLEAR_STRING = 0x60B79B0
OPTIONS_RECORD_APPEND = 0x6099CE0
MATCHER = 0x60BB9A0
RESOLVER = 0x60971C0
SERIALIZER = 0x60BA600
VALUE_COPY = 0x60B9D70
VALUE_DTOR = 0x5E33FB0

# Block constructor sub-calls (boundary record only).
BLOCK_CTOR_SUB_1 = 0x60DB1E0
BLOCK_CTOR_SUB_2 = 0x60D7FB0
BLOCK_CTOR_SUB_3 = 0x60D6FD0
BLOCK_CTOR_MUTEX_INIT = 0x60D50C0
BLOCK_CTOR_EXTRA = 0x5DB8800
PRIME_REHASH_POLICY = 0x5E52800

# The plain options object's vtable: the constructor stores
# 0x64d6618 + 0x10. The shared_ptr control installed by the
# plain host carries vtable 0x64c8748 (0x64c8738 + 0x10) and
# counts 0x100000001, taken from .rodata 0x459b20.
PLAIN_VTABLE_BASE = 0x64D6618
PLAIN_VTABLE = 0x64D6628
PLAIN_CONTROL_VTABLE = 0x64C8748
PLAIN_CONTROL_COUNTS = 0x100000001
PLAIN_OBJECT_SIZE = 0x48
BLOCK_OBJECT_SIZE = 0x260
PLAIN_OPTIONS_SIZE = 0x28
BLOCK_OPTIONS_SIZE = 0xF8
NAME_SET_NODE_SIZE = 0x30
OPTIONS_MAP_NODE_SIZE = 0x50
OPTIONS_LIST_NODE_SIZE = 0x28
BLOCK_DEFAULTS_TEMPLATE = 0x4506C0
BLOCK_DEFAULTS_TEMPLATE_VALUES = (0x2000, 0x2)
OPTIONS_RECORD_GLOBAL = 0x6508260
BLOCK_CTOR_BSS = 0x6507540
BLOCK_CTOR_VTABLES = (0x64D39A8, 0x64D3A70, 0x64C9C60, 0x64C9A40)

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
MSG_CANNOT_FIND = "Cannot find option: "
MSG_MISMATCHED_TABLE_OPTION = "Mismatched table option: "
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

    def erase_node(self, node):
        """0x609a2f0 (map_erase_next): unlink the given node
        object (not by key), destroy both strings and
        sized-delete the 0x50-byte node, fixing any bucket
        pointer that pointed at it and clearing its bucket
        when it held the last node. Returns the next node."""
        bucket = node.hash % self.bucket_count
        prev = self._predecessor(node)
        nxt = node.next
        if prev is self.SENTINEL:
            self.first = nxt
        else:
            prev.next = nxt
        for b in range(self.bucket_count):
            if self.buckets[b] is node:
                self.buckets[b] = prev
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
        self.destroyed = False

    @property
    def counts(self):
        """The packed u64 at control+0x08: the use count in
        the low 32 bits, the weak count in the high 32 bits
        (0x100000001 for a fresh 1/1 control)."""
        return self.use_count | (self.weak_count << 32)

    def dispose(self):
        """The control vtable slot 0x10: destroy the managed
        object. (The model records the dispose; the object
        reference is dropped.)"""
        self.disposed = True
        self.obj = None

    def destroy_control(self):
        """The control vtable slot 0x18: destroy the control
        block itself."""
        self.destroyed = True

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
                 flag_b1=False, sub_first=0, obj=None,
                 flag_byte=None, slot_0x10_target=None):
        self.name = name
        self.kind = kind
        self.state = state
        self.flags = flags
        self.flag_b1 = flag_b1 or (bool(flag_byte & 1)
                                  if flag_byte is not None
                                  else False)
        # The full +0xd9 flag byte: the matcher reads its bit
        # 0 (flag_b1); the element-scan host reads bits
        # 0x8/0x4/0x2 to decide the slot-0x10 deref.
        self.flag_byte = flag_byte if flag_byte is not None \
            else (1 if self.flag_b1 else 0)
        # The u64 at node+0x28+0x00: the recursive kind-0x16
        # call reads it as the descriptor's +0x00 offset.
        self.sub_first = sub_first
        # The object at node+0x28 that the matcher consults
        # (a NodeObj): its +0x60 field selects the virtual
        # slot-0x40 path and its name object feeds the
        # resolver. None when the node carries no object.
        self.obj = obj
        # The object the element-scan host's slot-0x10 path
        # calls (resolved from found-out + the int32 at
        # node+0x28); its ``deref`` attribute, when present,
        # is the object *target resolves to when the +0xd9
        # byte has any of bits 0x8/0x4/0x2 set.
        self.slot_0x10_target = slot_0x10_target
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
                 slot_0x68=None, slot_0x78=None,
                 slot_0x38=None, slot_0x08=None,
                 slot_0x10=None):
        self.elements = list(elements)
        self.slot_0x28 = slot_0x28
        self.slot_0x40 = slot_0x40
        self.is_zero_stub_0x40 = is_zero_stub_0x40
        self.slot_0x48 = slot_0x48
        self.slot_0x50 = slot_0x50
        self.slot_0x68 = slot_0x68
        self.slot_0x78 = slot_0x78
        # slot_0x38 resolves the options struct for the
        # Plain/BlockTableOptions hosts; slot_0x08 is the
        # created object's post-install call; slot_0x10 is
        # the element-scan host's delegate virtual.
        self.slot_0x38 = slot_0x38
        self.slot_0x08 = slot_0x08
        self.slot_0x10 = slot_0x10


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


# --- Matcher side (re-shipped from #3485) ------------------------------


class NameObject:
    """The object the matcher resolves names through: its vtable
    slot 0x60 returns a string (0x60971c0's input) and slot 0x78
    returns a string (the 0x16 delegate-name path). The binary
    reaches both through the prefix pointer plus the int32 at
    node+0x28; here the object is held directly."""

    def __init__(self, slot_0x60="", slot_0x78="", link=None):
        self._slot_0x60 = slot_0x60
        self._slot_0x78 = slot_0x78
        # The one-link follow the 0x15/0x16 flag chain takes
        # when +0xd8 & 0x800/0x400/0x200 is set.
        self.link = link

    def slot_0x60(self):
        return self._slot_0x60

    def slot_0x78(self):
        return self._slot_0x78


class NodeObj:
    """The object at node+0x28: {int32 +0x00 (added to the
    prefix pointer to find the name object), +0x60 (0x38 from
    node+0x28) non-null selects the virtual slot-0x40 path,
    kind +0xd0, state +0xd4, flags +0xd8, flag byte +0xd9}."""

    def __init__(self, base_offset=0, has_virtual=False,
                 virtual_serialize=None, name_object=None):
        self.base_offset = base_offset
        self.has_virtual = has_virtual
        self.virtual_serialize = virtual_serialize
        self.name_object = name_object


def resolver(name_object):
    """0x60971c0: the name object's slot-0x60 string is returned
    as-is, unless it contains '=' -- then '{' + the part before
    '=' + '}' is returned."""
    text = name_object.slot_0x60()
    if not text:
        return text
    p = text.find("=")
    if p == -1:
        return text
    return "{" + text[:p] + "}"


def default_serializer(obj, kind, value_out):
    """The serializer 0x60ba600 as a boundary: its per-kind
    rules (25 jump-table cases, 0..0x18) are an open unknown
    for this item, so the default model reports every kind as
    serialized (True) and leaves the value-out untouched. Pass
    a real callable to model a kind that fails."""
    return True


def matcher(node, value, name, prefix, value_out,
            serializer=default_serializer):
    """0x60bb9a0: match one delegate-table node. ``prefix`` is
    the element's name-string pointer (None = no match);
    ``value_out`` is a one-element list holding the output
    string. Returns the out Status."""
    if prefix is None:
        return Status.ok()
    if node.state == 4:
        return Status.ok()
    if node.flags & 0x2000:
        return Status.build(NOT_SUPPORTED, 0, name,
                            MSG_CANNOT_SERIALIZE)
    obj = node.obj
    if obj is not None and obj.has_virtual:
        # Virtual slot 0x40 of node+0x28 fills out directly.
        if obj.virtual_serialize is not None:
            return obj.virtual_serialize(value, name, value_out)
        return Status.ok()
    kind = node.kind
    if kind == 0x16:
        return _matcher_kind_0x16(node, value, name, value_out)
    if kind == 0x15:
        return _matcher_kind_0x15(node, value, name, value_out)
    # Any other kind: the serializer path.
    if value.has_value and not (node.flags & 0x100):
        return Status.ok()
    ok = serializer(obj, kind, value_out)
    if ok:
        return Status.ok()
    return Status.build(INVALID_ARGUMENT, 0, name,
                        MSG_CANNOT_SERIALIZE)


def _resolve_into(node, value, value_out, name_object):
    """The shared 0x15 / 0x16 resolver path: copy the value,
    replace the copy's name with ";", run the resolver on the
    given name object and move the result into the value-out.
    Returns the resolver string."""
    copy = value.copy()
    copy.name = ";"
    result = resolver(name_object)
    value_out[0] = result
    copy.destroy()
    return result


def _matcher_kind_0x15(node, value, name, value_out):
    """Kind 0x15: when +0xd8 & 0x800/0x400/0x200 is set, the
    name object is followed through *(%rbp) once and the body
    runs on the linked object; a null link is no match. Then
    the resolver path runs and the result is assigned to the
    value-out unconditionally."""
    current = node.obj.name_object
    if node.flags & 0xE00:
        nxt = getattr(current, "link", None)
        if nxt is None:
            return Status.ok()
        current = nxt
    _resolve_into(node, value, value_out, current)
    return Status.ok()


def _matcher_kind_0x16(node, value, name, value_out):
    """Kind 0x16: the value-out is cleared first. When
    +0xd8 & 0x800/0x400/0x200 is set, the name object is
    followed through *(%rbp) once and the body runs on the
    linked object; a null link ends in the chain-exhausted
    outcome: the global default name, unless the 0xb1 flag is
    clear and the value's +0x04 byte is set, which clears the
    value-out instead. Then the delegate-name path (slot 0x78
    on the name object) runs when +0xd8 & 0x8000 is set, the
    value's +0x28 field is not 2, and the value's +0x04 byte
    is clear or +0xd8 & 0x100 is set; the same gate with
    +0x04 set and 0x100 clear is no match. Otherwise the
    resolver path runs: the 0xb1 flag clears the copy's +0x04
    byte; otherwise a non-zero +0x04 byte requires the
    resolved string to contain '=', and a missing '=' clears
    the value-out."""
    current = node.obj.name_object
    # The binary clears the value-out on every 0x16 entry.
    value_out[0] = ""
    if node.flags & 0xE00:
        nxt = getattr(current, "link", None)
        if nxt is None:
            # Chain exhausted: default name, or "" when the
            # 0xb1 flag is clear and +0x04 is set.
            if not node.flag_b1 and value.has_value:
                value_out[0] = ""
            else:
                value_out[0] = DEFAULT_NAME
            return Status.ok()
        current = nxt
    if node.flags & 0x8000 and value.field28 != 2:
        if not value.has_value or (node.flags & 0x100):
            # Delegate-name path: slot 0x78 on the name object.
            value_out[0] = current.slot_0x78()
        # Else no match: the value-out stays cleared.
        return Status.ok()
    # Resolver path.
    copy = value.copy()
    copy.name = ";"
    if node.flag_b1:
        copy.has_value = 0
    result = resolver(current)
    copy.destroy()
    if copy.has_value == 0:
        value_out[0] = result
    elif "=" in result:
        value_out[0] = result
    else:
        value_out[0] = ""
    return Status.ok()


# --- Helpers pinned by this item ---------------------------------------


def cstr_ctor(cstr):
    """0x607d9f0: std::string from a const char*. SSO at 15
    chars or fewer (with the length-1 fast path), heap via
    _M_create above that; a null pointer throws logic_error
    through 0x963298. The model returns the string value
    (the SSO/heap split is unobservable); a null input
    raises ValueError, modelling the throw. A second
    instantiation of the same template as 0x60b7d80 -- the
    two excerpts differ only in branch-target addresses."""
    if cstr is None:
        raise ValueError(
            "logic_error: basic_string::_M_construct null not valid")
    if len(cstr) > MAX_STRING_LEN:
        raise ValueError("length_error: basic_string::_M_create")
    return cstr


def cstr_dup(out_holder, cstr):
    """0x61cf610: strdup-like: strlen+1, new char[],
    __strncpy_chk, the pointer stored into *(out). Returns
    out (the one-element holder receives the fresh copy)."""
    out_holder[0] = cstr
    return out_holder[0]


def clear_string(string_holder, cstr):
    """0x60b79b0: the string's _M_replace(0, size, cstr,
    strlen(cstr)) -- the string is assigned the C string.
    The holder receives the new value."""
    string_holder[0] = cstr
    return string_holder[0]


def shared_release(control):
    """0x5d35070: the shared-control release tail: dispose
    through the control vtable slot 0x10, then decrement the
    weak count at +0x0c (a plain decrement when
    __libc_single_threaded at 0x64ed290 is non-zero, a locked
    xadd when it is 0 -- unobservable in the model, no
    threads); when the old weak count was 1, destroy the
    control through vtable slot 0x18."""
    if control is None:
        return
    control.dispose()
    old_weak = control.weak_count
    control.weak_count -= 1
    if old_weak == 1:
        control.destroy_control()


def counted_release(control):
    """0x5d350c0: the shared_ptr control release: counts ==
    0x100000001 -> the counts are zeroed, dispose through
    vtable slot 0x10, then destroy through slot 0x18;
    otherwise the use count at +0x08 is decremented (a plain
    decrement when __libc_single_threaded is non-zero, a
    locked xadd when it is 0), and when the old use count
    was 1 the 0x5d35070 tail runs."""
    if control is None:
        return
    if control.counts == PLAIN_CONTROL_COUNTS:
        control.use_count = 0
        control.weak_count = 0
        control.dispose()
        control.destroy_control()
        return
    old_use = control.use_count
    control.use_count -= 1
    if old_use == 1:
        shared_release(control)


def options_record_append(obj, name, options, global_ptr):
    """0x6099ce0: append a 0x30-byte record {name string,
    options pointer, global} to the vector at obj+0x08
    (begin/end/capacity), growing it when end == capacity.
    The model appends to the object's records list."""
    obj.records.append((name, options, global_ptr))
    return len(obj.records)


class TableOptions:
    """A created table-options object: the 0x48-byte plain
    object (vtable 0x64d6628) or the 0x260-byte block object.
    ``options`` is the options struct the constructor was
    given (a dict of pinned offset -> value for the
    defaults, or an opaque struct from slot 0x38);
    ``records`` is the vector at +0x08 that
    options_record_append grows; the slot callables are the
    object's vtable slots the hosts consult (0x28 for
    find_e70, 0x40 for find_e70, 0x08 for the post-install
    call)."""

    def __init__(self, size, vtable, slot_0x28=None,
                 slot_0x40=None, is_zero_stub_0x40=False,
                 slot_0x08=None, slot_0x48=None):
        self.size = size
        self.vtable = vtable
        self.options = None
        self.records = []
        self.slot_0x28 = slot_0x28
        self.slot_0x40 = slot_0x40
        self.is_zero_stub_0x40 = is_zero_stub_0x40
        self.slot_0x08 = slot_0x08
        # find_e70's ';' / '=' parse path runs delegate_impl,
        # which consults slot 0x48 (None = the ok default).
        self.slot_0x48 = slot_0x48

    # find_e70 consults these two attributes on its node.
    @property
    def elements(self):
        return []


def plain_default_options():
    """The 0x28-byte default options struct the plain host
    builds on the stack when the resolved struct is null:
    zeroed, byte +0x04 = 0xa, dword +0x0e = 0x103fe8.
    Returned as a dict of pinned offset -> value."""
    return {0x04: 0x0A, 0x0E: 0x103FE8}


def block_default_options():
    """The 0xf8-byte default options struct the block host
    builds on the stack when the resolved struct is null:
    29 zeroed qwords, then the pinned field values. The
    +0x98/+0xa0 fields hold a stack pointer (rsp+0xa8) in
    the binary; the model records them as the marker
    "stack" (value not pinned). Returned as a dict of
    pinned offset -> value."""
    return {
        0x59: 0xA00000000000010,
        0x64: 0x0000000100000010,
        0x71: 0x0200000000000010,
        0x2E: 0x43FE8,
        0x98: "stack",
        0xA0: "stack",
        0xB2: 1,
        0xC8: 1,
        0xD0: 5,
        0xD4: 1,
        0xD6: 1,
        0xD8: 0x40000,
        0xE8: BLOCK_DEFAULTS_TEMPLATE_VALUES,
    }


def plain_ctor(obj, options):
    """0x6193a00: zeroes obj+0x08/+0x10/+0x18, installs
    vtable 0x64d6628 (0x64d6618 + 0x10), copies the
    0x28-byte options struct into obj+0x20..+0x47, builds
    the 17-char name "PlainTableOptions" (16 bytes from
    0x451120 plus 's'), and appends the record {name,
    obj+0x20, global 0x6508260} through
    options_record_append 0x6099ce0."""
    obj.vtable = PLAIN_VTABLE
    obj.options = options
    options_record_append(obj, "PlainTableOptions", options,
                          OPTIONS_RECORD_GLOBAL)
    return obj


def plain_creator(options, slot_0x28=None, slot_0x40=None,
                  is_zero_stub_0x40=False, slot_0x08=None,
                  slot_0x48=None):
    """0x6193b40: new(0x48) + the constructor 0x6193a00."""
    obj = TableOptions(PLAIN_OBJECT_SIZE, PLAIN_VTABLE_BASE,
                       slot_0x28=slot_0x28, slot_0x40=slot_0x40,
                       is_zero_stub_0x40=is_zero_stub_0x40,
                       slot_0x08=slot_0x08,
                       slot_0x48=slot_0x48)
    return plain_ctor(obj, options)


# The block constructor's pinned references, recorded as a
# boundary: the model constructs the object from the options
# struct and records the append, but the sub-constructors'
# field effects are not pinned.
BLOCK_CTOR_CALLS = (BLOCK_CTOR_SUB_1, BLOCK_CTOR_SUB_2,
                    BLOCK_CTOR_SUB_3, BLOCK_CTOR_MUTEX_INIT,
                    OPTIONS_RECORD_APPEND, BLOCK_CTOR_EXTRA)


def block_ctor(obj, options):
    """0x60db710 (boundary): allocate 0x260, construct from
    the options struct. The binary calls the
    sub-constructors 0x60db1e0/0x60d7fb0/0x60d6fd0, the mutex
    init 0x60d50c0, options_record_append and 0x5db8800,
    references vtables 0x64d39a8/0x64d3a70/0x64c9c60/
    0x64c9a40 and BSS 0x6507540, and throws on "map::at"
    (0x4408a7). The model records the options struct, the
    record append (name = the options struct's leading
    string, "" for the defaults; options pointer obj+0x20;
    global 0x6507540) and the pinned call/vtable/literal
    references; the sub-constructors' field effects are an
    open unknown."""
    obj.options = options
    name = options.get("name", "") if isinstance(options, dict) \
        else ""
    options_record_append(obj, name, options, BLOCK_CTOR_BSS)
    obj.boundary_calls = BLOCK_CTOR_CALLS
    obj.boundary_vtables = BLOCK_CTOR_VTABLES
    return obj


def block_creator(options, slot_0x28=None, slot_0x40=None,
                  is_zero_stub_0x40=False, slot_0x08=None,
                  slot_0x48=None):
    """0x60dbd80: new(0x260) + the constructor 0x60db710."""
    obj = TableOptions(BLOCK_OBJECT_SIZE, BLOCK_CTOR_VTABLES[0],
                       slot_0x28=slot_0x28, slot_0x40=slot_0x40,
                       is_zero_stub_0x40=is_zero_stub_0x40,
                       slot_0x08=slot_0x08,
                       slot_0x48=slot_0x48)
    return block_ctor(obj, options)


class OptionsListNode:
    """One 0x28-byte node of the options list the block host
    destroys: {child +0x10, next +0x18} (the +0x00/+0x08
    fields are not read by the destroyer)."""

    def __init__(self, child=None, next=None):
        self.child = child
        self.next = next
        self.freed = False


def options_list_destroy(head):
    """0x607e020: recursive linked-list destroy. The +0x18
    links are walked unrolled 8 deep and then recursed; each
    0x28-byte node is freed after its +0x10 child is freed
    as a 0x28 node. The free order is the chain in reverse
    (the tail is destroyed first), each node followed by its
    child subtree. Returns the freed nodes in free order."""
    if head is None:
        return []
    freed = options_list_destroy(head.next)
    head.freed = True
    freed.append(head)
    freed.extend(options_list_destroy(head.child))
    return freed


class NameSetNode:
    """One 0x30-byte node of the walker's local name set:
    {next +0x00, key string +0x08, hash +0x28}."""

    def __init__(self, key):
        self.key = key
        self.hash = hash_bytes(key)
        self.next = None


class NameSet:
    """The walker's local name set: an unordered_set<string>
    in the binary's layout (buckets, count, before-begin
    list, element count, load 1.0), built with one bucket.
    Nodes are 0x30 bytes with the hash at +0x28; the
    binary's map_insert 0x609bad0 inserts into it and the
    walker's code-3 path searches it inline."""

    PRIMES = OptionsMap.PRIMES
    SENTINEL = OptionsMap.SENTINEL

    def __init__(self, bucket_count=1):
        self.bucket_count = bucket_count
        self.buckets = [None] * bucket_count
        self.first = None
        self.element_count = 0
        self.max_load_factor = 1.0

    def _nodes(self):
        node = self.first
        while node is not None:
            yield node
            node = node.next

    def _bucket_first(self, bucket):
        before = self.buckets[bucket]
        if before is None:
            return None
        if before is self.SENTINEL:
            return self.first
        return before.next

    def find_name(self, key):
        """The walker's inline search of the local set: the
        element count <= 0x14 walks the list (length, then
        memcmp), otherwise the hash-bucket walk (_Hash_bytes
        seed 0xc70f6907, the stored hash at node+0x28)."""
        if self.element_count <= LINEAR_WALK_LIMIT:
            for node in self._nodes():
                if len(node.key) == len(key) \
                        and node.key == key:
                    return node
            return None
        h = hash_bytes(key)
        bucket = h % self.bucket_count
        node = self._bucket_first(bucket)
        while node is not None \
                and node.hash % self.bucket_count == bucket:
            if node.hash == h and len(node.key) == len(key) \
                    and node.key == key:
                return node
            node = node.next
        return None

    def _need_rehash(self):
        return (self.element_count + 1) > \
            self.bucket_count * self.max_load_factor

    def _rehash(self):
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
            node.next = new_list[i + 1] \
                if i + 1 < len(new_list) else None
        self.first = new_list[0] if new_list else None
        self.bucket_count = new_count
        self.buckets = [None] * new_count
        prev = self.SENTINEL
        for node in new_list:
            bucket = node.hash % new_count
            if self.buckets[bucket] is None:
                self.buckets[bucket] = prev
            prev = node

    def insert(self, bucket, h, node):
        """0x609bad0 (map_insert): the rehash check through
        _Prime_rehash_policy (0x5e52800 when needed), the
        hash stored at node+0x28, the node inserted after
        the bucket's before-begin node (at the list head for
        an empty bucket, the sentinel = &map.first), the
        count incremented."""
        if self._need_rehash():
            self._rehash()
            bucket = h % self.bucket_count
        node.hash = h
        before = self.buckets[bucket]
        if before is None:
            old_first = self.first
            node.next = old_first
            self.first = node
            if old_first is not None:
                self.buckets[old_first.hash
                             % self.bucket_count] = node
            self.buckets[bucket] = self.SENTINEL
        else:
            first_of_bucket = self._bucket_first(bucket)
            node.next = first_of_bucket
            if before is self.SENTINEL:
                self.first = node
            else:
                before.next = node
        self.element_count += 1
        return node


def map_insert(name_set, bucket, h, node):
    """0x609bad0: insert ``node`` into the walker's local
    name set. Called only from the walker."""
    return name_set.insert(bucket, h, node)


def map_find_name(table, key):
    """0x609a1b0: the options-map find by name -- count <=
    0x14 walks the list (length, then memcmp), otherwise the
    hash-bucket walk (_Hash_bytes seed 0xc70f6907, the
    stored hash at node+0x48, the name at +0x08/+0x10).
    Returns the node or None."""
    return table._find_node(key)


def map_erase_next(table, node):
    """0x609a2f0: erase ``node`` from the options map --
    unlink it from its hash bucket, free its two strings
    (+0x38, +0x18, SSO-checked) and the 0x50-byte node,
    decrement the element count. Returns the next node."""
    return table.erase_node(node)


# --- The four sibling Find-family hosts -------------------------------


class SharedHolder:
    """A shared_ptr-like holder {object +0x00, control +0x08}
    that the Plain/BlockTableOptions hosts install into:
    the delegate is loaded from +0x00, and on a successful
    find_e70 the created object and a fresh control (counts
    0x100000001, vtable 0x64c8748) replace them, the old
    control released through counted_release."""

    def __init__(self, obj=None, control=None):
        self.obj = obj
        self.control = control


class Slot10Target:
    """The object the element-scan host's slot-0x10 path
    calls: ``slot_0x10`` is the virtual (called as
    slot_0x10(obj, value-copy, out3-holder, value-out
    holder)); ``deref`` is the object *target resolves to
    when the found node's +0xd9 byte has any of bits
    0x8/0x4/0x2 set (None = the target itself is used)."""

    def __init__(self, slot_0x10=None, deref=None):
        self.slot_0x10 = slot_0x10
        self.deref = deref


def _create_and_find(created, value, arg7, holder):
    """The shared create tail of the Plain/Block hosts: run
    find_e70 on the created object; on success install the
    object and a fresh control (counts 0x100000001, vtable
    0x64c8748) into the holder, releasing the old control
    through counted_release, and return the temp Status; on
    failure call the created object's vtable slot 0x08 with
    the created object (the binary calls it only on this
    path -- on success the register holding the object has
    been overwritten with the old control, which is null
    after the release) and return the temp Status."""
    temp = find_e70(created, value, arg7)
    if temp.is_ok():
        new_control = SharedControl(created)
        new_control.vtable = PLAIN_CONTROL_VTABLE
        old_control = holder.control
        holder.obj = created
        holder.control = new_control
        if old_control is not None:
            counted_release(old_control)
        return temp
    if created is not None and created.slot_0x08 is not None:
        created.slot_0x08(created)
    return temp


def _table_options_host(value, name, arg7, holder, table_name,
                        factory_name, default_options, creator,
                        destroy_defaults=None):
    """The shared skeleton of find_plain_table 0x6080b10 and
    find_block_table 0x60818f0. The delegate is loaded from
    the holder; with a null delegate and a factory name the
    defaults are built directly (slot 0x38 is never called);
    otherwise the delegate's slot 0x38 resolves the options
    struct for the table name. A factory name takes the
    create path (the resolved struct, or the defaults when
    it is null); any other name with a null resolved struct
    is Status code 1 "Mismatched table option: " + name, and
    with a non-null one runs no_equals. Returns the out
    Status."""
    delegate = holder.obj
    if delegate is None:
        if name == factory_name:
            defaults = default_options()
            created = creator(defaults)
            if destroy_defaults is not None:
                destroy_defaults(defaults)
            return _create_and_find(created, value, arg7, holder)
        return Status.build(OPTION_NOT_FOUND, 0,
                            MSG_MISMATCHED_TABLE_OPTION, name)
    name2 = cstr_ctor(table_name)
    resolved = None
    if delegate.slot_0x38 is not None:
        resolved = delegate.slot_0x38(name2)
    if name == factory_name:
        if resolved is None:
            defaults = default_options()
            created = creator(defaults)
            if destroy_defaults is not None:
                destroy_defaults(defaults)
        else:
            created = creator(resolved)
        return _create_and_find(created, value, arg7, holder)
    if resolved is None:
        return Status.build(OPTION_NOT_FOUND, 0,
                            MSG_MISMATCHED_TABLE_OPTION, name)
    return no_equals(None, delegate, value, name, arg7)


def destroy_block_defaults(defaults):
    """The block host's post-creator release of the defaults
    struct's owned sub-objects: every SharedControl value
    in the struct is released through counted_release, and
    an "options_list" entry (the list at +0x90) is destroyed
    through options_list_destroy. The pinned defaults carry
    no owned sub-objects (all zero in the defaults path),
    so this is a no-op for them."""
    if not isinstance(defaults, dict):
        return
    for val in defaults.values():
        if isinstance(val, SharedControl):
            counted_release(val)
    head = defaults.get("options_list")
    if head is not None:
        options_list_destroy(head)


def find_plain_table(value, name, arg7, holder,
                     creator=plain_creator):
    """0x6080b10: the PlainTableOptions host. The delegate
    is loaded from the holder; a null delegate reports
    Status code 1 "Mismatched table option: " + name (with
    a factory name the defaults are built directly instead).
    Otherwise the name "PlainTableOptions" is built and
    the delegate's slot 0x38 resolves the options struct.
    The factory name "plain_table_factory" (19 chars) takes
    the create path (the resolved struct, or the 0x28-byte
    defaults when null); any other name takes no_equals
    when resolved, else the code-1 error. Returns the out
    Status."""
    return _table_options_host(value, name, arg7, holder,
                               "PlainTableOptions",
                               "plain_table_factory",
                               plain_default_options, creator)


def find_block_table(value, name, arg7, holder,
                     creator=block_creator):
    """0x60818f0: the BlockTableOptions host, the same
    skeleton as the plain host with the name
    "BlockTableOptions", the factory name
    "block_based_table_factory" (25 chars) and the 0x260-byte
    creator 0x60dbd80. A null resolved struct builds the
    0xf8-byte defaults (released after the creator); any
    other name takes no_equals when resolved, else the
    code-1 error. Returns the out Status."""
    return _table_options_host(value, name, arg7, holder,
                               "BlockTableOptions",
                               "block_based_table_factory",
                               block_default_options, creator,
                               destroy_defaults=
                               destroy_block_defaults)


def find_by_element_scan(value, table, name, arg5_holder,
                         serializer=default_serializer):
    """0x6098ad0: the element-scan host (out, value, table,
    name, arg5). element_scan runs over the table's vector
    with the name; a null result reports Status code 1
    "Cannot find option: " + name. Otherwise the 0x50-byte
    value is copied (its +0x48 control use-count bumped)
    and the copy's name is replaced with ";" (the resolver
    sentinel); when the scan's out-string equals the query
    name, or the matched node's kind is 0x13, the matcher
    0x60bb9a0 runs (prefix = &found_out, modelled as a
    one-element holder of the found-out value, never null;
    value-out = arg5). Kinds 0x15/0x16 take the delegate
    slot-0x10 virtual path: the object is the found-out
    value plus the int32 at the found node's +0x28,
    dereferenced once when the found node's +0xb1 flag byte
    has any of bits 0x8/0x4/0x2 set; a null object is the
    code-1 error; otherwise the virtual runs with (object,
    value-copy, the out-string, arg5). Any other kind is
    the code-1 error. The value copy's +0x48 control is
    released on exit through counted_release. Returns the
    out Status; arg5_holder receives the value-out string."""
    out_holder = [""]
    found, field20 = element_scan(table, name, out_holder)
    if found is None:
        return Status.build(OPTION_NOT_FOUND, 0,
                            MSG_CANNOT_FIND, name)
    copy = value.copy()
    copy.name = ";"
    try:
        if out_holder[0] == name or found.kind == 0x13:
            return matcher(found, copy, out_holder[0],
                           [field20], arg5_holder,
                           serializer=serializer)
        if found.kind in (0x15, 0x16):
            target = found.slot_0x10_target
            if found.flag_byte & 0x0E and target is not None:
                target = target.deref
            if target is None:
                return Status.build(OPTION_NOT_FOUND, 0,
                                    MSG_CANNOT_FIND, name)
            if target.slot_0x10 is None:
                return Status.ok()
            return target.slot_0x10(target, copy, out_holder,
                                    arg5_holder)
        return Status.build(OPTION_NOT_FOUND, 0,
                            MSG_CANNOT_FIND, name)
    finally:
        # The value copy's +0x48 control is released on
        # exit: counts == 0x100000001 -> the control's
        # vtable slots 0x10 then 0x18; otherwise an atomic
        # decrement, and when it was 1 the 0x5d35070 tail.
        if copy.shared is not None:
            counted_release(copy.shared)
            copy.shared = None


def resolve_all_elements(value, node, table, registry_map,
                         extra):
    """0x609bcb0: the registry walker (out, value, node,
    table, map, extra). A local empty name set is built
    (one bucket, count 1, load 1.0) and the registry map is
    walked: per element the node's slot 0x68 fills the
    search key, name_lookup runs on it, and on a hit
    kind_dispatch runs with the element's value string as
    arg7 and ``extra`` as the extra argument. A
    kind_dispatch code of 1 advances to the next element;
    code 3 accumulates the code-3 status (the message
    strdup'd) and inserts the element's key into the local
    set (a 0x30 node, hash at +0x28) unless already
    present; any other code erases the element from the
    registry map (the erase counter incremented) and, when
    the code is non-zero, accumulates the code status into
    the -0x12a family (message strdup'd, the old one
    freed). When the list is exhausted and erasures
    happened, the outer loop repeats; when the registry map
    is empty the sweep phase runs: every name in the local
    set is looked up in the registry map and erased when
    found. The final Status: the value's +0x00 word's low
    byte non-zero -> success; else the -0x12a family
    non-zero -> that status; else the value's +0x00 word's
    second byte zero -> the -0x128 family status (code 3);
    otherwise success. The accumulated messages are
    transferred to the caller; on the success paths they
    are freed (the model drops them). Returns the out
    Status."""
    local = NameSet(1)
    status_a = None
    status_b = None
    while True:
        if registry_map.element_count == 0:
            break
        element = registry_map.first
        if element is None:
            # The list head is null while the count is
            # non-zero: the StatusB code and sub-bytes are
            # zeroed (the message is kept) and the sweep
            # phase runs.
            if status_b is not None:
                status_b = Status(0, 0, status_b.msg, 0)
            break
        erased = 0
        while element is not None:
            key = node.slot_0x68(node, element.key)
            out_holder = [""]
            found = name_lookup(key, table, out_holder)
            if found is None:
                element = element.next
                continue
            kd = kind_dispatch(None, value, node, found, key,
                               out_holder[0], element.value,
                               extra)
            code = kd.code
            if code == 1:
                element = element.next
                continue
            if code == 3:
                status_b = Status(kd.code, kd.subcode,
                                  kd.msg, kd.severity)
                if local.find_name(element.key) is None:
                    h = hash_bytes(element.key)
                    bucket = h % local.bucket_count
                    map_insert(local, bucket, h,
                               NameSetNode(element.key))
                element = element.next
                continue
            erased += 1
            nxt = map_erase_next(registry_map, element)
            if code != 0:
                status_a = Status(kd.code, kd.subcode,
                                  kd.msg, kd.severity)
            element = nxt
        if erased == 0:
            break
    # Sweep phase: every name in the local set is looked up
    # in the registry map and erased when found.
    for name_node in list(local._nodes()):
        hit = map_find_name(registry_map, name_node.key)
        if hit is not None:
            map_erase_next(registry_map, hit)
    # Final Status.
    if (value.code & 0xFF) != 0:
        return Status.ok()
    if status_a is not None and status_a.code != 0:
        return status_a
    if ((value.code >> 8) & 0xFF) == 0:
        if status_b is not None:
            return status_b
        return Status.ok()
    return Status.ok()
