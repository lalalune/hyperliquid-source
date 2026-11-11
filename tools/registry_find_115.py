"""RE-001: pin node #115 registry Find: name normalization, the '='
options parser, the options-map merge and the delegate table search.

Bounded question: after the host 0x6077820 has decided a name is
not the default and not "BasicStatistics", how does node #115
resolve that name -- through the Find pair 0x609e510/0x609a410,
the '=' options parser 0x60c1190, the options map and the delegate
table search 0x6097630 -- and what does it report when the name
cannot be resolved?

Behaviour, pinned from the node #115 binary
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

  * Find entry 0x609e510 (out, value, delegate, name, out-string,
    map): the name is empty or equal to the global default name
    at 0x6508980 (length, then memcmp) -> clear the out-string
    and the map, return success. A null delegate -> Find normal
    with an empty-string fallback. A non-null delegate -> its
    slot 0x78 name is fetched, then Find normal runs with that
    string as the fallback; its status is moved into out and a
    failure returns at once. On success the delegate-name check
    runs: slot 0x80's target against the canonical GOT entry
    0x64eceb8 (0x5d2e770) -- a different target is called as a
    predicate on the out-string (false -> return); the canonical
    target compares the out-string against the slot 0x70 string,
    else the slot 0x90 string. On a match the register path
    runs: the 0x50-byte value struct is deep-copied, the copy's
    name is replaced wholesale with ";", the thunk 0x6098510
    runs the delegate table search 0x6097630, and on worker
    success the worker's accumulated string is parsed by the
    parser into a fresh temp map and merged insert-if-absent
    into the real map. A worker or parser failure on this path
    is swallowed: its message is freed and Find returns the
    success status left by Find normal.
  * Find normal 0x609a410 (out, name, fallback, out-string,
    ctx-map): the name is empty or the default -> out-string =
    fallback. No '=' (0x3d) in the name -> out-string = name.
    Otherwise the parser runs; a parser failure assigns the
    name to the out-string, clears the map and resets out to
    success. On parser success the "id" path runs: key "id" is
    looked up in the map; found -> out-string = the node's
    value, the node is erased, and an out-string equal to the
    global default name is cleared; not found -> the fallback
    when it is non-empty, else the name with the map cleared.
  * Parser 0x60c1190 (out, name, ctx-map): the name is trimmed
    (0x61d11f0); while it is longer than 2 and starts with '{'
    and ends with '}' the outer braces are stripped and it is
    re-trimmed. Then key=value pairs separated by ';' are read:
    find_first_of over "={};" must land on '=' first, else
    Status code 4 "Unexpected char in key"; an empty key is
    code 4 "Empty key found"; the value comes from
    0x60b97f0 (brace groups with depth counting, or up to the
    next ';'); each pair is stored via operator[] 0x60c0e90
    (insert-if-absent, then _M_assign). No delimiter at all is
    code 4 "Mismatched key value pair, '=' expected". A value
    extraction failure is copied into out via 0x60b7ac0.
  * Value extractor 0x60b97f0 (out, str, sep, start, &cursor,
    value-out): leading whitespace is skipped; '{' starts a
    brace-group scan (depth +1 on '{', -1 on '}'; unbalanced is
    code 4 "Mismatched curly braces for nested options"; the
    value is the trimmed inner content, then whitespace is
    skipped and ';' is required, else code 4 "Unexpected chars
    after nested options"; at end of string the cursor stays at
    or past the length). Otherwise the value is the trimmed
    str[start..p) up to ';' (or to the end, with the cursor
    set to -1). start >= len clears the value-out and sets the
    cursor to -1. Success zeroes out.
  * Options map (unordered_map<string, string>): nodes are
    0x50 bytes {next +0x00, key string +0x08, value string
    +0x28, hash +0x48}; the header is {buckets +0x00,
    bucket_count +0x08, first node +0x10, element_count +0x18,
    rehash policy +0x20..0x30}. find 0x609a1b0 walks the list
    while the element count is <= 20 (key length, then memcmp),
    else the hash bucket (_Hash_bytes, seed 0xc70f6907; bucket
    = hash % bucket_count; stored hash, length, memcmp).
    erase 0x609a2f0 unlinks the node, destroys both strings and
    sized-deletes it. operator[] 0x60c0e90 inserts a 0x50-byte
    node when absent (key copied, value "", hash stored,
    rehash via 0x5d38260 when _M_need_rehash says so) and
    returns &node->value. clear 0x5d5b300 destroys every node
    and zeroes the buckets, the first node and the count.
  * Worker 0x6097630 (out, value, delegate, prefix-string,
    out-string): the delegate's vector at +0x08..+0x10 holds
    0x30-byte elements; each element's list starts at
    *(element+0x28)+0x10, next at +0x00. Per node: skip when
    +0xd4 is 4 or 5, skip when +0xd8 & 0x2000. When the value's
    +0x04 byte is set and +0xd8 & 0x100, a full 0x50-byte copy
    of the value is built with +0x04 forced to 1 and the
    matcher runs on the copy; when +0x04 is set and the kind
    +0xd0 is 0x15 or 0x16, the node is skipped unless the
    value's +0x28 field is 2 or +0xd8 & 0x8000 is clear.
    Otherwise the matcher runs on the value itself. Each
    attempt builds name = prefix-string + node name and calls
    the matcher 0x60bb9a0; a matcher error returns at once
    (first match wins). A no-match that leaves the value-out
    string non-empty appends name + "=" + value-out to the
    out-string (the worker adds no ';' separator between
    pairs) and the search continues. No match at all zeroes
    out. The out-string is the caller's accumulator: the thunk
    clears it before the search and Find entry parses it after.
  * Matcher 0x60bb9a0 (out, node+0x28, value, name, prefix,
    value-out): no match (out zeroed) when the prefix is null
    or node+0xd4 == 4. node+0xd8 & 0x2000 is Status code 3,
    msg1 = the name, msg2 = "Cannot serialize option: ". When
    node+0x60 != 0 the virtual slot 0x40 of node+0x28 fills
    out directly. Otherwise the kind +0xd0 dispatches: 0x15
    takes the resolver path (the value is copied, its name
    replaced with ";", the resolver 0x60971c0 runs); any
    other kind takes the serializer path: when the value's
    +0x04 byte is set, +0xd8 & 0x100 must be set or there is
    no match; the serializer 0x60ba600 is then called with the
    object at prefix + int32(node+0x28), the kind and the
    value-out -- true means serialized (no match), false is
    Status code 4, msg1 = the name, msg2 = "Cannot serialize
    option: ". Kind 0x16 takes the delegate-name path (slot
    0x78 on the name object at prefix + int32(node+0x28))
    when +0xd8 & 0x8000 is set, the value's +0x28 field is
    not 2, and the value's +0x04 byte is clear or +0xd8 &
    0x100 is set; the same gate with +0x04 set and 0x100
    clear is no match. Otherwise kind 0x16 takes the resolver
    path (including when the value's +0x28 field is 2).
    Flag chains: when +0xd8 & 0x800/0x400/0x200 is set, the
    name object is followed through *(%rbp) once and the body
    runs on the linked object; a null link is no match on the
    0x15 path. On the 0x16 resolver path the
    0xb1 flag (node+0xd9) clears the copy's +0x04 byte, which
    skips the '=' requirement; otherwise a non-zero +0x04
    byte requires the resolved string to contain '=', and a
    missing '=' clears the value-out. After a chain is
    exhausted with no object left, the value-out becomes the
    global default name, unless the 0xb1 flag is clear and the
    value's +0x04 byte is set, which clears it instead.
  * Resolver 0x60971c0 (out, name-object, value, empty): the
    name object's slot 0x60 string is returned as-is, unless
    it contains '=' -- then '{' + the part before '=' + '}' is
    returned.
  * Fallback variant 0x609e2d0 (out, a, b, c): b non-null ->
    the delegate implementation 0x6097110 fills out through
    the object's vtable slot 0x48 (via wrapper 0x6097150) and
    the temp out is moved into out. b null and c+0x18 == 0 ->
    out stays success. Otherwise Status code 4, msg1 = "",
    msg2 = "Cannot configure null object ".
  * Status builder 0x61cf670 (re-shipped from #3440): out =
    {code u8 +0x00, subcode u8 +0x01, severity u8 +0x02, msg
    char* +0x08}; the message is msg1, or msg1 + ": " + msg2
    when msg2 is non-empty.

Open unknowns carried in the packet (see README): the runtime
contents of the global default name at 0x6508980 (set by static
init; the model takes it as a parameter, defaulting to
"default"); the serializer 0x60ba600's per-kind rules (a
boundary: the model takes the serializer as a callable); the
sibling entry point 0x609a740, a separate Find entry point
whose body is not pinned here.
"""

# --- Pinned addresses (node #115) -------------------------------------

FIND_ENTRY = 0x609E510
FIND_NORM = 0x609A410
PARSER = 0x60C1190
TRIM = 0x61D11F0
VALUE_EXTRACT = 0x60B97F0
MAP_FIND = 0x609A1B0
MAP_ERASE = 0x609A2F0
MAP_INDEX = 0x60C0E90
MAP_CLEAR = 0x5D5B300
STATUS_COPY = 0x60B7AC0
VALUE_ASSIGN = 0x60B79E0
RANGE_ASSIGN = 0x60B7CD0
VALUE_COPY = 0x60B9D70
THUNK = 0x6098510
WORKER = 0x6097630
MATCHER = 0x60BB9A0
RESOLVER = 0x60971C0
SERIALIZER = 0x60BA600
FALLBACK = 0x609E2D0
FALLBACK_DELEGATE = 0x6097150
DELEGATE_IMPL = 0x6097110
VALUE_DTOR = 0x5E33FB0
CSTR_REPLACE = 0x60B79B0
CSTR_CTOR = 0x60B7D80
STATUS_BUILDER = 0x61CF670

# The delegate's canonical slot-0x80 target, from the GOT entry
# at 0x64eceb8 (R_X86_64_RELATIVE 0x5d2e770).
CANONICAL_DELEGATE = 0x5D2E770
# __libc_single_threaded, consulted by the shared-control release
# paths (0x64ed290, R_X86_64_GLOB_DAT).
LIBC_SINGLE_THREADED = 0x64ED290

LINEAR_WALK_LIMIT = 20
HASH_SEED = 0xC70F6907
VALUE_SIZE = 0x50
MAP_NODE_SIZE = 0x50
MAX_STRING_LEN = 0x3FFFFFFFFFFFFFFF

NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4

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


class NameObject:
    """The object the matcher resolves names through: its vtable
    slot 0x60 returns a string (0x60971c0's input) and slot 0x78
    returns a string (the 0x16 delegate-name path). The binary
    reaches both through the prefix pointer plus the int32 at
    node+0x28; here the object is held directly."""

    def __init__(self, slot_0x60="", slot_0x78=""):
        self._slot_0x60 = slot_0x60
        self._slot_0x78 = slot_0x78

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


class TableNode:
    """One node in a delegate element's list: {next +0x00, name
    string +0x08, object pointer +0x28, kind +0xd0, state
    +0xd4, flags +0xd8, flag byte +0xd9}."""

    def __init__(self, name, obj, kind=0, state=0, flags=0,
                 flag_b1=False):
        self.name = name
        self.obj = obj
        self.kind = kind
        self.state = state
        self.flags = flags
        self.flag_b1 = flag_b1
        self.next = None


class TableEntry:
    """One 0x30-byte delegate element: the name string at +0x20
    (its pointer is the matcher's prefix) and the node list
    whose head is *(element+0x28)+0x10."""

    def __init__(self, name, nodes=()):
        self.name = name
        self.nodes = list(nodes)


class Delegate:
    """The registry delegate: a vector of TableEntry at +0x08,
    plus the vtable slots Find entry consults -- 0x70 and 0x90
    (name strings), 0x78 (the delegate-name string) and 0x80
    (the predicate, or the canonical 0x5d2e770 target)."""

    def __init__(self, elements=(), slot_0x78_name="",
                 slot_0x80_target=None, slot_0x80_predicate=None,
                 slot_0x70_name="", slot_0x90_name=""):
        self.elements = list(elements)
        self.slot_0x78_name = slot_0x78_name
        self.slot_0x80_target = slot_0x80_target
        self.slot_0x80_predicate = slot_0x80_predicate
        self.slot_0x70_name = slot_0x70_name
        self.slot_0x90_name = slot_0x90_name


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
    if obj.has_virtual:
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


def worker(delegate, value, prefix_string="", out_string=None,
           serializer=default_serializer):
    """0x6097630: search the delegate's table. ``prefix_string``
    is the worker's 4th argument (the empty string from the
    thunk); ``out_string`` is a one-element list holding the
    accumulator the thunk cleared. Returns the out Status."""
    if out_string is None:
        out_string = [""]
    for element in delegate.elements:
        for node in element.nodes:
            if node.state in (4, 5):
                continue
            if node.flags & 0x2000:
                continue
            if value.has_value and (node.flags & 0x100):
                # Copy path (0x6097bd8): a full 0x50-byte copy
                # with +0x04 forced to 1.
                attempt_value = value.copy()
                attempt_value.has_value = 1
            elif value.has_value and node.kind in (0x15, 0x16):
                # 0x6097ef8 path: skip unless the value's +0x28
                # field is 2 or +0xd8 & 0x8000 is clear.
                if value.field28 != 2 and (node.flags & 0x8000):
                    continue
                attempt_value = value
            else:
                attempt_value = value
            value_out = [""]
            status = matcher(node, attempt_value,
                             prefix_string + node.name,
                             element, value_out,
                             serializer=serializer)
            if attempt_value is not value:
                attempt_value.destroy()
            if not status.is_ok():
                return status
            if value_out[0]:
                # The attempt left a value-out: append
                # name + "=" + value-out to the accumulator.
                # The worker adds no ';' separator.
                out_string[0] += prefix_string + node.name + \
                    "=" + value_out[0]
    return Status.ok()


def thunk(delegate, value, prefix_string="",
          serializer=default_serializer):
    """0x6098510: NUL-terminate the out-string (modelled as
    clearing it), build a fresh empty prefix string and run the
    worker. Returns (status, out_string)."""
    out_string = [""]
    status = worker(delegate, value, prefix_string, out_string,
                    serializer=serializer)
    return status, out_string[0]


def find_entry(value, delegate, name, out_string, options_map,
               default_name=DEFAULT_NAME,
               serializer=default_serializer):
    """0x609e510: the Find entry point. ``out_string`` and
    ``options_map`` are mutated in place; the return is
    (status, out_string_after)."""
    if not name or name == default_name:
        out_string[0] = ""
        options_map.clear()
        return Status.ok(), out_string[0]
    if delegate is None:
        status, result = find_norm(name, "", options_map,
                                   default_name)
        out_string[0] = result
        return status, out_string[0]
    # Non-null delegate: slot 0x78 name, then Find normal with
    # that string as the fallback.
    status, result = find_norm(name, delegate.slot_0x78_name,
                               options_map, default_name)
    out_string[0] = result
    if not status.is_ok():
        return status, out_string[0]
    # Delegate-name check.
    matched = False
    if delegate.slot_0x80_target != CANONICAL_DELEGATE:
        if delegate.slot_0x80_predicate is not None:
            matched = bool(delegate.slot_0x80_predicate(result))
    else:
        if result == delegate.slot_0x70_name or \
                result == delegate.slot_0x90_name:
            matched = True
    if not matched:
        return Status.ok(), out_string[0]
    # Register path: deep-copy the value, replace the copy's
    # name with ";", run the table search.
    copy = value.copy()
    copy.name = ";"
    status, accumulated = thunk(delegate, copy,
                                serializer=serializer)
    copy.destroy()
    if not status.is_ok():
        # The worker failure is swallowed: its message is
        # freed and Find returns the success left by Find
        # normal.
        return Status.ok(), out_string[0]
    # Parse the accumulated string into a fresh temp map and
    # merge it insert-if-absent into the real map. A parser
    # failure is swallowed the same way.
    temp_map = OptionsMap()
    parse_status = parse_options(accumulated, temp_map)
    if not parse_status.is_ok():
        return Status.ok(), out_string[0]
    for key, val in temp_map.items():
        if options_map.find(key) is None:
            options_map.index(key).set(val)
    return Status.ok(), out_string[0]


def fallback(a, b, c_has_0x18):
    """0x609e2d0: the fallback Find variant. ``b`` is the
    delegate object (or None); ``c_has_0x18`` is whether
    c+0x18 is non-zero. Returns the out Status."""
    if b is not None:
        return delegate_impl(b)
    if not c_has_0x18:
        return Status.ok()
    return Status.build(INVALID_ARGUMENT, 0, "",
                        MSG_CANNOT_CONFIGURE_NULL)


def fallback_delegate(obj):
    """0x6097150: call the delegate implementation with r8d=0."""
    return delegate_impl(obj)


def delegate_impl(obj):
    """0x6097110: call the object's vtable slot 0x48, which
    fills the out Status. ``obj`` is a Delegate carrying a
    ``slot_0x48`` callable, or None."""
    if obj is None or getattr(obj, "slot_0x48", None) is None:
        return Status.ok()
    return obj.slot_0x48()
