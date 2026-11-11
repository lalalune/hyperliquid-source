"""Python model of node #115's ObjectRegistry registrar map lifecycle.

Pinned by research/work-items/RE-001-registrar-map-115 (RE-001):
the static init 0x620b470, the string-install helper 0x5f204e0, the
registrar unordered_map at 0x6509540, its 0x50-byte nodes, the map
destructor 0x620a500, and the ObjectRegistry ctor replay loop 0x61f91b0
(re-shipped from #4015).

The model is a small explicit-memory simulation: flat address-keyed
fields plus an allocation log, so tests can assert the exact operation
sequence the binary performs.
"""

# --- pinned constants (see records.json) -----------------------------------

MAP_ADDR = 0x6509540
MAP_SIZE = 0x38
NODE_SIZE = 0x50

# _Hashtable field offsets within the map object.
MAP_BUCKETS = 0x00
MAP_BUCKET_COUNT = 0x08
MAP_BEFORE_BEGIN = 0x10
MAP_ELEMENT_COUNT = 0x18
MAP_MAX_LOAD_FACTOR = 0x20
MAP_NEXT_RESIZE = 0x28
MAP_SINGLE_BUCKET = 0x30

# _Hash_node field offsets within a node.
NODE_NXT = 0x00
NODE_KEY = 0x08        # std::string: ptr +0x08, length +0x10, capacity/SSO +0x18
NODE_VALUE = 0x28      # std::function: functor +0x28, manager +0x38, invoker +0x40
NODE_HASH = 0x48        # cached hash-code slot (layout inference)

# std::string field offsets within a string object.
STR_PTR = 0x00
STR_LEN = 0x08
STR_CAP = 0x10          # capacity; overlaps the SSO buffer start

# std::function field offsets within a function object.
FN_FUNCTOR = 0x00
FN_MANAGER = 0x10
FN_INVOKER = 0x18

SSO_LIMIT = 15
MAX_LOAD_FACTOR = 1.0
MAX_LOAD_FACTOR_BITS = 0x3F800000

STATIC_INIT_FDE = (0x620B470, 0x620B57D)
STRING_ASSIGN_FDE = (0x5F204E0, 0x5F205C3)
MAP_DTOR_FDE = (0x620A500, 0x620A5BD)
CTOR_FDE = (0x61F91B0, 0x61F9277)

# The three build-info literals installed by the static init.
BUILD_SHA = "6a436150417120a3f9732d65a2a5c2b8d19b60fc"
BUILD_TAG = "rocksdb_build_git_tag:v8.1.1"
BUILD_DATE = "rocksdb_build_date:2023-04-06 16:38:52"
NULL_CTOR_MESSAGE = "basic_string: construction from null is not valid"

# Census constants (reproduced by census.py).
MAP_LEA_SITES = (0x61F9234, 0x620B516)
STRING_HELPER_CALLS = 12
GETTER_CALLERS = (0x5FF88FC, 0x61F9420, 0x6206A3D)
CTOR_CALLER = 0x61F9380


class LogicError(Exception):
    """std::logic_error raised by the string helper on a null input."""


class Memory:
    """Flat address-keyed fields plus allocation tracking and an ops log."""

    def __init__(self):
        self.fields = {}
        self.blobs = {}
        self.cells = {}
        self.next_addr = 0x1000000
        self.ops = []

    def alloc(self, size):
        addr = self.next_addr
        self.next_addr += size
        self.cells[addr] = size
        self.ops.append(("alloc", addr, size))
        return addr

    def free(self, addr, size):
        if addr not in self.cells:
            raise AssertionError("free of unknown address %#x" % addr)
        if self.cells[addr] != size:
            raise AssertionError(
                "free size mismatch at %#x: got %d, expected %d"
                % (addr, size, self.cells[addr]))
        del self.cells[addr]
        self.ops.append(("free", addr, size))

    def put(self, addr, off, value):
        self.fields[addr + off] = value

    def get(self, addr, off, default=None):
        return self.fields.get(addr + off, default)


class StdString:
    """A libstdc++ std::string: ptr/len/capacity over the explicit heap."""

    def __init__(self, mem, addr):
        self.mem = mem
        self.addr = addr

    def _set_fields(self, ptr, length, capacity):
        self.mem.put(self.addr, STR_PTR, ptr)
        self.mem.put(self.addr, STR_LEN, length)
        self.mem.put(self.addr, STR_CAP, capacity)

    @property
    def ptr(self):
        return self.mem.get(self.addr, STR_PTR)

    @property
    def length(self):
        return self.mem.get(self.addr, STR_LEN)

    @property
    def capacity(self):
        return self.mem.get(self.addr, STR_CAP)

    @property
    def sso_buffer(self):
        return self.addr + STR_CAP

    def is_local(self):
        return self.ptr == self.sso_buffer

    def value(self):
        if self.is_local():
            return self.mem.blobs.get(self.sso_buffer, "")
        return self.mem.blobs.get(self.ptr, "")[:self.length]


def string_assign(mem, obj_addr, cstr):
    """The helper 0x5f204e0: install a const char* into a std::string.

    Returns the StdString. Raises LogicError on a null input, exactly as
    the binary's __throw_logic_error arm does.
    """
    s = StdString(mem, obj_addr)
    # The helper writes the SSO-buffer address into the data pointer first.
    s._set_fields(s.sso_buffer, 0, 0)
    if cstr is None:
        raise LogicError(NULL_CTOR_MESSAGE)
    n = len(cstr)
    if n <= SSO_LIMIT:
        # SSO path: copy into the inline buffer, NUL-terminate.
        mem.blobs[s.sso_buffer] = cstr
        s._set_fields(s.sso_buffer, n, n)
        mem.ops.append(("string_sso", obj_addr, n))
    else:
        # Heap path: _M_create(n, 0), then memcpy.
        buf = mem.alloc(n + 1)
        mem.blobs[buf] = cstr
        s._set_fields(buf, n, n)
        mem.ops.append(("string_heap", obj_addr, n))
    return s


def string_dispose(mem, obj_addr):
    """std::string::_M_dispose as used by the map destructor.

    Frees the heap buffer iff the data pointer is not the SSO buffer,
    with the sized delete (capacity + 1).
    """
    s = StdString(mem, obj_addr)
    if not s.is_local():
        mem.free(s.ptr, s.capacity + 1)


class StdFunction:
    """A libstdc++ std::function: functor/manager/invoker triple."""

    def __init__(self, mem, addr, manager=None):
        self.mem = mem
        self.addr = addr
        mem.put(addr, FN_MANAGER, manager)

    @property
    def manager(self):
        return self.mem.get(self.addr, FN_MANAGER)


class RegistrarNode:
    """One 0x50-byte _Hash_node: nxt, key string, creator function, hash."""

    def __init__(self, mem, addr, name, manager):
        self.mem = mem
        self.addr = addr
        mem.put(addr, NODE_NXT, None)
        mem.put(addr, NODE_HASH, None)
        string_assign(mem, addr + NODE_KEY, name)
        self.creator = StdFunction(mem, addr + NODE_VALUE, manager=manager)

    @property
    def key(self):
        return StdString(self.mem, self.addr + NODE_KEY)

    @property
    def nxt(self):
        return self.mem.get(self.addr, NODE_NXT)

    @nxt.setter
    def nxt(self, value):
        self.mem.put(self.addr, NODE_NXT, value)


class RegistrarMap:
    """The std::unordered_map at 0x6509540 (0x38 bytes)."""

    def __init__(self, mem, addr=MAP_ADDR):
        self.mem = mem
        self.addr = addr

    def _set(self, off, value):
        self.mem.put(self.addr, off, value)

    def _get(self, off, default=None):
        return self.mem.get(self.addr, off, default)

    @property
    def buckets(self):
        return self._get(MAP_BUCKETS)

    @property
    def bucket_count(self):
        return self._get(MAP_BUCKET_COUNT)

    @property
    def before_begin(self):
        return self._get(MAP_BEFORE_BEGIN)

    @property
    def element_count(self):
        return self._get(MAP_ELEMENT_COUNT)

    @property
    def max_load_factor(self):
        return self._get(MAP_MAX_LOAD_FACTOR)

    @property
    def next_resize(self):
        return self._get(MAP_NEXT_RESIZE)

    @property
    def single_bucket(self):
        return self.addr + MAP_SINGLE_BUCKET

    def is_empty_state(self):
        """The exact empty-state invariant the static init establishes."""
        return (
            self.buckets == self.single_bucket
            and self.bucket_count == 1
            and self.before_begin is None
            and self.element_count == 0
            and self.max_load_factor == MAX_LOAD_FACTOR
            and self.next_resize == 0
            and self._get(MAP_SINGLE_BUCKET) is None
        )

    def chain(self):
        """Node addresses in _M_before_begin chain order."""
        out = []
        node = self.before_begin
        while node is not None:
            out.append(node)
            node = self.mem.get(node, NODE_NXT)
        return out


def static_init(mem):
    """The static init 0x620b470: build-info strings + map init + atexit.

    Returns (registrar_map, build_strings, atexit_registrations) where the
    registrations are (function, argument) pairs in registration order.
    """
    strings = {}
    for addr, literal in ((0x65095C0, BUILD_SHA),
                          (0x65095A0, BUILD_TAG),
                          (0x6509580, BUILD_DATE)):
        strings[addr] = string_assign(mem, addr, literal)
    reg = RegistrarMap(mem)
    # In-place _Hashtable empty-state initialization (0x620b516..0x620b54e).
    reg._set(MAP_BUCKETS, reg.single_bucket)
    reg._set(MAP_BUCKET_COUNT, 1)
    reg._set(MAP_BEFORE_BEGIN, None)
    reg._set(MAP_ELEMENT_COUNT, 0)
    reg._set(MAP_MAX_LOAD_FACTOR, MAX_LOAD_FACTOR)
    reg._set(MAP_NEXT_RESIZE, 0)
    reg._set(MAP_SINGLE_BUCKET, None)
    # __cxa_atexit registrations, in order (the map's is the tail jmp).
    atexit = [
        ("std::string::~basic_string", 0x65095C0),
        ("std::string::~basic_string", 0x65095A0),
        ("std::string::~basic_string", 0x6509580),
        ("registrar_map_destructor", MAP_ADDR),
    ]
    return reg, strings, atexit


def ctor_replay(reg, add_library):
    """The ObjectRegistry ctor replay loop 0x61f91b0..0x61f9277.

    Walks the map's node chain and calls add_library(name, creator)
    per node, in chain order. Returns the list of (name, creator) pairs
    visited. On this target the map is empty, so the list is empty.
    """
    visited = []
    node = reg.before_begin
    while node is not None:
        name = StdString(reg.mem, node + NODE_KEY).value()
        creator = reg.mem.get(node + NODE_VALUE, FN_MANAGER)
        visited.append((name, creator))
        add_library(name, creator)
        node = reg.mem.get(node, NODE_NXT)
    return visited


def map_destroy(mem, reg):
    """The registrar-map destructor 0x620a500..0x620a5bd.

    Destroys every node in chain order (manager op 3, key-string
    dispose, sized free 0x50), then tears down the bucket array.
    Returns the list of (name, manager_called) pairs in destroy order.
    """
    destroyed = []
    node = reg.before_begin
    while node is not None:
        nxt = mem.get(node, NODE_NXT)
        manager = mem.get(node + NODE_VALUE, FN_MANAGER)
        called = False
        if manager is not None:
            manager(node + NODE_VALUE, node + NODE_VALUE, 3)
            called = True
        name = StdString(mem, node + NODE_KEY).value()
        string_dispose(mem, node + NODE_KEY)
        mem.free(node, NODE_SIZE)
        destroyed.append((name, called))
        node = nxt
    # Bucket teardown: memset(buckets, 0, count * 8), zero the counters,
    # and free the bucket array unless it is the inline single bucket.
    count = reg.bucket_count
    buckets = reg.buckets
    mem.ops.append(("memset", buckets, count * 8))
    reg._set(MAP_ELEMENT_COUNT, 0)
    reg._set(MAP_BEFORE_BEGIN, None)
    if buckets != reg.single_bucket:
        mem.free(buckets, count * 8)
    return destroyed
