"""Model of node #115's RegisterEncryptionBuiltins registrar.

Pins the complete behavior of the lambda inside
``rocksdb::_GLOBAL__N_1::RegisterEncryptionBuiltins()`` (host
0x5ff88c0..0x5ff9c50, reached once via the 9-byte tail-call thunk
0x5ff9c50 from two pthread_once call sites):

  * block 1 creates the ``encryption`` ObjectLibrary (0x90-byte
    make_shared block, control-block vtable 0x64d00f0, counts
    0x100000001, version float 1.0) and appends it to the
    ObjectRegistry libraries vector under the registry mutex;
  * blocks 2-4 register three FactoryEntry records through the
    helper 0x5ff8260 (find-or-insert on the registry map, append
    one qword to the name's vector):
      1. name ``EncryptionProvider``, creator E_ (``_M_invoke``
         0x5ff6d60, manager 0x5fefa50), pattern ``CTR``,
         element ``://test`` mode 2;
      2. name ``EncryptionProvider``, creator E0 (``_M_invoke``
         0x5ff6a00, manager 0x5fefa80), pattern ``1://test``,
         no elements;
      3. name ``BlockCipher``, creator E_ (``_M_invoke`` 0x5ff7120,
         manager 0x5fefab0), pattern ``ROT13``, element ``:``
         mode 3.
  * PatternEntry matching follows the pinned str-match 0x61f8430
    and elem-match 0x61f8280 semantics (PR #3983): an empty
    +0x58 vector means exact match only; otherwise the query must
    start with the pattern, every +0x58 element must match in
    sequence, and the tail is decided by the last element's mode.

FactoryEntry layout (0x30 bytes): +0x00 vtable, +0x08 PatternEntry*,
+0x10..+0x20 the std::function functor storage (16 zero bytes for
these stateless lambdas), +0x20 manager, +0x28 invoker.  D2 destroys
the function via manager(this+0x10, this+0x10, op 3) and deletes
the PatternEntry through its vtable slot 1.

The creator lambdas:
  * E0 (0x5ff6a00) builds a CTREncryptionProvider via C1 0x5ff6880
    from a BlockCipher looked up in the registry, and registers
    options via Configurable::RegisterOptions 0x6099ce0.
  * E_ (0x5ff6d60) checks EndsWith(name, "://test") (0x61d1390);
    on the true branch it resolves ``ROT13BlockCipherOptions``
    (literal 0x443890) and then builds the provider via C1;
    on the false branch it builds the provider directly.
  * BlockCipher E_ (0x5ff7120) finds ':' in the name, builds
    ``ROT13BlockCipherOptions``, and creates the ROT13 cipher;
    a bad substring throws out_of_range (format at 0x958cf8,
    ``basic_string::substr`` at 0x43e542).

Environment limits: no cargo/rustc on this VM; the model is the
deterministic Python layer, verified against the raw binary.
"""

# --- pinned addresses -------------------------------------------------

HOST = 0x5FF88C0
HOST_COLD = 0x5FF844A
THUNK = 0x5FF9C50
REGISTER_HELPER = 0x5FF8260
STRING_CTOR = 0x5FF0300
STRING_RANGE = 0x5FEFD80
VEC_GROW = 0x5FF7420
REG_GETTER = 0x61F92B0  # pinned by PR #4015
FIND_OR_INSERT = 0x5FD1DA0  # pinned by PR #3983
VEC_INSERT = 0x5FD17C0  # pinned by PR #3983

LIBRARY_VTABLE = 0x64D00F0
LIBRARY_TYPEINFO = 0x64CF808
LIBRARY_COUNTS = 0x100000001
LIBRARY_VERSION = 1.0
LIBRARY_NAME = "encryption"

PATTERN_VTABLE = 0x64D8ED0
PATTERN_TYPEINFO = 0x64D8E90

FACTORY_VTABLE_ENC = 0x64D0090
FACTORY_VTABLE_CIPHER = 0x64D00C0

CREATORS = {
    "E_": {"invoke": 0x5FF6D60, "manager": 0x5FEFA50,
           "typeinfo": 0x64CF7B8, "kind": "EncryptionProvider"},
    "E0": {"invoke": 0x5FF6A00, "manager": 0x5FEFA80,
           "typeinfo": 0x64CF7C8, "kind": "EncryptionProvider"},
    "Cipher": {"invoke": 0x5FF7120, "manager": 0x5FEFAB0,
               "typeinfo": 0x64CF7D8, "kind": "BlockCipher"},
}

CTR_PROVIDER_CTOR = 0x5FF6880
REGISTER_OPTIONS = 0x6099CE0
ENDS_WITH = 0x61D1390
ROT13_OPTIONS = "ROT13BlockCipherOptions"


# --- small helpers ----------------------------------------------------

def ends_with(name, suffix):
    """rocksdb::EndsWith 0x61d1390."""
    return name.endswith(suffix)


class GrowableVector:
    """std::vector growth as used by the libraries vector and the
    PatternEntry +0x58 element vector: capacity doubles on growth
    (vec-insert 0x5fd17c0 / grow 0x5ff7420), elements are preserved
    in order, strings are deep-copied."""

    def __init__(self):
        self.items = []
        self.capacity = 0

    def _grow(self):
        self.capacity = 1 if self.capacity == 0 else 2 * self.capacity

    def append(self, item):
        if len(self.items) == self.capacity:
            self._grow()
        self.items.append(item)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, i):
        return self.items[i]


# --- PatternEntry ------------------------------------------------------

class PatternEntry:
    """0x70-byte record, vtable 0x64d8ed0.

    +0x08 pattern string, +0x28 pattern-length copy,
    +0x30 vector of plain strings (empty in all three entries here),
    +0x48 flag byte, +0x50 pointer (0), +0x58 vector of
    0x28-byte {string, mode u32} elements.
    """

    def __init__(self, pattern, elements=(), flag=1, offset50=0):
        self.pattern = pattern
        self.elements = [(s, int(m)) for s, m in elements]
        self.flag = flag
        self.offset50 = offset50

    def _elem_match(self, pos, query, mode, element):
        """Per-element matcher 0x61f8280.  Returns the new position,
        or -1 on failure.  Mode 2: the element must occur AT pos.
        Modes 0/1: string::find from pos+1.  Mode 3: like 0/1 but
        the gap (after an optional '-') must be all digits.
        Mode 4: like 3 but the gap may contain at most one '.'
        and must hold at least one digit."""
        if mode == 2:
            if query[pos:pos + len(element)] == element:
                return pos + len(element)
            return -1
        start = pos + 1
        found = query.find(element, start)
        if found < 0:
            return -1
        gap = query[pos:found]
        if mode in (3, 4):
            body = gap[1:] if gap.startswith("-") else gap
            if mode == 3:
                if not body or not body.isdigit():
                    return -1
            else:  # mode 4
                if not body or body.count(".") > 1:
                    return -1
                if not body.replace(".", "").isdigit():
                    return -1
                if not any(c.isdigit() for c in body):
                    return -1
        return found + len(element)

    def matches(self, query):
        """str-match 0x61f8430 (entry, pattern, pattern_len, query,
        query_len) as pinned by PR #3983."""
        pattern = self.pattern
        if not self.elements:
            # Empty +0x58 vector: exact match only; the +0x48
            # flag is NOT checked on this path.
            return query == pattern
        if len(query) == len(pattern):
            # Equal lengths with a non-empty vector: exact match,
            # and the +0x48 flag must be set.
            return query == pattern and self.flag != 0
        if len(query) < len(pattern):
            return False
        if not query.startswith(pattern):
            return False
        if len(query) < self.offset50 + len(pattern):
            return False
        # Every +0x58 element must match in sequence; element 0
        # is governed by the initial mode 2, and the mode
        # governing element i+1 is stored in element i's +0x20.
        pos = len(pattern)
        mode = 2
        for element, elem_mode in self.elements:
            pos = self._elem_match(pos, query, mode, element)
            if pos < 0:
                return False
            mode = elem_mode
        # The tail is decided by the last element's mode.
        tail = query[pos:]
        if mode == 2:
            return pos == len(query)
        if mode in (3, 4):
            body = tail[1:] if tail.startswith("-") else tail
            if not body:
                return False
            if mode == 3:
                return body.isdigit()
            # Mode 4: dotted digits, at most one '.', at least
            # one digit.
            if body.count(".") > 1:
                return False
            return (body.replace(".", "").isdigit()
                    and any(c.isdigit() for c in body))
        return True


# --- FactoryEntry ------------------------------------------------------

class FactoryEntry:
    """0x30-byte record: +0x00 vtable, +0x08 PatternEntry*,
    +0x10..+0x20 std::function functor storage (16 zero bytes),
    +0x20 manager, +0x28 invoker."""

    def __init__(self, kind, pattern_entry, creator):
        self.kind = kind  # 'EncryptionProvider' or 'BlockCipher'
        self.pattern_entry = pattern_entry
        self.creator = creator  # key into CREATORS
        self.vtable = (FACTORY_VTABLE_ENC if kind == "EncryptionProvider"
                       else FACTORY_VTABLE_CIPHER)
        self.functor = bytes(16)
        self.manager = CREATORS[creator]["manager"]
        self.invoker = CREATORS[creator]["invoke"]

    def matches(self, query):
        return self.pattern_entry.matches(query)

    def create(self, name, registry):
        """Dispatch to the creator lambda's _M_invoke."""
        if self.creator == "E0":
            return invoke_e0(name, registry)
        if self.creator == "E_":
            return invoke_e_(name, registry)
        return invoke_cipher(name)


def manager_op(manager_addr, op):
    """The std::function managers 0x5fefa50 / 0x5fefa80 / 0x5fefab0:
    op 0 returns the typeinfo address, op 1 clones the functor,
    op 2 and op 3 are no-ops here (op 2 returns false, op 3
    destroys nothing for these stateless lambdas)."""
    if op == 0:
        for info in CREATORS.values():
            if info["manager"] == manager_addr:
                return info["typeinfo"]
        raise KeyError(manager_addr)
    if op == 1:
        return "clone"
    if op in (2, 3):
        return False
    raise ValueError(op)


# --- creator lambdas ----------------------------------------------------

def invoke_e0(name, registry):
    """_M_invoke 0x5ff6a00: build a CTREncryptionProvider via C1
    0x5ff6880 from a BlockCipher looked up in the registry, then
    register options via Configurable::RegisterOptions 0x6099ce0."""
    cipher = registry.lookup_block_cipher(name)
    return {
        "provider": "CTREncryptionProvider",
        "ctor": CTR_PROVIDER_CTOR,
        "cipher": cipher,
        "options_registered": True,
        "register_options": REGISTER_OPTIONS,
    }


def invoke_e_(name, registry):
    """_M_invoke 0x5ff6d60: if EndsWith(name, "://test") resolve
    ROT13BlockCipherOptions and build the provider via C1;
    otherwise build the provider directly (fallback at 0x5ff6f70)."""
    resolved_rot13 = ends_with(name, "://test")
    result = {
        "provider": "CTREncryptionProvider",
        "ctor": CTR_PROVIDER_CTOR,
        "resolved_rot13_options": resolved_rot13,
    }
    if resolved_rot13:
        result["options_name"] = ROT13_OPTIONS
    return result


def invoke_cipher(name):
    """_M_invoke 0x5ff7120: find ':' in the name, build
    ROT13BlockCipherOptions, create the ROT13 cipher.  A bad
    substring throws out_of_range (basic_string::substr)."""
    pos = name.find(":")
    if pos < 0:
        raise ValueError("basic_string::substr: __pos > this->size()")
    return {
        "cipher": "ROT13BlockCipher",
        "options_name": ROT13_OPTIONS,
        "colon_pos": pos,
    }


# --- ObjectLibrary / ObjectRegistry -------------------------------------

class ObjectLibrary:
    """The 'encryption' library block: 0x10-byte control-block
    header + 0x80-byte object; control-block vtable 0x64d00f0,
    counts 0x100000001, version float 1.0, SSO name string."""

    def __init__(self, name=LIBRARY_NAME):
        self.name = name
        self.version = LIBRARY_VERSION
        self.counts = LIBRARY_COUNTS
        self.control_block_vtable = LIBRARY_VTABLE
        self.typeinfo = LIBRARY_TYPEINFO


class ObjectRegistry:
    """The registry the host fills: libraries vector (registry+0x00)
    under the registry mutex (registry+0x98), and the map
    name -> vector<FactoryEntry*> (registry+0x28 via find-or-insert
    0x5fd1da0).  The host runs once, on first use, through the
    pthread_once call sites."""

    def __init__(self):
        self.libraries = GrowableVector()
        self.entries = {}  # name -> GrowableVector[FactoryEntry]
        self.mutex_locked = False
        self.registered = False

    def register_library(self, name=LIBRARY_NAME):
        library = ObjectLibrary(name)
        self.mutex_locked = True
        try:
            self.libraries.append(library)
        finally:
            self.mutex_locked = False
        return library

    def register_entry(self, name, entry):
        """The helper 0x5ff8260: lock, find-or-insert the name,
        append ONE qword (the record pointer) to that name's
        vector, unlock."""
        self.mutex_locked = True
        try:
            vec = self.entries.get(name)
            if vec is None:
                vec = GrowableVector()
                self.entries[name] = vec
            vec.append(entry)
        finally:
            self.mutex_locked = False
        return entry

    def find_factory(self, name):
        """Return the entry vector for a map key (empty when absent)."""
        vec = self.entries.get(name)
        return list(vec) if vec is not None else []

    def lookup_block_cipher(self, name):
        """The virtual call inside invoke_e0: resolve the cipher
        named by the query through the registered BlockCipher
        entries; returns the first matching entry's cipher."""
        for entry in self.find_factory("BlockCipher"):
            if entry.matches(name):
                return entry.create(name, self)
        return None

    def create(self, name, query):
        """Create through the first entry under `name` whose
        pattern matches `query`."""
        for entry in self.find_factory(name):
            if entry.matches(query):
                return entry.create(query, self)
        return None


def register_encryption_builtins(registry=None):
    """The host 0x5ff88c0 end-to-end: the 'encryption' library plus
    its three factory entries, in registration order."""
    registry = registry if registry is not None else ObjectRegistry()
    registry.register_library()
    registry.register_entry(
        "EncryptionProvider",
        FactoryEntry("EncryptionProvider",
                     PatternEntry("CTR", [("://test", 2)]), "E_"))
    registry.register_entry(
        "EncryptionProvider",
        FactoryEntry("EncryptionProvider",
                     PatternEntry("1://test", []), "E0"))
    registry.register_entry(
        "BlockCipher",
        FactoryEntry("BlockCipher",
                     PatternEntry("ROT13", [(":", 3)]), "Cipher"))
    registry.registered = True
    return registry
