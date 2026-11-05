"""Model of node #115's record-vector push-back (RE-001).

Pins the behaviour of the 0x6099ce0 helper with its growth path
0x6099790 (`std::vector<Record>::_M_realloc_insert`), as
established in research/work-items/RE-001-record-pushback-115/.

A Record is 48 (0x30) bytes: a std::string key (0x20 bytes),
a u64 field `a` at +0x20 and a u64 field `b` at +0x28. The
owning object holds the vector triple at +0x08: begin, end,
end-of-storage. `push_back` appends exactly one record at the
end: on spare capacity it constructs the record in place and
advances the end; when end == capacity it reallocates through
the growth path and inserts the record at the (new) end.

Growth rule (from growth.txt): new capacity is 1 element when
the vector is empty, else min(2 * size, MAX_SIZE); the new
buffer holds new_capacity * 48 bytes. When size == MAX_SIZE
the growth path throws length_error "vector::_M_realloc_insert".
Relocation moves each existing record by string-move: a
heap-backed key is stolen (source left an empty SSO string),
an SSO key is copied byte for byte; the two u64 fields move
with the record; element order is preserved and the old buffer
is freed.

The key is modelled as a plain Python str; the observable
SSO/heap split (<= 15 chars inline, >= 16 chars heap) is
pinned by the copy rules in `string_storage`.
"""

MAX_SIZE = 192153584101141162  # (2**63 - 1) // 48 == 0x2aaaaaaaaaaaaaa
ELEMENT_SIZE = 48
SSO_LIMIT = 15


class LengthError(Exception):
    """Models std::length_error from vector::_M_realloc_insert."""


def string_storage(key):
    """('sso', key) for keys of at most 15 chars, else ('heap', key).

    Matches the copy branches in pushback.txt / growth.txt:
    size > 15 takes the _M_create heap path, size == 1 copies one
    char inline, size == 0 stores only the NUL, sizes 2..15 use
    memcpy into the inline buffer.
    """
    if not isinstance(key, str):
        raise TypeError("key must be str")
    if len(key.encode()) != len(key):
        raise ValueError("key must be ASCII for this model")
    return ("sso", key) if len(key) <= SSO_LIMIT else ("heap", key)


def new_capacity(size):
    """Capacity of the fresh buffer for a growth from `size`.

    Empty vector -> 1 element. Otherwise min(2 * size, MAX_SIZE).
    Raises LengthError when size == MAX_SIZE (the growth path's
    _M_check_len-equivalent: max_size() - size() < 1).
    """
    if size == MAX_SIZE:
        raise LengthError("vector::_M_realloc_insert")
    if size == 0:
        return 1
    doubled = 2 * size
    return doubled if doubled <= MAX_SIZE else MAX_SIZE


class Record:
    """One 48-byte record: (key, a, b)."""

    __slots__ = ("key", "a", "b", "storage")

    def __init__(self, key, a, b):
        storage, _ = string_storage(key)
        self.key = key
        self.a = a
        self.b = b
        self.storage = storage

    def as_tuple(self):
        return (self.key, self.a, self.b)

    def __eq__(self, other):
        return (isinstance(other, Record)
                and self.as_tuple() == other.as_tuple())

    def __repr__(self):
        return "Record(%r, %#x, %#x)" % (self.key, self.a, self.b)


class RecordVector:
    """The vector triple at owner+0x08 over Record elements.

    `capacity` is tracked explicitly because the growth rule
    (doubling, capped at MAX_SIZE) is observable: it decides
    whether a push_back takes the fast path or the growth path.
    """

    def __init__(self):
        self.items = []
        self.capacity = 0

    def __len__(self):
        return len(self.items)

    def _realloc_insert(self, value):
        """Growth path: fresh buffer, move every existing record
        (string-move semantics: the record values are preserved
        in order), construct the new record at the end, free the
        old buffer, publish the new triple."""
        size = len(self.items)
        new_cap = new_capacity(size)
        moved = [Record(r.key, r.a, r.b) for r in self.items]
        moved.append(Record(value.key, value.a, value.b))
        self.items = moved
        self.capacity = new_cap
        return new_cap

    def push_back(self, key, a, b):
        """Append exactly one record. Returns 'fast' when spare
        capacity covered it, 'growth' when the realloc-insert
        path ran."""
        value = Record(key, a, b)
        if len(self.items) < self.capacity:
            self.items.append(value)
            return "fast"
        self._realloc_insert(value)
        return "growth"


def key_from_chunks(chunk16, chunk8, store_offset, size):
    """Rebuild a key assembled from two overlapping constant
    stores, as 0x6064440 does for "SkipListFactoryOptions":
    a 16-byte chunk from a literal followed by an 8-byte chunk
    stored `store_offset` bytes into the buffer, overwriting the
    tail of the first chunk. `size` is the final length."""
    buf = bytearray(chunk16 + b"\x00" * 16)
    buf[store_offset:store_offset + len(chunk8)] = chunk8
    return bytes(buf[:size]).decode()


def table_init_record(owner):
    """The record table_init 0x60db710 appends: key
    "BlockTableOptions" (17 chars, heap), a = owner + 0x20,
    b = the .bss tag at 0x6507540."""
    return Record("BlockTableOptions", owner + 0x20, 0x6507540)


def factory_options_record(owner):
    """The record 0x6064440 appends: key "SkipListFactoryOptions"
    (22 chars, heap), a = owner + 0x20, b = the .bss tag at
    0x6505c40."""
    return Record("SkipListFactoryOptions", owner + 0x20, 0x6505C40)


def empty_key_record(owner):
    """The record 0x5fd0090 appends: empty key, a = owner + 0x20,
    b = the .bss tag at 0x6504b80."""
    return Record("", owner + 0x20, 0x6504B80)
