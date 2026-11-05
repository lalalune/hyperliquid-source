"""Model of node #115's six timestamp-guarded WriteBatch operations.

Reconstruction of the pipeline pinned by
research/work-items/RE-001-writebatch-ops-115/ (RE-001):

  wrapper (timestamp guard 0x5d58810, PR #3202)
    -> implementation (builds a rocksdb::WriteBatch on the stack)
    -> middle callee (a WriteBatch vtable function: resolves the
       column family, validates, appends one record)
    -> virtual slot 0xe0 on the rsi-object (the DB write dispatch)
    -> batch destructor

The six operations are Put, PutEntity, Delete, SingleDelete,
DeleteRange and Merge. Each appends exactly one record to the
batch rep_ string. A record is:

  [type byte][varint32 column-family id, only when cf_id != 0]
  [varint32 key length][key bytes + ts_size NUL bytes]
  [varint32 value length][value bytes]   (Put, Merge, PutEntity only)

The key bytes carry a timestamp suffix: when the column
family's timestamp size is nonzero, the middle builds a
zero-filled string of that size and the inner appender
writes the key as key bytes followed by ts_size NUL bytes.
When the timestamp size is 0, the middle calls the tail
callee instead, which writes the same record type with the
plain key. PutEntity never takes a timestamp: its middle
returns InvalidArgument when the timestamp size is nonzero,
and its inner is the plain-key path.

Record types (rocksdb ValueType), default-CF / with-CF:
  Put          0x01 / 0x05    Delete       0x00 / 0x04
  SingleDelete 0x07 / 0x08    Merge        0x02 / 0x06
  DeleteRange  0x0f / 0x0e    PutEntity    0x16 / 0x17

A fresh batch rep_ is 12 NUL bytes: an 8-byte sequence number
(0) followed by a 4-byte record count (0). Each appended record
bumps the count by one and sets one flag bit in the batch's
+0x24 word: Put 0x2, Delete 0x4, SingleDelete 0x8, Merge 0x10,
DeleteRange 0x200, PutEntity 0x1000.

Status is the 16-byte layout pinned by PR #3202: code at +0x00
(u16), subcode at +0x02 (u32), message pointer at +0x08.
Codes used here: 0 OK, 3 NotSupported, 4 InvalidArgument.

Error paths pinned from the binary:
  * guard non-OK: the wrapper copies the guard Status into out
    (message deep-copied with the strdup helper 0x61cf610) and
    returns without calling the implementation.
  * Merge, merge operator missing: the wrapper returns
    NotSupported "Provide a merge_operator when opening DB".
  * middle, CF resolution code != 0: the resolution Status is
    propagated into out.
  * PutEntity, no column-family handle (rdx == 0):
    InvalidArgument "Cannot call this method without a column
    family handle".
  * PutEntity, CF timestamp size != 0:
    InvalidArgument "Cannot call this method on column family
    enabling timestamp".
  * CF resolution, default-CF timestamp size mismatch:
    InvalidArgument "Default cf timestamp size mismatch".
  * PutEntity, key too large / entity too large:
    InvalidArgument "key is too large" /
    "wide column entity is too large". Both thresholds are
    pinned at 0xFFFFFFFF: the inner compares the key Slice
    length (parts array +0x08) against 0xffffffff, and the
    entity size computed by 0x5fb4f60 against 0xffffffff.

Unknowns (recorded, not modelled): what the virtual slot 0xe0
dispatch does with the batch (the model records the dispatch
call: the DB object, the batch rep_ and the operation); the
full internals of the five tail callees (0x5fbed30, 0x5fbfc20,
0x5fc0910, 0x5fc1600, 0x5fc24f0) — their record-type bytes are
pinned (same as the inners) but their length-encoding, count
bump and hash epilogue are not resolved, so the model treats
the tail path as the same record shape with the plain key;
the exact entity-size computation behind 0x5fb4f60 (the model
uses key length + value length as its documented
approximation); the exact object identities behind the
wrapper/impl argument slots (arg0 = out Status*, arg1 = the
rsi-object, arg2 = the rdx-object, arg3/arg4/arg5 = op
arguments); the batch's post-append hash-combine epilogue.
"""

# Operation table: name -> (vtable slot, type byte default CF,
# type byte with CF, flag bit in batch +0x24, inner appender).
# Slots are counted from the vtable pointer 0x64cd498 (slot 0
# = the destructor); they are the RELATIVE relocation offsets
# (reloc vaddr - 0x64cd498) / 8, verified by census.py.
OPS = {
    "put": (2, 0x01, 0x05, 0x0002, 0x5FBF0B0),
    "putentity": (7, 0x16, 0x17, 0x1000, 0x5FC46C0),
    "delete": (13, 0x00, 0x04, 0x0004, 0x5FBFF40),
    "singledelete": (18, 0x07, 0x08, 0x0008, 0x5FC0C30),
    "deleterange": (23, 0x0F, 0x0E, 0x0200, 0x5FC1980),
    "merge": (8, 0x02, 0x06, 0x0010, 0x5FC3B00),
}

# WriteBatch vtable (rocksdb::WriteBatch), from the RELATIVE
# relocations at 0x64cd498..: slot -> function address.
VTABLE = {
    2: 0x5FBF5D0, 7: 0x5FC4DB0, 8: 0x5FC4020, 13: 0x5FC0320,
    18: 0x5FC1010, 23: 0x5FC1E60,
}
VTABLE_ADDR = 0x64CD498
TYPEINFO_NAME = "rocksdb::WriteBatch"

OK = 0
NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4

MERGE_OPERATOR_MSG = "Provide a merge_operator when opening DB"
NO_CF_HANDLE_MSG = "Cannot call this method without a column family handle"
CF_TIMESTAMP_MSG = "Cannot call this method on column family enabling timestamp"
TS_MISMATCH_MSG = "Default cf timestamp size mismatch"
KEY_TOO_LARGE_MSG = "key is too large"
ENTITY_TOO_LARGE_MSG = "wide column entity is too large"

# The guard message, pinned by PR #3202.
GUARD_MSG_PREFIX = "cannot call this method on column family "


class Status:
    """A 16-byte rocksdb Status: code +0x00, subcode +0x02,
    message pointer +0x08."""

    def __init__(self, code=OK, subcode=0, message=None):
        self.code = code
        self.subcode = subcode
        self.message = message

    @property
    def ok(self):
        return self.code == OK

    def to_bytes(self, msg_ptr=0):
        """The 16-byte layout: code u16 at +0x00, subcode u32 at
        +0x02, two zero bytes at +0x06..+0x07, message pointer
        at +0x08. msg_ptr is caller-supplied: the model does not
        invent heap addresses."""
        import struct
        return struct.pack("<H", self.code) + struct.pack("<I", self.subcode) \
            + b"\x00\x00" + struct.pack("<Q", msg_ptr)

    def __repr__(self):
        return "Status(code=%d, subcode=%d, message=%r)" % (
            self.code, self.subcode, self.message)


def put_varint32(value):
    """RocksDB PutVarint32: little-endian base-128."""
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


class WriteBatch:
    """A rocksdb::WriteBatch as the binary builds it: rep_ starts
    as 12 NUL bytes (sequence 0, count 0); +0x24 is the flag word."""

    def __init__(self):
        self.rep = bytearray(12)
        self.flags = 0

    @property
    def sequence(self):
        import struct
        return struct.unpack_from("<Q", self.rep, 0)[0]

    @property
    def count(self):
        import struct
        return struct.unpack_from("<I", self.rep, 8)[0]

    def _bump_count(self):
        import struct
        struct.pack_into("<I", self.rep, 8, self.count + 1)

    def append_record(self, op, cf_id, key, value=None, ts_size=0):
        """Append one record for op. value is required for put,
        merge and putentity; ignored for delete, singledelete
        and deleterange (which take a second key instead).
        ts_size is the column family's timestamp size: nonzero
        means the inner appender wrote the key with a
        zero-filled timestamp suffix of that length; zero means
        the tail callee wrote the record with the plain key.
        Returns (record bytes, path) where path is "inner" or
        "tail"."""
        _slot, type_default, type_cf, flag, _inner = OPS[op]
        if op == "putentity" or ts_size > 0:
            path = "inner"
        else:
            path = "tail"
        record_key = key + b"\x00" * ts_size
        record = bytearray()
        record.append(type_cf if cf_id != 0 else type_default)
        if cf_id != 0:
            record += put_varint32(cf_id)
        record += put_varint32(len(record_key))
        record += record_key
        if value is not None:
            record += put_varint32(len(value))
            record += value
        self.rep += record
        self._bump_count()
        self.flags |= flag
        return bytes(record), path


def check_putentity_sizes(key_len, entity_len):
    """The PutEntity inner's size checks, pinned from the
    binary: key length > 0xFFFFFFFF -> "key is too large";
    entity size > 0xFFFFFFFF -> "wide column entity is too
    large". The binary computes the entity size via 0x5fb4f60
    (not resolved here); the caller supplies it, modelled as
    key length + value length. Returns a Status, or None when
    both sizes are within bounds."""
    if key_len > 0xFFFFFFFF:
        return Status(INVALID_ARGUMENT, message=KEY_TOO_LARGE_MSG)
    if entity_len > 0xFFFFFFFF:
        return Status(INVALID_ARGUMENT, message=ENTITY_TOO_LARGE_MSG)
    return None


class CfResolve:
    """The column-family resolution record 0x5fbbc90 fills:
    timestamp size at +0x00, CF id (dword) at +0x08, Status
    code at +0x10, subcode bytes at +0x11..+0x15, message at
    +0x18."""

    def __init__(self, ts_size=0, cf_id=0, code=OK, message=None):
        self.ts_size = ts_size
        self.cf_id = cf_id
        self.code = code
        self.message = message

    @property
    def ok(self):
        return self.code == OK


def run_operation(op, guard_status, resolve, key, value=None,
                  merge_operator_present=True, dispatch=None):
    """Run one wrapper->impl->middle->dispatch pipeline.

    guard_status: the Status the timestamp guard returned.
    resolve: the CfResolve record for the column family; its
      ts_size decides the append path (0 -> tail callee,
      nonzero -> inner appender with a zero timestamp suffix;
      PutEntity errors instead when nonzero).
    dispatch: optional callable(db_object, batch, op) standing in
      for the virtual slot 0xe0 call; it must return a Status.
    Returns (Status, WriteBatch or None, dispatch record or None,
    path or None) where path is "inner" or "tail".
    """
    out = Status()
    if not guard_status.ok:
        # Wrapper: copy the guard Status (message deep-copied).
        out.code = guard_status.code
        out.subcode = guard_status.subcode
        out.message = guard_status.message
        return out, None, None, None
    if op == "merge" and not merge_operator_present:
        # Merge wrapper's second gate (slot 0x30 + +0x5c8 null).
        out.code = NOT_SUPPORTED
        out.message = MERGE_OPERATOR_MSG
        return out, None, None, None
    if op == "putentity" and resolve is None:
        out.code = INVALID_ARGUMENT
        out.message = NO_CF_HANDLE_MSG
        return out, None, None, None
    if not resolve.ok:
        out.code = resolve.code
        out.message = resolve.message
        return out, None, None, None
    if op == "putentity" and resolve.ts_size != 0:
        out.code = INVALID_ARGUMENT
        out.message = CF_TIMESTAMP_MSG
        return out, None, None, None
    batch = WriteBatch()
    if op == "putentity":
        size_error = check_putentity_sizes(
            len(key), len(key) + (len(value) if value is not None else 0))
        if size_error is not None:
            return size_error, batch, None, None
    _record, path = batch.append_record(
        op, resolve.cf_id, key, value, ts_size=resolve.ts_size)
    record = None
    if dispatch is not None:
        record = dispatch("db-object", batch, op)
    return out, batch, record, path
