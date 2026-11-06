"""Model of node #115's timestamp-gated SliceParts WriteBatch operations.

Reconstruction of the pipeline pinned by
research/work-items/RE-001-ts-gate-ops-115/ (RE-001):

  wrapper (timestamp-size gate 0x5e882b0)
    -> implementation (builds a rocksdb::WriteBatch on the stack)
    -> middle callee (a WriteBatch vtable function: resolves the
       column family, validates the timestamp slice, appends one
       record built from Slice parts)
    -> virtual slot 0xe0 on the rsi-object (the DB write dispatch)
    -> batch destructor

The five operations are Put, Delete, SingleDelete, DeleteRange
and Merge. They are the timestamp-enabled counterparts of the
six operations in PR #3209: where #3209's guard 0x5d58810
rejects a column family that ENABLES timestamp, this gate
0x5e882b0 rejects one that does NOT enable it (or whose size
mismatches the caller's). Each operation appends exactly one
record to the batch rep_ string, built from Slice parts:

  Put / Merge:    key parts [key1, timestamp], value parts [value]
  Delete / SingleDelete: key parts [key1, timestamp]
  DeleteRange:    key parts [key1, timestamp],
                  end-key parts [end1, timestamp]

The timestamp slice's length must equal the column family's
timestamp size (checked twice: by the gate against the
caller's slice, and by the middle's resolver 0x5fb6910).
A record is:

  [type byte][varint32 column-family id, only when cf_id != 0]
  [varint32 key length][key-part bytes]
  [varint32 value length][value bytes]   (Put, Merge only;
   DeleteRange carries an end key instead of a value)

Record types (rocksdb ValueType), default-CF / with-CF:
  Put          0x01 / 0x05    Delete       0x00 / 0x04
  SingleDelete 0x07 / 0x08    Merge        0x02 / 0x06
  DeleteRange  0x0f / 0x0e

A fresh batch rep_ is 12 NUL bytes: an 8-byte sequence number
(0) followed by a 4-byte record count (0). The implementations
pass the resolved timestamp size into the constructor, stored
at batch+0x38; the middles set batch+0x22 = 1. (Contrast
PR #3209: its implementations passed ts_size 0 and its
middles set batch+0x21/+0x22 = 0x0101.)

Status is the 16-byte layout pinned by PR #3202: code at +0x00
(u16), subcode at +0x02 (u32), message pointer at +0x08.
Codes used here: 0 OK, 4 InvalidArgument.

Error paths pinned from the binary:
  * gate, factory null:
    InvalidArgument "column family handle cannot be null".
  * gate, resolved timestamp size 0:
    InvalidArgument "cannot call this method on column family
    <name> that does not enable timestamp".
  * gate, size mismatch:
    InvalidArgument "Timestamp sizes mismatch: expect <cf size>,
    <caller size> given".
  * gate, flag != 0 and the low-watermark string is non-empty
    and the resolved object's slot 0xc8 is not the always-OK
    stub 0x5d48400 and that slot returns < 0:
    InvalidArgument "Read timestamp: <hex(ts)> is smaller than
    full_history_ts_low: <hex(low)>". The hex is UPPERCASE.
    No in-binary caller passes a nonzero flag (all five
    wrappers xor ecx first), so this branch is modelled from
    the gate disassembly only.
  * resolver 0x5fb6910, cf_obj null:
    InvalidArgument "column family handle cannot be null".
  * resolver, *(P+0x28) == 0: InvalidArgument "timestamp disabled".
  * resolver, size mismatch:
    InvalidArgument "timestamp size mismatch".
  * middle, resolver code != 0: the resolver Status is
    propagated into out.

Unknowns (recorded, not modelled): what the virtual slot 0xe0
dispatch does with the batch (the model records the dispatch
call: the DB object, the batch rep_ and the operation); the
full internals of the five inner appenders (their record-type
bytes are pinned, but the length-encoding, count bump and hash
epilogue are not resolved, so the model treats the inner as
appending the pinned record shape); the exact object
identities behind the wrapper/impl argument slots; which
concrete column-family names occur at runtime.
"""

OK = 0
NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4

NO_CF_HANDLE_MSG = "column family handle cannot be null"
NO_TIMESTAMP_PREFIX = "cannot call this method on column family "
NO_TIMESTAMP_SUFFIX = " that does not enable timestamp"
TS_MISMATCH_PREFIX = "Timestamp sizes mismatch: expect "
TS_DISABLED_MSG = "timestamp disabled"
TS_SIZE_MISMATCH_MSG = "timestamp size mismatch"
READ_TS_PREFIX = "Read timestamp: "
READ_TS_SUFFIX = " is smaller than full_history_ts_low: "

OPS = ("put", "delete", "singledelete", "deleterange", "merge")

# WriteBatch vtable slots (base 0x64cd498, slot 0 = destructor).
VTABLE_ADDR = 0x64CD498
TYPEINFO_NAME = "rocksdb::WriteBatch"
MIDDLE_SLOTS = {"put": 4, "delete": 15, "singledelete": 20,
                "deleterange": 25, "merge": 10}
# Record types (rocksdb ValueType): (default-CF, with-CF).
RECORD_TYPES = {"put": (0x01, 0x05), "delete": (0x00, 0x04),
                "singledelete": (0x07, 0x08),
                "deleterange": (0x0F, 0x0E), "merge": (0x02, 0x06)}
# The always-OK stub the gate compares slot 0xc8 against.
OK_STUB = 0x5D48400

# Gate / resolver / middle / implementation addresses.
GATE = 0x5E882B0
RESOLVER = 0x5FB6910
HEX_HELPER = 0x61C7E30
NIBBLE = 0x61C7DA0
STATUS_BUILDER = 0x61CF670
DEFAULT_GETTER = 0x5D48510
WRAPPERS = {"put": 0x5E94800, "delete": 0x5E95040,
            "singledelete": 0x5E95560, "deleterange": 0x5E95AC0,
            "merge": 0x5E960A0}
IMPLS = {"put": 0x5E94690, "delete": 0x5E94EE0,
         "singledelete": 0x5E95400, "deleterange": 0x5E95950,
         "merge": 0x5E95F30}
MIDDLES = {"put": 0x5FBF7D0, "delete": 0x5FC04F0,
           "singledelete": 0x5FC11E0, "deleterange": 0x5FC2080,
           "merge": 0x5FC4220}
INNERS = {"put": 0x5FBF0B0, "delete": 0x5FBFF40,
          "singledelete": 0x5FC0C30, "deleterange": 0x5FC1980,
          "merge": 0x5FC3B00}


class Status:
    """The 16-byte Status: code u16 +0x00, subcode u32 +0x02,
    message pointer +0x08 (modelled as a str or None)."""

    def __init__(self, code=OK, subcode=0, message=None):
        self.code = code
        self.subcode = subcode
        self.message = message

    def ok(self):
        return self.code == OK

    def copy(self):
        # The wrappers deep-copy a failure message (strdup helper).
        return Status(self.code, self.subcode,
                      None if self.message is None else str(self.message))

    def __repr__(self):
        return "Status(code=%d, subcode=%d, message=%r)" % (
            self.code, self.subcode, self.message)


def invalid_argument(message):
    return Status(INVALID_ARGUMENT, 0, message)


class Slice:
    """A {ptr, len} view; the model holds the bytes directly."""

    def __init__(self, data=b""):
        self.data = bytes(data)

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return "Slice(%r)" % self.data


def nibble(value):
    """The 0x61c7da0 helper: 0-9 -> '0'+n, else 'A'+n-10."""
    if not 0 <= value <= 15:
        raise ValueError("nibble out of range: %r" % value)
    if value <= 9:
        return chr(ord("0") + value)
    return chr(ord("A") + value - 10)


def hex_or_copy(data, hex_flag):
    """The 0x61c7e30 helper: hex_flag 0 copies the bytes
    verbatim; nonzero returns UPPERCASE hex, high nibble first."""
    data = bytes(data)
    if not hex_flag:
        return data
    out = []
    for byte in data:
        out.append(nibble(byte >> 4))
        out.append(nibble(byte & 0xF))
    return "".join(out).encode("ascii")


class Resolved:
    """The object factory slot 0x28 returns: +0x28 is the
    column family's timestamp size (0 = timestamp disabled),
    and slot 0xc8 is the read-timestamp validator (the
    always-OK stub 0x5d48400, or a callable)."""

    def __init__(self, ts_size, slot_c8=OK_STUB):
        self.ts_size = ts_size
        self.slot_c8 = slot_c8


class Factory:
    """The factory object behind the gate/impl calls:
    slot 0x28 resolves the column family, slot 0x10 names it,
    slot 0x30 yields the low-watermark string, slot 0x3e8 is
    the default getter whose slot 0x28 gives the default
    timestamp size."""

    def __init__(self, resolved, name="", low=b"",
                 default_ts_size=None):
        self.resolved = resolved
        self.name = name
        self.low = bytes(low)
        self.default_ts_size = (resolved.ts_size
                                if default_ts_size is None
                                else default_ts_size)

    def describe(self):
        return self.resolved

    def cf_name(self):
        return self.name

    def low_string(self):
        return self.low


class CfObj:
    """The column-family object behind the resolver and the
    middles: slot 0x28 gives P with +0x28 the timestamp size,
    slot 0x18 returns the CF id."""

    def __init__(self, ts_size, cf_id=0):
        self.ts_size = ts_size
        self.cf_id = cf_id

    def describe(self):
        return self

    def cf_id_of(self):
        return self.cf_id


def gate(factory, ts_slice, flag):
    """The gate 0x5e882b0(out, factory, ts_slice, flag)."""
    if factory is None:
        return invalid_argument(NO_CF_HANDLE_MSG)
    resolved = factory.describe()
    ts = resolved.ts_size
    if ts == 0:
        return invalid_argument(
            NO_TIMESTAMP_PREFIX + factory.cf_name() +
            NO_TIMESTAMP_SUFFIX)
    if ts != len(ts_slice):
        return invalid_argument(
            "%s%d, %d given" % (TS_MISMATCH_PREFIX, ts, len(ts_slice)))
    if not flag:
        return Status()
    low = factory.low_string()
    if len(low) == 0:
        return Status()
    slot = resolved.slot_c8
    if slot == OK_STUB:
        return Status()
    result = slot(resolved, ts_slice, low)
    if result >= 0:
        return Status()
    return invalid_argument(
        READ_TS_PREFIX + hex_or_copy(ts_slice.data, 1).decode("ascii") +
        READ_TS_SUFFIX + hex_or_copy(low, 1).decode("ascii"))


def resolve(cf_obj, ts_slice):
    """The resolver 0x5fb6910(out, cf_obj, ts_slice)."""
    if cf_obj is None:
        return invalid_argument(NO_CF_HANDLE_MSG)
    resolved = cf_obj.describe()
    ts = resolved.ts_size
    if ts == 0:
        return invalid_argument(TS_DISABLED_MSG)
    if ts != len(ts_slice):
        return invalid_argument(TS_SIZE_MISMATCH_MSG)
    return Status()


def put_varint32(value):
    """Unsigned LEB128, as the inner appenders encode lengths."""
    if value < 0:
        raise ValueError("varint32 of negative value")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


class WriteBatch:
    """A rocksdb::WriteBatch as the implementations build it:
    rep_ starts as 12 NUL bytes, +0x38 holds the timestamp
    size, +0x22 is set to 1 by the middles, +0x24 is the
    flags word (not modelled per-op here; the record append
    is modelled in append_record)."""

    def __init__(self, ts_size=0, protector=None):
        self.rep = bytearray(b"\x00" * 12)
        self.ts_size = ts_size
        self.protector = protector
        self.flag_22 = 0
        self.destroyed = False
        self.records = []

    def sequence(self):
        return int.from_bytes(self.rep[0:8], "little")

    def count(self):
        return int.from_bytes(self.rep[8:12], "little")

    def append_record(self, op, cf_id, key_parts, value_parts=None,
                      end_parts=None):
        """The inner appender's pinned record shape (the
        length-encoding, count bump and hash epilogue are the
        inner's internals; the model records the parts)."""
        default, with_cf = RECORD_TYPES[op]
        type_byte = with_cf if cf_id != 0 else default
        record = bytearray()
        record.append(type_byte)
        if cf_id != 0:
            record += put_varint32(cf_id)
        key = b"".join(p.data for p in key_parts)
        record += put_varint32(len(key))
        record += key
        if op in ("put", "merge"):
            value = b"".join(p.data for p in value_parts)
            record += put_varint32(len(value))
            record += value
        elif op == "deleterange":
            end = b"".join(p.data for p in end_parts)
            record += put_varint32(len(end))
            record += end
        self.rep += record
        self.records.append(bytes(record))
        count = self.count() + 1
        self.rep[8:12] = count.to_bytes(4, "little")
        return bytes(record)

    def destroy(self):
        self.destroyed = True


def middle(op, batch, cf_obj, key1, ts_slice, extra=None):
    """A SliceParts middle: resolve, set batch+0x22, read the
    CF id from slot 0x18, build the Slice-parts arrays and
    append one record to the impl's batch. Returns
    (status, record|None). extra is the value slice
    (put/merge) or the end-key slice (deleterange)."""
    status = resolve(cf_obj, ts_slice)
    if not status.ok():
        return status, None
    batch.flag_22 = 1
    cf_id = cf_obj.cf_id_of()
    key_parts = [key1, ts_slice]
    if op in ("put", "merge"):
        record = batch.append_record(op, cf_id, key_parts, [extra])
    elif op == "deleterange":
        record = batch.append_record(op, cf_id, key_parts,
                                     end_parts=[extra, ts_slice])
    else:
        record = batch.append_record(op, cf_id, key_parts)
    return Status(), record


class DbStub:
    """The slot 0xe0 dispatch target: records the dispatch
    instead of performing a real DB write (the callee identity
    is not resolved from the file)."""

    def __init__(self):
        self.dispatches = []

    def write(self, out, batch, op):
        self.dispatches.append((op, bytes(batch.rep), batch.ts_size))
        return Status()


def run_operation(op, factory, cf_obj, ts_slice, key1, extra=None,
                  flag=0, db=None):
    """The full wrapper -> gate -> impl -> middle -> dispatch
    pipeline. Returns (out Status, batch|None, db)."""
    if db is None:
        db = DbStub()
    out = Status()
    gate_status = gate(factory, ts_slice, flag)
    if not gate_status.ok():
        return gate_status.copy(), None, db
    # Implementation: default timestamp size via slot 0x3e8
    # then slot 0x28 then *(result+0x28).
    ts_size = factory.default_ts_size
    batch = WriteBatch(ts_size=ts_size,
                       protector=getattr(cf_obj, "protector", None))
    status, _record = middle(op, batch, cf_obj, key1, ts_slice, extra)
    if not status.ok():
        out = status.copy()
        batch.destroy()
        return out, batch, db
    db.write(out, batch, op)
    batch.destroy()
    return Status(), batch, db
