"""Model of the node #115 RocksDB data-block builder.

Transcribed from the target bodies (see the packet
RE-001-block-builder-115 for the verbatim excerpts):

  * 0x6129a00  BlockBuilder::BlockBuilder(int, bool, bool,
               BlockBasedTableOptions::DataBlockIndexType, double)
  * 0x6129b10  BlockBuilder::EstimateSizeAfterKV(Slice, Slice)
  * 0x6129c10  BlockBuilder::Finish()
  * 0x6129f60  BlockBuilder::Reset()
  * 0x612a1b0  BlockBuilder::Add(Slice, Slice, const Slice*)
  * 0x612ca80  DataBlockHashIndexBuilder::Add(Slice, size_t)
  * 0x612cc80  DataBlockHashIndexBuilder::Finish(std::string*)
  * 0x612ce10  DataBlockHashIndexBuilder::Reset() (local helper)
  * 0x612ce90  block trailer word helper (local)
  * 0x61c34a0  rocksdb::Hash(const char*, size_t, uint32_t)

Object layout of BlockBuilder (offsets from `this`):

  +0x00 int32     restart_interval_
  +0x04 uint8     use_delta_encoding_
  +0x05 uint8     use_value_delta_encoding_
  +0x08 string    buffer_
  +0x28 vector    restarts_ (uint32 elements)
  +0x40 uint64    running finished-size estimate; the bodies keep
                  it equal to buffer_.size() + 4*len(restarts_) + 4
  +0x48 int32     counter_ (entries since the last restart)
  +0x4c uint8     finished_
  +0x50 string    last_key_
  +0x70           DataBlockHashIndexBuilder annex:
    +0x70 double  per-entry bucket increment (see below)
    +0x78 double  bucket accumulator
    +0x80 uint8   annex enabled flag
    +0x88 vector  entries, 8-byte records {uint32 hash,
                  uint8 restart_index, 3 uninitialised pad bytes}

Entry encoding written by Add into buffer_:

  varint32(shared) varint32(non_shared) [varint32(value_size)]
  key[shared:] value_bytes

The third varint is present only when use_value_delta_encoding_
is off.  value_bytes is the full value, except when the value
delta form is on and shared > 0, in which case the caller-supplied
value_delta slice is appended verbatim instead (the body reads its
data pointer and size with no null check).

The annex increment is fixed at construction: -1.0 when the index
type argument is not 1 (kDataBlockBinaryAndHash); for type 1 it is
1.0 / ratio when ratio > 0, 4/3 when ratio <= 0, and NaN when the
ratio is NaN (the compare in the body is ordered).  The annex only
acts while its enabled flag is set and the increment is > 0.

Annex Add strips the last 8 bytes off the key (the internal-key
tag), hashes the rest with rocksdb::Hash at seed 0x18d (397), and
records (hash, restart_index).  A restart_index above 0xfd (253)
clears the enabled flag instead and records nothing; the flag is
also the gate for the annex call in Reset, so once cleared the
annex stays inert for the life of the builder.

Finish appends each restart as a raw little-endian uint32, then
(when the annex is live and the projected block size
estimate + num_buckets + 2 does not exceed 0x10000) the annex
bucket array and its uint16 bucket count, and finally the trailer
word: num_restarts, with the top bit set iff the bucket array was
appended.  num_buckets is (uint16)((int32)accumulator | 1) where
the (int32) conversion is the x86 cvttsd2si (truncation, with the
indefinite value 0x80000000 for NaN / out of range).  Bucket b of
the array starts as 0xff (empty); each recorded entry maps to
bucket hash % num_buckets: an empty bucket takes the entry's
restart index byte, a bucket already holding the same byte is
left, and any other occupied bucket degrades to 0xfe.

EstimateSizeAfterKV is an estimator, not an exact size: it starts
from the running estimate field, adds the full key size, the hash
allowance ((uint16)((int32)accumulator | 1)) + 2 when the annex is
live, and a header allowance that depends on the mode:
counter_ < restart_interval_ and counter_ >= restart_interval_
("restart imminent") use fixed allowances of 4 and 8 plus the
varint32 lengths of the key and value sizes; with value delta
encoding and no imminent restart the value counts at half size
(value_size >> 1) and its varint length is not added (this last
branch is taken when the stored flag byte is exactly 1; the other
branches key on the byte being nonzero).

Every append the bodies make to buffer_ (and the annex bucket
appends to the same string in Finish) is guarded by the
std::string maximum size 0x3fffffffffffffff: if the remaining
capacity is smaller than the piece about to be appended, the body
throws std::length_error("basic_string::append") before appending
that piece.  The model raises LengthError in the same places.
"""

import math

MASK32 = (1 << 32) - 1
STRING_MAX = 0x3FFFFFFFFFFFFFFF
HASH_MULT = 0xC6A4A793
HASH_SEED = 0x18D


class LengthError(Exception):
    """std::length_error as thrown by the target bodies."""

    def __init__(self, message="basic_string::append"):
        super().__init__(message)
        self.message = message


def encode_varint32(value):
    """The EncodeVarint32 body at 0x61bd410: canonical unsigned
    LEB128 of the low 32 bits, 1 to 5 bytes; returns the bytes."""
    value &= MASK32
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0xFF) | 0x80)
        value >>= 7
    out.append(value & 0xFF)
    return bytes(out)


def varint32_len(value):
    """Number of bytes encode_varint32 emits (the loop the
    EstimateSizeAfterKV body uses)."""
    value &= MASK32
    count = 1
    while value > 0x7F:
        value >>= 7
        count += 1
    return count


def _sign8(byte):
    return byte - 256 if byte >= 128 else byte


def hash32(data, seed):
    """rocksdb::Hash at 0x61c34a0 (seed in edx, length in rsi).

    h = seed ^ (len32 * 0xc6a4a793); per 4-byte group
    h = (h + le32) * 0xc6a4a793, h ^= h >> 16.  The tail bytes
    are added SIGN-extended (movsx): a 3-byte tail adds
    s8(b2) << 16 and s8(b1) << 8 first; any nonzero tail then
    adds s8(b0) and finishes with h *= 0xc6a4a793, h ^= h >> 24.
    A zero tail (length a multiple of 4, including 0) skips the
    final multiply/xor entirely.
    """
    n = len(data)
    h = (seed ^ ((n & MASK32) * HASH_MULT)) & MASK32
    pos = 0
    while n - pos >= 4:
        word = int.from_bytes(data[pos:pos + 4], "little")
        h = (h + word) & MASK32
        h = (h * HASH_MULT) & MASK32
        h ^= h >> 16
        pos += 4
    rem = n - pos
    if rem == 3:
        h = (h + (_sign8(data[pos + 2]) << 16)) & MASK32
    if rem >= 2:
        h = (h + (_sign8(data[pos + 1]) << 8)) & MASK32
    if rem >= 1:
        h = (h + _sign8(data[pos])) & MASK32
        h = (h * HASH_MULT) & MASK32
        h ^= h >> 24
    return h


def _cvttsd2si32(value):
    """x86 cvttsd2si to a 32-bit register: truncation toward
    zero; NaN or out-of-range yields 0x80000000."""
    if math.isnan(value) or value >= 2147483648.0 or value < -2147483648.0:
        return -2147483648
    return int(value)


def num_buckets(accumulator):
    """(uint16)((int32)accumulator | 1), as computed identically
    by the Finish gate, the annex Finish and Estimate."""
    return ((_cvttsd2si32(accumulator) | 1) & 0xFFFF)


def trailer_word(num_restarts, flag):
    """The helper at 0x612ce90: num_restarts, with the top bit
    set iff flag == 1 exactly."""
    word = num_restarts & MASK32
    if flag == 1:
        word |= 0x80000000
    return word


class _GuardedBuffer:
    """A byte string with the bodies' append guard."""

    def __init__(self):
        self.data = bytearray()

    def append(self, piece):
        if STRING_MAX - len(self.data) < len(piece):
            raise LengthError()
        self.data += piece

    def __len__(self):
        return len(self.data)


class HashIndexAnnex:
    """DataBlockHashIndexBuilder (BlockBuilder +0x70)."""

    def __init__(self, increment, enabled):
        self.increment = increment
        self.accumulator = 0.0
        self.enabled = enabled
        self.entries = []  # list of (hash32, restart_index byte)

    def live(self):
        return self.enabled != 0 and self.increment > 0

    def add(self, user_key, restart_index):
        """0x612ca80.  restart_index is restarts_.size() - 1."""
        if restart_index > 0xFD:
            self.enabled = 0
            return
        digest = hash32(user_key, HASH_SEED)
        self.entries.append((digest, restart_index & 0xFF))
        self.accumulator += self.increment

    def finish(self, buffer):
        """0x612cc80: append the bucket array and its uint16
        count to the buffer (each append guarded)."""
        count = num_buckets(self.accumulator)
        buckets = bytearray([0xFF] * count)
        for digest, restart_byte in self.entries:
            slot = digest % count
            current = buckets[slot]
            if current == 0xFF:
                buckets[slot] = restart_byte
            elif current != restart_byte:
                buckets[slot] = 0xFE
        for byte in buckets:
            buffer.append(bytes([byte]))
        buffer.append(count.to_bytes(2, "little"))

    def reset(self):
        """0x612ce10: accumulator zeroed, flag set, entries
        cleared (capacity kept)."""
        self.accumulator = 0.0
        self.enabled = 1
        self.entries = []


class BlockBuilder:
    """The BlockBuilder bodies at 0x6129a00..0x612a4f2."""

    def __init__(self, restart_interval, use_delta, use_value_delta,
                 index_type, ratio):
        self.restart_interval = restart_interval
        self.use_delta = use_delta & 0xFF
        self.use_value_delta = use_value_delta & 0xFF
        self.buffer = _GuardedBuffer()
        self.restarts = [0]
        self.estimate = 8
        self.counter = 0
        self.finished = 0
        self.last_key = bytearray()
        if index_type == 1:
            if ratio > 0:
                increment = 1.0 / ratio
            elif ratio <= 0:
                increment = 4.0 / 3.0
            else:  # NaN: the ordered compare falls through to the divide
                increment = 1.0 / ratio
            self.annex = HashIndexAnnex(increment, 1)
        else:
            self.annex = HashIndexAnnex(-1.0, 0)

    # -- Add (0x612a1b0) -------------------------------------------

    def add(self, key, value, value_delta=None):
        size_at_entry = len(self.buffer)
        if self.counter >= self.restart_interval:
            self.restarts.append(size_at_entry & MASK32)
            self.estimate += 4
            self.counter = 0
            shared = 0
        elif self.use_delta:
            limit = min(len(self.last_key), len(key))
            shared = 0
            while shared < limit and self.last_key[shared] == key[shared]:
                shared += 1
        else:
            shared = 0
        non_shared = len(key) - shared
        if self.use_value_delta:
            header = (encode_varint32(shared)
                      + encode_varint32(non_shared))
        else:
            header = (encode_varint32(shared)
                      + encode_varint32(non_shared)
                      + encode_varint32(len(value)))
        self.buffer.append(header)
        self.buffer.append(key[shared:])
        if shared > 0 and self.use_value_delta:
            if value_delta is None:
                raise ValueError("body dereferences the delta slice "
                                 "with no null check")
            self.buffer.append(value_delta)
        else:
            self.buffer.append(value)
        if self.annex.live():
            user_key = key[:len(key) - 8]
            self.annex.add(user_key, len(self.restarts) - 1)
        self.counter += 1
        self.estimate += len(self.buffer) - size_at_entry
        if self.use_delta:
            self.last_key = bytearray(key)

    # -- Finish (0x6129c10) ----------------------------------------

    def finish(self):
        for restart in self.restarts:
            self.buffer.append((restart & MASK32).to_bytes(4, "little"))
        flag = 0
        if self.annex.live():
            count = num_buckets(self.annex.accumulator)
            if self.estimate + count + 2 <= 0x10000:
                self.annex.finish(self.buffer)
                flag = 1
        word = trailer_word(len(self.restarts), flag)
        self.buffer.append(word.to_bytes(4, "little"))
        self.finished = 1
        return bytes(self.buffer.data)

    # -- Reset (0x6129f60) -----------------------------------------

    def reset(self):
        self.buffer = _GuardedBuffer()
        if not self.restarts:
            self.restarts = [0]
        elif len(self.restarts) > 1:
            self.restarts = self.restarts[:1]
        self.estimate = 8
        self.counter = 0
        self.finished = 0
        self.last_key = bytearray()
        if self.annex.live():
            self.annex.reset()

    # -- EstimateSizeAfterKV (0x6129b10) ---------------------------

    def estimate_after_kv(self, key_size, value_size):
        total = self.estimate + key_size
        if self.annex.live():
            total += num_buckets(self.annex.accumulator) + 2
        if self.use_value_delta:
            if self.counter < self.restart_interval:
                total += value_size >> 1
                total += 4 + varint32_len(key_size)
                if self.use_value_delta == 1:
                    return total
                return total + varint32_len(value_size)
            total += value_size
            total += 8 + varint32_len(key_size) + varint32_len(value_size)
            return total
        total += value_size
        if self.counter < self.restart_interval:
            total += 4 + varint32_len(key_size) + varint32_len(value_size)
        else:
            total += 8 + varint32_len(key_size) + varint32_len(value_size)
        return total
