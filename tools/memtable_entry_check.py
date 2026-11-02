"""RE-001: node #94 memtable entry check (0x5167040).

A length-prefixed memtable entry is split into a user key, an 8-byte
trailer (value-type byte + 56-bit sequence), a length-prefixed suffix,
and a stored checksum of ``width`` bytes.  The entry passes when the
stored checksum equals the low ``width`` bytes of a four-part hash
chain; otherwise the reader writes an error record.  This is the
routine the MemtableIterator refresh handlers (mapped in #1984) call
as ``reader(record, buffer, tag_width, 0)``.

Observed (from the disassembly window in the evidence packet):

* Signature: ``check(buffer, width, flag) -> Record``.  The binary
  takes ``(record_out, buffer, width, flag)``; the model returns the
  record value instead of writing through a pointer.
* ``width == 0`` returns the zero record before reading the buffer.
* Length prefix: when the first byte is below ``0x80`` it *is* the
  length and the entry starts at ``buffer[1:]``; otherwise a bounded
  varint (LEB128, at most 5 bytes, limit ``buffer + 5``) is decoded
  at ``buffer[0:]`` and the entry starts past it.  A decode failure
  writes error ``Unable to parse internal key length``.  A length of
  7 or less writes error ``Memtable entry internal key length too
  short.``.
* Entry layout: ``user_key = entry[:len-8]`` and the trailer is the
  last 8 bytes, little-endian: ``value_type = trailer[0]`` and
  ``seq = trailer[1:8]`` as a 56-bit integer.
* Suffix: the byte at ``entry_end`` is the suffix length when below
  ``0x80`` (suffix starts one byte later); otherwise a bounded
  varint (limit ``entry_end + 5``) is decoded there.  A decode
  failure writes error ``Unable to parse internal key value``.
* Stored checksum: ``width`` bytes at ``suffix_start + suffix_len``.
* Hash chain (callees by contract, seeds verbatim from the window):
  ``H(user_key, 0) ^ H(suffix, 0xd28aad72f49bd50b) ^
  H(bytes([value_type]), 0xa5155ae5e937aa16) ^
  H(seq_as_u64_le, 0x77a00858ddd37f21)`` where ``H`` is the
  libstdc++ ``std::_Hash_bytes`` (MurmurHash64A) at 0x5422f00.
* Width dispatch: widths 1, 2, 4, 8 compare the low 1, 2, 4, 8 bytes
  of the chain against the stored checksum; every other width skips
  the comparison and returns the zero record.
* Match: the zero record ``(code 0, detail "")``.  The binary writes
  code 0, sub 0 and a null detail pointer on this path and leaves
  the detail length/capacity slots untouched, so callers pass a
  zero-initialised record.
* Mismatch: error record ``(code 2, detail)`` where detail is
  ``Corrupted memtable entry, per key-value checksum verification
  failed.`` when ``flag == 0``, and that string plus
  ``Unrecognized value type: <type>. ``,
  ``User key: <hex(user_key)>. `` and ``seq: <seq>. `` when
  ``flag != 0``.  The hex piece is the 0x5427800 callee (lowercase
  hex of the user key); the detail builder is 0x542f040, whose
  auxiliary-append arm is dead for this caller (aux length 0), so
  the detail is exactly the composed string.
* The binary performs no bounds check on the entry, suffix or stored
  checksum; callers guarantee a complete buffer.  The model raises
  ``ValueError`` on truncation instead of reading past the buffer.

Inference (names only): "memtable entry", "user key", "value type"
and "seq" describe the observed field roles; the detail strings
literally name the memtable entry, the user key and the sequence.
The 0x5166fd4..0x5167040 landing pads and the LSDA are exception
cleanup only (dispose temporaries, resume unwinding) and are not
part of normal-path behaviour.
"""

MASK64 = (1 << 64) - 1

FAILED_DETAIL = (
    "Corrupted memtable entry, per key-value checksum verification failed."
)
SHORT_DETAIL = "Memtable entry internal key length too short."
NO_LENGTH_DETAIL = "Unable to parse internal key length"
NO_VALUE_DETAIL = "Unable to parse internal key value"
FRAG_TYPE = "Unrecognized value type: "
FRAG_USERKEY = "User key: "
FRAG_SEQ = "seq: "
FRAG_TAIL = ". "

SEED_SUFFIX = 0xD28AAD72F49BD50B
SEED_TYPE = 0xA5155AE5E937AA16
SEED_SEQ = 0x77A00858DDD37F21

_CHECK_WIDTHS = {1: 1, 2: 2, 4: 4, 8: 8}


class Record:
    """A reader result: code 0 is the zero record, code 2 an error."""

    def __init__(self, code, detail):
        self.code = code
        self.detail = detail

    def __eq__(self, other):
        return (
            isinstance(other, Record)
            and self.code == other.code
            and self.detail == other.detail
        )

    def __repr__(self):
        return "Record(code=%r, detail=%r)" % (self.code, self.detail)


ZERO = Record(0, "")


def hash_bytes(data, seed):
    """libstdc++ std::_Hash_bytes (MurmurHash64A).

    Provided as the default hash for the chain; its byte-exactness
    against the binary's 0x5422f00 was not executed on this VM (the
    node binary cannot be run here), so tests inject a stub hash for
    dispatch logic and use this implementation only for structural
    checks.  Seeds and the four-part XOR structure are verbatim from
    the window.
    """
    m = 0xC6A4A7935BD1E995
    r = 47
    length = len(data)
    h = (seed ^ (length * m)) & MASK64
    i = 0
    while length - i >= 8:
        k = int.from_bytes(data[i : i + 8], "little")
        k = (k * m) & MASK64
        k ^= k >> r
        k = (k * m) & MASK64
        h ^= k
        h = (h * m) & MASK64
        i += 8
    tail = data[i:]
    if tail:
        for j in range(len(tail) - 1, -1, -1):
            h ^= tail[j] << (8 * j)
        # The binary's tail switch falls through to the multiply.
        h = (h * m) & MASK64
    h ^= h >> r
    h = (h * m) & MASK64
    h ^= h >> r
    return h


def hex_encode(data):
    """The 0x5427800 callee with its flag set: lowercase hex."""
    digits = "0123456789abcdef"
    out = []
    for byte in data:
        out.append(digits[byte >> 4])
        out.append(digits[byte & 0xF])
    return "".join(out)


def decode_varint(buf, pos, limit):
    """Bounded unsigned LEB128 decode.

    Returns ``(value, next_pos)`` or ``None`` when the varint does
    not terminate before ``limit``.  Mirrors the 0x541cec0 contract:
    a first byte below 0x80 terminates immediately with its own
    value; otherwise continuation bytes are consumed up to the
    limit.
    """
    value = 0
    shift = 0
    while pos < limit:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
    return None


def check(buffer, width, flag, hash_fn=hash_bytes):
    """Check one length-prefixed memtable entry.

    ``buffer`` is the raw entry buffer, ``width`` the stored
    checksum width in bytes, ``flag`` the detail-format flag
    (nonzero selects the fully formatted mismatch detail).
    """
    if width == 0:
        return Record(0, "")
    if len(buffer) == 0:
        return Record(2, SHORT_DETAIL)
    first = buffer[0]
    if first < 0x80:
        entry_len = first
        base = 1
    else:
        decoded = decode_varint(buffer, 0, min(5, len(buffer)))
        if decoded is None:
            return Record(2, NO_LENGTH_DETAIL)
        entry_len, base = decoded
    if entry_len <= 7:
        return Record(2, SHORT_DETAIL)
    end = base + entry_len
    if end > len(buffer):
        raise ValueError("entry extends past the buffer")
    user_key = buffer[base : end - 8]
    trailer = buffer[end - 8 : end]
    value_type = trailer[0]
    seq = int.from_bytes(trailer[1:8], "little")
    if end >= len(buffer):
        raise ValueError("suffix length byte is missing")
    if buffer[end] < 0x80:
        suffix_len = buffer[end]
        suffix_start = end + 1
    else:
        decoded = decode_varint(buffer, end, min(end + 5, len(buffer)))
        if decoded is None:
            return Record(2, NO_VALUE_DETAIL)
        suffix_len, suffix_start = decoded
    suffix = buffer[suffix_start : suffix_start + suffix_len]
    stored_at = suffix_start + suffix_len
    combined = (
        hash_fn(user_key, 0)
        ^ hash_fn(suffix, SEED_SUFFIX)
        ^ hash_fn(bytes([value_type]), SEED_TYPE)
        ^ hash_fn(seq.to_bytes(8, "little"), SEED_SEQ)
    )
    nbytes = _CHECK_WIDTHS.get(width)
    if nbytes is None:
        return Record(0, "")
    if stored_at + nbytes > len(buffer):
        raise ValueError("stored checksum extends past the buffer")
    stored = int.from_bytes(buffer[stored_at : stored_at + nbytes], "little")
    if combined & ((1 << (8 * nbytes)) - 1) == stored:
        return Record(0, "")
    detail = FAILED_DETAIL
    if flag:
        detail += (
            FRAG_TYPE
            + str(value_type)
            + FRAG_TAIL
            + FRAG_USERKEY
            + hex_encode(user_key)
            + FRAG_TAIL
            + FRAG_SEQ
            + str(seq)
            + FRAG_TAIL
        )
    return Record(2, detail)
