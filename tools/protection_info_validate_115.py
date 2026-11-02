"""Python model of node #115 ProtectionInfo validation (0x5f09b10).

One whole function from the digest-verified node #115 work binary
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
it validates a two-field length-prefixed record and its
ProtectionInfo fold, and clears the caller's status record on success.

Layout of the buffer (all lengths are unsigned):

    [key-length prefix][key payload][trailer qword]
    [value-length prefix][value payload, exactly to the end]

Rules, in window order:

1. Key length: a single byte below 0x80 is the length and the payload
   starts one byte later; otherwise the length comes from the varint
   callee 0x61bd4f0 (cited by contract only -- this model decodes it
   as unsigned LEB128, the encoding the neighbouring packets
   establish for that callee). A parse failure reports
   "Unable to parse internal key length".
2. Key bounds: key_len must be at least key_capacity + 8, where
   key_capacity is the +0x28 field of the object reached through the
   second argument's +0x10 slot; otherwise "Internal key length too
   short". The key payload must fit in the remaining buffer;
   otherwise "Internal key length too long".
3. Trailer: the qword at key_payload + (key_len - 8). Its low byte is
   the tag byte; the remaining seven bytes (trailer >> 8) are the
   shifted trailer value.
4. Value length: parsed the same way at trailer + 8. A parse failure
   reports "Unable to parse value length". The value length must
   equal the remaining bytes exactly: smaller reports "Value length
   too short", larger reports "Value length too long".
5. Protection fold: with the hash callee 0x61c3530 (cited by contract
   only -- callers pass a hash function in), success requires

       hash(trailer >> 8 as 8 little-endian bytes, 0x77a00858ddd37f21)
       ^ hash(key payload, 0)
       ^ protection_qword
       ^ hash(value payload, 0xd28aad72f49bd50b)
       == hash(tag byte as 1 byte, 0xa5155ae5e937aa16)

   where protection_qword is the +0x00 qword of the fourth argument's
   object. Any other result reports "ProtectionInfo mismatch".

On success the 16-byte status record is cleared except bytes 6..7,
which the window never writes (it stores a dword at +0x00, a word at
+0x04 and a qword at +0x08). On failure the window reports through
callee 0x61cf670 with code 2, the message above, and an empty file
slice; the exact status bytes the report callee writes are that
callee's business and are not modelled here. The function returns
the status object in both cases; this model returns (ok, message),
with message None on success.
"""

import struct

SEED_SHIFTED_TRAILER = 0x77A00858DDD37F21
SEED_KEY = 0x0000000000000000
SEED_VALUE = 0xD28AAD72F49BD50B
SEED_TAG_BYTE = 0xA5155AE5E937AA16

MSG_KEY_PARSE = "Unable to parse internal key length"
MSG_KEY_SHORT = "Internal key length too short"
MSG_KEY_LONG = "Internal key length too long"
MSG_VALUE_PARSE = "Unable to parse value length"
MSG_VALUE_SHORT = "Value length too short"
MSG_VALUE_LONG = "Value length too long"
MSG_PROTECTION = "ProtectionInfo mismatch"


def parse_length_prefix(buf, pos):
    """Parse one length prefix at pos.

    Returns (length, next_pos), or None on failure. The single-byte
    fast path (byte < 0x80) is literal window behaviour; the
    multi-byte path delegates to the unsigned-LEB128 decoding the
    neighbouring packets establish for callee 0x61bd4f0.
    """
    if pos >= len(buf):
        return None
    first = buf[pos]
    if first < 0x80:
        return (first, pos + 1)
    result = 0
    shift = 0
    i = pos
    while i < len(buf) and shift < 70:
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return (result, i)
        shift += 7
    return None


def validate(buffer, key_capacity, protection_qword, hash_fn):
    """Validate one record. Returns (ok, error_message_or_None).

    buffer: the whole record bytes. key_capacity: the +0x28 field
    described above. protection_qword: the +0x00 qword of the fourth
    argument's object. hash_fn(data: bytes, seed: int) -> int, the
    0x61c3530 callee supplied by the caller (its body is not part of
    this model).
    """
    parsed = parse_length_prefix(buffer, 0)
    if parsed is None:
        return (False, MSG_KEY_PARSE)
    key_len, key_start = parsed
    if key_len < key_capacity + 8:
        return (False, MSG_KEY_SHORT)
    if len(buffer) - key_start < key_len:
        return (False, MSG_KEY_LONG)
    trailer_pos = key_start + (key_len - 8)
    trailer = struct.unpack_from("<Q", buffer, trailer_pos)[0]
    parsed = parse_length_prefix(buffer, trailer_pos + 8)
    if parsed is None:
        return (False, MSG_VALUE_PARSE)
    value_len, value_start = parsed
    remaining = len(buffer) - value_start
    if value_len < remaining:
        return (False, MSG_VALUE_SHORT)
    if value_len > remaining:
        return (False, MSG_VALUE_LONG)
    key_payload = buffer[key_start:key_start + key_len - 8]
    value_payload = buffer[value_start:value_start + value_len]
    shifted = struct.pack("<Q", trailer >> 8)
    tag = bytes([trailer & 0xFF])
    fold = (
        hash_fn(shifted, SEED_SHIFTED_TRAILER)
        ^ hash_fn(key_payload, SEED_KEY)
        ^ protection_qword
        ^ hash_fn(value_payload, SEED_VALUE)
    )
    if fold != hash_fn(tag, SEED_TAG_BYTE):
        return (False, MSG_PROTECTION)
    return (True, None)


def clear_status(status):
    """Apply the window's success store to a 16-byte status record.

    Zeroes bytes 0..5 and 8..15; bytes 6..7 are never written by the
    window and are left exactly as they were.
    """
    if len(status) != 16:
        raise ValueError("status record must be 16 bytes")
    status[0:6] = b"\x00" * 6
    status[8:16] = b"\x00" * 8
    return status
