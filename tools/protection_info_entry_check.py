"""Model of node #94 ProtectionInfo entry check 0x51694e0 (RE-001).

Reconstructed semantics, from research/work-items/RE-001-protection-info-entry-check-94/:

    check(buffer, expected, min_gate, hash_bytes) -> result dict

``buffer`` is a length-prefixed internal key followed by a
length-prefixed value. ``expected`` is the caller-provided u64 (the
*r8 argument). ``min_gate`` is the u64 field value the binary reads
at [[gate_object + 0x10] + 0x28]; the model takes it as an input
because the gate object's identity is unresolved. ``hash_bytes`` is
the hash function 0x5422f00 by contract: it is injected because the
target hash is not implemented on this VM (no cargo/rustc, no
execution of the target binary).

Length prefixes follow the binary exactly: a first byte below 0x80
is the length; otherwise the 32-bit varint helper decodes 7-bit
groups at shifts 0/7/14/21/28 and fails on a fifth continuation byte
or on running past the end.

On success the result is {"ok": True, ...parsed fields}; on failure
it is {"ok": False, "detail": <the binary's detail string>}.
"""

SEQ_SEED = 0x77A00858DDD37F21
USER_SEED = 0
VALUE_SEED = 0xD28AAD72F49BD50B
TYPE_SEED = 0xA5155AE5E937AA16

DETAIL_LEN_KEY = "Unable to parse internal key length"
DETAIL_LEN_SHORT = "Internal key length too short"
DETAIL_LEN_LONG = "Internal key length too long"
DETAIL_VAL_KEY = "Unable to parse value length"
DETAIL_VAL_SHORT = "Value length too short"
DETAIL_VAL_LONG = "Value length too long"
DETAIL_MISMATCH = "ProtectionInfo mismatch"


def decode_varint32(buf, pos, end):
    """The 0x541cec0 helper: (value, next_pos) or None on failure."""
    value = 0
    shift = 0
    cur = pos
    while True:
        if cur >= end:
            return None
        byte = buf[cur]
        cur += 1
        if byte < 0x80:
            return (value | (byte << shift)), cur
        value |= (byte & 0x7F) << shift
        shift += 7
        if shift > 28:
            return None


def decode_prefix(buf, pos, end, fail_detail):
    """One length prefix: single-byte fast path or the varint helper."""
    if pos < end and buf[pos] < 0x80:
        return buf[pos], pos + 1
    decoded = decode_varint32(buf, pos, end)
    if decoded is None:
        raise ValueError(fail_detail)
    return decoded


def check_entry(buf, expected, min_gate, hash_bytes):
    """Verify one buffer; returns a result dict (see module docstring)."""
    try:
        length, entry_start = decode_prefix(buf, 0, len(buf), DETAIL_LEN_KEY)
    except ValueError as exc:
        return {"ok": False, "detail": str(exc)}
    if length < min_gate + 8:
        return {"ok": False, "detail": DETAIL_LEN_SHORT}
    if len(buf) - entry_start < length:
        return {"ok": False, "detail": DETAIL_LEN_LONG}
    entry = buf[entry_start:entry_start + length]
    user_key = entry[:-8]
    trailer = int.from_bytes(entry[-8:], "little")
    value_type = trailer & 0xFF
    sequence = trailer >> 8
    value_start_prefix = entry_start + length
    try:
        value_len, value_start = decode_prefix(
            buf, value_start_prefix, len(buf), DETAIL_VAL_KEY)
    except ValueError as exc:
        return {"ok": False, "detail": str(exc)}
    remaining = len(buf) - value_start
    if value_len < remaining:
        return {"ok": False, "detail": DETAIL_VAL_SHORT}
    if value_len > remaining:
        return {"ok": False, "detail": DETAIL_VAL_LONG}
    value = buf[value_start:value_start + value_len]
    computed = (
        hash_bytes(sequence.to_bytes(8, "little"), SEQ_SEED)
        ^ hash_bytes(user_key, USER_SEED)
        ^ hash_bytes(value, VALUE_SEED)
        ^ hash_bytes(bytes([value_type]), TYPE_SEED)
    )
    if computed != expected:
        return {"ok": False, "detail": DETAIL_MISMATCH}
    return {
        "ok": True,
        "user_key": user_key,
        "value_type": value_type,
        "sequence": sequence,
        "value": value,
    }


def encode_prefix(length):
    """Encode a length the way the binary's producers do (single byte
    below 0x80, otherwise standard LEB128). Used by the tests only."""
    if length < 0x80:
        return bytes([length])
    out = bytearray()
    value = length
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_buffer(user_key, value_type, sequence, value):
    """Build a well-formed buffer for the tests."""
    trailer = (sequence << 8) | value_type
    entry = user_key + trailer.to_bytes(8, "little")
    return encode_prefix(len(entry)) + entry + encode_prefix(len(value)) + value
