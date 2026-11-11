"""Model of the node #115 record-write entry 0x5f0f930.

The entry takes an owner object, a user key, a tag qword, an
options record and an optional direct-value pointer, looks the
key up in the owner's two products, and dispatches on the
owner's virtual slot 0x40:

  * code 0: the key is already present -- run the once helper
    and return Status OK;
  * code 1: refresh the stored value -- rebuild the protection
    fold, resolve it into the record tail, validate the record,
    and return the validation status;
  * code 2: the key is absent -- insert it through the record
    insert 0x5f0e890 (#3330) and return the insert status.

Any other dispatch code returns Status NotFound (code 1).

Phases, in order:

1. Key build (0x5eab0c0): internal key = varint(len(key) + 8)
   + key + trailer((tag << 8) | 0x16). The buffer is inline
   (the key struct's own tail) when len(key) + 13 <= 0xc8,
   else heap-allocated with operator new.
2. Product-1 lookup (owner+0xa50): the canonical-forwarder
   dispatch (slot 0x98 vs GOT 0x64ed778 holding 0x5f04d80;
   canonical -> slot 0x90), then slot 0x30, slot 0x10 (must
   be true) and slot 0x18 (the found key). The found key
   length is parsed (one byte < 0x80, else varint32
   0x61bd4f0) and the trailer's low byte must be 1
   (kTypeValue), else NotFound.
3. Product-2 lookup (owner+0x10): the canonical-forwarder
   dispatch (slot 0x98 vs GOT 0x64ed010 holding 0x5d2ca80;
   canonical -> slot 0x10 on the product+0x20 subobject).
   The two paths use opposite return senses: the canonical
   slot 0x10 proceeds on a zero return, the non-canonical
   slot 0x98 on a nonzero return.
4. Value length (0x5f06f40): the varint after the found
   key's trailer, then the hash-bucket projection 0x5f099b0
   (#2115) and the bucket write-lock 0x60d5ab0.
5. Dispatch on the owner's virtual slot 0x40 with
   (value pointer, &reported length, the 16-byte options
   record by value, &out string, the direct pointer) and
   the three arms above. The once helper 0x5f07490 runs
   once per arm (sites 0x5f0fc4d, 0x5f0fce4, 0x5f0ff5e).
6. Epilogue, shared by all paths: bucket unlock 0x60d5c30
   (dispatch arms only), the out-string dispose, the
   product-1 object release (slot 0x8) and the key-buffer
   delete[] when heap-allocated.

The 64-bit hash callee 0x61c3530 is cited by contract only
(as in the merged packets) and injected as `hash64`. The
record insert 0x5f0e890, the value resolve 0x5f09e90 and the
ProtectionInfo validation 0x5f09b10 are merged/#3330 ground;
their call sites and argument lists are pinned here, their
bodies are not re-implemented -- the model calls the local
`resolve_value` / `validate_record` mirrors of #2084/#2108
and takes the insert as an injectable.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
TYPE_VALUE = 1
TRAILER_TYPE = 0x16
INLINE_LIMIT = 0xC8
STATUS_OK = 0
STATUS_NOT_FOUND = 1
STATUS_CORRUPTION = 2
STATUS_TRY_AGAIN = 13
SEED_SHIFTED_TRAILER = 0x77A00858DDD37F21
SEED_VALUE = 0xD28AAD72F49BD50B
SEED_TAG_BYTE = 0xA5155AE5E937AA16
SEED_KEY = 0x0000000000000000
RWLOCK_OK = (0, 0x10, 0x6E)
STATS_ARM1 = 0x27
STATS_ARM2 = 0x25

# The seven ProtectionInfo validation messages (merged ground,
# #2108: addresses and lengths pinned there).
VALIDATE_MESSAGES = {
    "parse_key_len": (0x95CFD0, b"Unable to parse internal key length"),
    "key_too_short": (0x44A2E4, b"Internal key length too short"),
    "key_too_long": (0x4361A9, b"Internal key length too long"),
    "parse_value_len": (0x43E6AD, b"Unable to parse value length"),
    "value_too_short": (0x44DF06, b"Value length too short"),
    "value_too_long": (0x43314B, b"Value length too long"),
    "protection_mismatch": (0x44A302, b"ProtectionInfo mismatch"),
}


def varint_len(value):
    """Bytes of the varint32 encoding of `value`."""
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def encode_varint32(value):
    """The 0x61bd410 encoder: little-endian base-128."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint32(buf, pos, limit=None):
    """The 0x61bd4f0 decoder: (value, consumed) or None.

    Reads at most 5 bytes (shifts 0, 7, 14, 21, 28); fails
    when the pointer reaches `limit` (default pos + 5, the
    bound the callers pass) or the shift would exceed 28.
    """
    if limit is None:
        limit = pos + 5
    if pos >= limit or pos >= len(buf):
        return None
    result = 0
    shift = 0
    i = pos
    while True:
        if i >= limit or i >= len(buf):
            return None
        byte = buf[i]
        i += 1
        if byte < 0x80:
            return (result | (byte << shift), i - pos)
        result |= (byte & 0x7F) << shift
        shift += 7
        if shift > 0x1C:
            return None


def parse_key_length(buf, pos):
    """The 0x5f06f40 reader: (length, value_ptr_offset).

    One byte below 0x80 is the length itself; otherwise the
    u32 varint at pos (limit pos + 5). Returns None on a
    decode failure.
    """
    if pos >= len(buf):
        return None
    first = buf[pos]
    if first < 0x80:
        return (first, pos + 1)
    parsed = decode_varint32(buf, pos, pos + 5)
    if parsed is None:
        return None
    value, consumed = parsed
    return (value, pos + consumed)


def build_internal_key(key, tag, second=b""):
    """The 0x5eab0c0 builder. Returns a dict with the built
    bytes, whether the buffer is inline, and the varint
    length of the length prefix.

    Layout: varint(len(key) + 8) + key + second + trailer,
    trailer = (tag << 8) | 0x16 as 8 little-endian bytes.
    Inline exactly when len(key) + len(second) + 13 <= 0xc8
    (the window compares len + 13 against 0xc8, heap-allocating
    with operator new above it).
    """
    prefix = encode_varint32(len(key) + 8)
    trailer = ((tag << 8) | TRAILER_TYPE) & MASK64
    buf = prefix + bytes(key) + bytes(second) + trailer.to_bytes(8, "little")
    inline = len(key) + len(second) + 13 <= INLINE_LIMIT
    return {"bytes": buf, "inline": inline,
            "varint_len": len(prefix), "total": len(buf)}


def clear_status(status):
    """The window's success store: zeroes bytes 0..5 and
    8..15 of a 16-byte status record; bytes 6..7 are never
    written by this window and are preserved."""
    if len(status) != 16:
        raise ValueError("status record must be 16 bytes")
    status[0:6] = b"\x00" * 6
    status[8:16] = b"\x00" * 8
    return status


def write_status(status, code):
    """Write a bare status code the way the 0x5f0fad7 /
    arm-0 paths do: dword code, word 0, qword 0; bytes
    6..7 preserved."""
    status[0:4] = code.to_bytes(4, "little")
    status[4:6] = b"\x00\x00"
    status[8:16] = b"\x00" * 8
    return status


def move_record(dst, src):
    """The 0x5f05310 move-assign: copies 6 bytes + the
    8-byte pointer at +0x8 from src to dst, zeroing the
    source; frees the destination's old +0x8 pointer when
    non-null (modelled as the returned freed value, or
    None). A move onto itself is a no-op."""
    if dst is src:
        return None
    freed = int.from_bytes(dst[8:16], "little")
    dst[0:6] = src[0:6]
    dst[8:16] = src[8:16]
    src[0:6] = b"\x00" * 6
    src[8:16] = b"\x00" * 8
    return freed if freed != 0 else None


def rwlock_wrlock(lock):
    """The 0x60d5ab0 write-lock: rc in {0, 0x10, 0x6e} is
    accepted, anything else prints
    'pthread write lock: <strerror>' to stderr and aborts.
    `lock` is a dict with "rc" and "locked"."""
    if lock.get("rc", 0) not in RWLOCK_OK:
        raise RuntimeError("pthread write lock: rc %#x" % lock["rc"])
    lock["locked"] = True
    return lock


def rwlock_unlock(lock):
    """The 0x60d5c30 unlock: same rc rule, message
    'pthread write unlock: <strerror>' on failure."""
    if lock.get("rc", 0) not in RWLOCK_OK:
        raise RuntimeError("pthread write unlock: rc %#x" % lock["rc"])
    lock["locked"] = False
    return lock


def resolve_value(direct, first_slice, second_slice, byte_in,
                  qword_in, width, out_slot, hash64):
    """Mirror of #2084 (0x5f09e90). `direct` is the resolved
    qword when the value pointer is non-null, else None and
    the four-way fold runs: hash(first, 0) ^
    hash(second, 0xd28aad72f49bd50b) ^ hash(bytes([byte]),
    0xa5155ae5e937aa16) ^ hash(qword as 8 LE bytes,
    0x77a00858ddd37f21). The value is stored truncated to
    `width` (1/2/4/8 bytes) at out_slot, a bytearray slice
    position; width 0 or outside {1, 2, 4, 8} stores nothing.
    Returns (resolved, stored_bytes)."""
    if direct is not None:
        resolved = direct & MASK64
    else:
        if hash64 is None:
            raise ValueError("hash path needs hash64")
        resolved = (
            hash64(bytes(first_slice), SEED_KEY)
            ^ hash64(bytes(second_slice), SEED_VALUE)
            ^ hash64(bytes([byte_in & 0xFF]), SEED_TAG_BYTE)
            ^ hash64(qword_in.to_bytes(8, "little"),
                     SEED_SHIFTED_TRAILER)
        ) & MASK64
    if width == 0 or width not in (1, 2, 4, 8):
        return (resolved, 0)
    out_slot[0:width] = resolved.to_bytes(8, "little")[:width]
    return (resolved, width)


def validate_record(buffer, key_capacity, protection_qword, hash64):
    """Mirror of #2108 (0x5f09b10). Returns (ok, message)."""
    parsed = parse_length_prefix(buffer, 0)
    if parsed is None:
        return (False, VALIDATE_MESSAGES["parse_key_len"][1])
    key_len, key_start = parsed
    if key_len < key_capacity + 8:
        return (False, VALIDATE_MESSAGES["key_too_short"][1])
    if len(buffer) - key_start < key_len:
        return (False, VALIDATE_MESSAGES["key_too_long"][1])
    trailer_pos = key_start + (key_len - 8)
    trailer = int.from_bytes(buffer[trailer_pos:trailer_pos + 8], "little")
    parsed = parse_length_prefix(buffer, trailer_pos + 8)
    if parsed is None:
        return (False, VALIDATE_MESSAGES["parse_value_len"][1])
    value_len, value_start = parsed
    remaining = len(buffer) - value_start
    if value_len < remaining:
        return (False, VALIDATE_MESSAGES["value_too_short"][1])
    if value_len > remaining:
        return (False, VALIDATE_MESSAGES["value_too_long"][1])
    key_payload = buffer[key_start:key_start + key_len - 8]
    value_payload = buffer[value_start:value_start + value_len]
    shifted = (trailer >> 8).to_bytes(8, "little")
    tag = bytes([trailer & 0xFF])
    fold = (
        hash64(shifted, SEED_SHIFTED_TRAILER)
        ^ hash64(bytes(key_payload), SEED_KEY)
        ^ (protection_qword & MASK64)
        ^ hash64(bytes(value_payload), SEED_VALUE)
    ) & MASK64
    if fold != hash64(tag, SEED_TAG_BYTE):
        return (False, VALIDATE_MESSAGES["protection_mismatch"][1])
    return (True, None)


def parse_length_prefix(buffer, pos):
    """The validate window's length parse: one byte < 0x80,
    else the varint32 decoder (0x61bd4f0). Returns
    (length, payload_start) or None."""
    if pos >= len(buffer):
        return None
    first = buffer[pos]
    if first < 0x80:
        return (first, pos + 1)
    parsed = decode_varint32(buffer, pos)
    if parsed is None:
        return None
    value, consumed = parsed
    return (value, pos + consumed)


def record_write(out, owner, key, tag, options, direct, virt,
                 hash64=None):
    """Mirror 0x5f0f930 end to end.

    `out` is a 16-byte bytearray (the status struct; bytes
    6..7 preserved). `owner` is a dict with "width"
    (host+0x6c) and "a10_capacity" (the capacity for the
    validate window). `key` is the user-key bytes (the
    orig-rcx slice payload). `tag` is the orig-rdx qword.
    `options` is the orig-r8 slice bytes. `direct` is the
    qword at the orig-r9 pointer, or None when r9 is null.
    `virt` holds the injectable virtuals / callees:
    find_a50(built_key_bytes) -> found record bytes or
    None (the product-1 lookup reads the key from the
    built key's data pointer: varint prefix + key +
    trailer); check_a10(found_payload, slice_150) ->
    proceed bool (slice_150 is the built key minus its
    trailer: varint prefix + user key); bucket_for(slice_150)
    -> bucket token dict {"rc": int, "locked": bool};
    dispatch(value, reported_len, options, direct) ->
    (code, reported_len, out_string_bytes);
    insert(args dict) -> 16-byte status bytes; once() and
    stats(code) (stats=None means owner+0x50 is null);
    release_a50() (the slot-0x8 release); lock/unlock
    default to the rwlock model. Returns (status, events)
    where status is 'ok', 'not_found', 'corruption' or
    'try_again' and events lists the phases that ran.
    """
    events = []
    if len(out) != 16:
        raise ValueError("out status must be 16 bytes")
    find_a50 = virt["find_a50"]
    check_a10 = virt["check_a10"]
    bucket_for = virt["bucket_for"]
    dispatch = virt["dispatch"]
    insert = virt["insert"]
    once = virt["once"]
    stats = virt.get("stats")
    release_a50 = virt.get("release_a50", lambda: None)
    lock = virt.get("lock", rwlock_wrlock)
    unlock = virt.get("unlock", rwlock_unlock)

    # 1. Key build.
    built = build_internal_key(key, tag)
    events.append("key_build:inline" if built["inline"]
                  else "key_build:heap")
    buf = built["bytes"]
    n = built["varint_len"]
    # The -0x150 slice: the built key minus its 8-byte
    # trailer (varint prefix + user key). It is the slice
    # the bucket projection, the product-2 check, the
    # arm-1 fold's fourth hash and the resolve's second
    # slice all read. The -0x150 record is an out-parameter
    # of the product-1 slot-0x30 call, overwritten with
    # {data, total - 8} before any read.
    slice_150 = buf[:n + len(key)]
    # The product-1 lookup reads the key from the built
    # key's data pointer: the whole built key.
    slice_full = bytes(buf)

    def epilogue(bucket):
        if bucket is not None:
            unlock(bucket)
            events.append("unlock")
        release_a50()
        events.append("release_a50")
        if not built["inline"]:
            events.append("key_buffer_freed")

    # 2. Product-1 lookup.
    found = find_a50(slice_full)
    events.append("find_a50")
    if found is None:
        write_status(out, STATUS_NOT_FOUND)
        epilogue(None)
        return ("not_found", events)
    found = bytes(found)
    parsed = parse_key_length(found, 0)
    if parsed is None:
        raise ValueError("found key length varint failed")
    klen, kconsumed = parsed
    payload = found[kconsumed:kconsumed + (klen - 8)]
    if len(payload) != klen - 8 or len(found) < kconsumed + klen:
        raise ValueError("found key truncated")
    trailer_at = kconsumed + (klen - 8)
    trailer = int.from_bytes(found[trailer_at:trailer_at + 8], "little")

    # 3. Product-2 lookup.
    if not check_a10(bytes(payload), bytes(slice_150)):
        write_status(out, STATUS_NOT_FOUND)
        epilogue(None)
        return ("not_found", events)
    events.append("check_a10")

    # Tag must be kTypeValue (1).
    if trailer & 0xFF != TYPE_VALUE:
        write_status(out, STATUS_NOT_FOUND)
        epilogue(None)
        return ("not_found", events)
    events.append("tag_value")

    # 4. Value length, bucket, lock.
    vparsed = parse_key_length(found, trailer_at + 8)
    if vparsed is None:
        raise ValueError("value length varint failed")
    vlen, vstart = vparsed
    value = found[vstart:vstart + vlen]
    if len(value) != vlen:
        raise ValueError("found value truncated")
    bucket = bucket_for(slice_150)
    events.append("bucket")
    lock(bucket)
    events.append("lock")

    # 5. Dispatch.
    code, reported_len, out_string = dispatch(
        bytes(value), vlen, bytes(options), direct)
    events.append("dispatch:%d" % code)

    if code == 0:
        once()
        events.append("once")
        write_status(out, STATUS_OK)
        epilogue(bucket)
        return ("ok", events)
    if code not in (1, 2):
        write_status(out, STATUS_NOT_FOUND)
        epilogue(bucket)
        return ("not_found", events)

    if code == 1:
        # Grow path: re-encode varint(reported_len) at the
        # value-length position; when the old varint is
        # longer, shift the value bytes to the new position.
        record = bytearray(found)
        record.extend(b"\x00" * 8)
        value_at = vstart
        if reported_len < vlen:
            events.append("grow")
            new_prefix = encode_varint32(reported_len)
            old_vlen = varint_len(vlen)
            if old_vlen > len(new_prefix):
                dst = trailer_at + 8 + len(new_prefix)
                record[dst:dst + reported_len] = value[:reported_len]
                value_at = dst
                events.append("grow_memcpy")
            record[trailer_at + 8:
                   trailer_at + 8 + len(new_prefix)] = new_prefix
        if stats is not None:
            stats(STATS_ARM1)
            events.append("stats:0x27")
        once()
        events.append("once")
        value_end = value_at + reported_len
        if direct is not None:
            fold = direct
            for data, seed in (
                    (tag.to_bytes(8, "little"), SEED_SHIFTED_TRAILER),
                    ((trailer >> 8).to_bytes(8, "little"),
                     SEED_SHIFTED_TRAILER),
                    (bytes(options), SEED_VALUE),
                    (bytes(slice_150), SEED_VALUE)):
                fold ^= hash64(bytes(data), seed)
            fold &= MASK64
            events.append("fold")
            resolved, _stored = resolve_value(
                fold, key, slice_150, 1, trailer >> 8,
                owner["width"],
                memoryview(record)[value_end:value_end + 8],
                hash64)
            events.append("resolve:direct")
            ok, message = validate_record(
                bytes(record[:value_end]),
                owner["a10_capacity"], fold, hash64)
            events.append("validate")
            if not ok:
                write_status(out, STATUS_CORRUPTION)
                epilogue(bucket)
                return ("corruption", message, events)
            clear_status(out)
            epilogue(bucket)
            return ("ok", events)
        # Direct pointer null: the resolve helper runs its
        # own four-way fold (value pointer null).
        resolved, _stored = resolve_value(
            None, key, slice_150, 1, trailer >> 8,
            owner["width"],
            memoryview(record)[value_end:value_end + 8],
            hash64)
        events.append("resolve:fold")
        write_status(out, STATUS_OK)
        epilogue(bucket)
        return ("ok", events)

    # code == 2: insert through 0x5f0e890.
    if direct is not None:
        fold2 = direct
        for data, seed in ((bytes(options), SEED_VALUE),
                           (bytes(out_string), SEED_VALUE)):
            fold2 ^= hash64(bytes(data), seed)
        fold2 &= MASK64
        events.append("fold2")
        arg7 = fold2
    else:
        arg7 = None
    insert_status = insert({
        "out_slot": "stack-0x150",
        "owner": owner,
        "keypart": tag,
        "type": TYPE_VALUE,
        "part1": bytes(key),
        "part2": bytes(out_string),
        "arg7": arg7,
        "flag": 0,
        "context": None,
        "counters": None,
    })
    events.append("insert")
    # The insert status is move-assigned into a temp, then
    # into out (0x5f05310 twice); the two delete[] checks
    # after each move find a null pointer (the move zeroes
    # the source), so nothing is freed.
    temp = bytearray(16)
    freed = move_record(temp, bytearray(insert_status))
    if freed is not None:
        events.append("insert_msg_freed")
    if stats is not None:
        stats(STATS_ARM2)
        events.append("stats:0x25")
    once()
    events.append("once")
    write_status(out, STATUS_OK)
    move_record(out, temp)
    code_out = out[0]
    epilogue(bucket)
    if code_out == STATUS_OK:
        return ("ok", events)
    if code_out == STATUS_TRY_AGAIN:
        return ("try_again", events)
    return ("status:%d" % code_out, events)
