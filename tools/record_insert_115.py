"""Model of the node #115 record insert 0x5f0e890.

The insert takes an owner object, a two-part key, a type byte
and a key-part qword, and records the key against the owner's
table. The phases, in order:

1. Product pick: type 0xf uses the product at owner+0xa58,
   any other type the product at owner+0xa50 (the two
   SkipListRep products built by the factory in #3286). The
   product's vtable slot 0 must be the forwarder 0x5f04dc0 for
   the inner object's slot 2 to supply the key buffer; any
   other slot 0 is called with a pointer-to-pointer and
   supplies the buffer itself.
2. Key build: the buffer is varint(L1+8) + part1 + an 8-byte
   trailer (keypart << 8 | type) + varint(L2) + part2, where
   L1/L2 are the two part lengths; width extra bytes follow
   for the resolved value.
3. Value resolve (0x5f09e90, merged ground): a directly
   supplied qword when the direct pointer is non-null, else a
   four-way xor-fold of the 64-bit hash callee; the value is
   stored truncated to the owner's +0x6c width at the tail.
4. ProtectionInfo validate (0x5f09b10, merged ground), run
   only when the protection pointer is non-null: two varint
   length parses with capacity bounds, then the four-way
   hash-fold equality. On failure the out status takes the
   Corruption status (code 2) with one of the seven pinned
   messages; the record is not inserted.
5. Commit branch, by the flag stack argument: flag != 0 runs
   the product slot dispatch (slots 0x30/0x28/0x38, or slot
   0x40 when the context pointer is null) against the GOT
   canonicals and then updates the caller's counters struct
   (count +1, total += key total, typed +1 when type != 0);
   flag == 0 runs the +0xc78 filter gate, the map
   find-or-insert 0x5f0e660 and the product slot dispatch
   (slots 0x20/0x18/0x8), or the direct slot-0x10/slot-0x8
   arm when the gate is absent or false, and then updates
   the owner fields +0xa70 (+1), +0xa68 (+= key total) and
   +0xa78 (+1 for types 0, 7 and 20). The two counter sets
   are path-specific: the flag!=0 path never touches the
   owner fields and the flag==0 path never touches the
   caller's counters struct. A false slot result in the
   gated slots builds Status TryAgain (code 13)
   "key+seq exists".
6. Bloom insert, one block per path with the same shape
   (0x5f0eb26..0x5f0ec09 on the flag!=0 path,
   0x5f0ee46..0x5f0ef1c on the flag==0 path): the
   +0xc58/+0xc60 filter's slot 0xa0 gates and slot 0x98
   supplies the hashed pair; the golden-ratio mixed hash
   sets two bits per probe for *(filter+0x4) probes. When
   *(owner+0x30) != 0 a second insert runs on the same
   pair hashed directly (0x5f0f206 on the flag!=0 path,
   0x5f0f0a7 on the flag==0 path). Both are skipped when
   the filter state is null.
7. The +0xc18/+0xc20 min-install (this packet closes the
   open unknown from #3322, which recorded the writer of
   owner+0xc18 as unknown): the two CAS loops install the
   key-part as the new minimum — block A when (old-1) >=
   the key-part unsigned, block B when +0xc20 is the
   sentinel or the key-part is below +0xc20 and +0xc18
   equals +0xc20, is the sentinel, or is above the
   key-part. When +0xc18 is still 0 afterwards — exactly
   when the key-part is 0 — the first-install path stores
   it and, when +0xc20 is still the sentinel, copies it
   there too.
8. Tail, by type: type 0xf allocates the 0x48-byte control
   and installs one shared_ptr per table entry (N = 1 <<
   *(owner+0xd18)), under the +0xce8 mutex when the flag is
   non-zero; any other type runs the once helper 0x5f07490
   and the lazy resolver 0x5f074e0 (#3304/#3322) on the owner.
9. The out status is zeroed (bytes 0..5 and 8..15; bytes
   6..7 are never written by this window).

Virtual slots are injectable callables; the 64-bit hash
callee 0x61c3530 is cited by contract only (as in the merged
packets) and injected as `hash64` in the tests. The 32-bit
hash 0x61c34a0 is implemented exactly.
"""

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1
GOLDEN64 = 0x9E3779B97F4A7C13
HASH32_MULT = 0xC6A4A793
HASH32_SEED = 0xBC9F1D34
MAP_HASH_SEED = 0x18D
C20_SENTINEL = 0x00FFFFFFFFFFFFFF
REFCOUNT_ONE = 0x100000001  # qword at .rodata 0x459b20
FORWARDER_SLOT0 = 0x5F04DC0
TYPE_TABLE = 0x0F
TYPE_CLASS_BITS = 0x100081  # bits 0, 7, 20: those types bump
# owner+0xa78 (the bit test at 0x5f0ee31..0x5f0ee46)

# Product vtable slots and their GOT canonicals.
GOT = {
    0x10: (0x64ED748, 0x5F04CF0),
    0x18: (0x64ED750, 0x5F04D10),
    0x20: (0x64ED798, 0x5F05740),
    0x28: (0x64ED758, 0x5F04D20),
    0x30: (0x64ED7A0, 0x5F05780),
    0x40: (0x64ED760, 0x5F04D30),
}

# Status codes (rocksdb::Status::Code): 2 Corruption, 13 TryAgain.
STATUS_CORRUPTION = 2
STATUS_TRY_AGAIN = 13
TRY_AGAIN_MESSAGE = b"key+seq exists"

# The seven ProtectionInfo validation messages (merged ground).
VALIDATE_MESSAGES = {
    "parse_key_len": (0x95CFD0, b"Unable to parse internal key length"),
    "key_too_short": (0x44A2E4, b"Internal key length too short"),
    "key_too_long": (0x4361A9, b"Internal key length too long"),
    "parse_value_len": (0x43E6AD, b"Unable to parse value length"),
    "value_too_short": (0x44DF06, b"Value length too short"),
    "value_too_long": (0x43314B, b"Value length too long"),
    "protection_mismatch": (0x44A302, b"ProtectionInfo mismatch"),
}

# The four 64-bit hash seeds of the resolve/validate folds.
HASH64_SEEDS = (
    0x0000000000000000,
    0xD28AAD72F49BD50B,
    0xA5155AE5E937AA16,
    0x77A00858DDD37F21,
)


def varint_len(value):
    """Bytes 0x61bd410 writes for value (1..5)."""
    n = 1
    while value >= 0x80:
        value >>= 7
        n += 1
    return n


def encode_varint32(value):
    """Mirror 0x61bd410: LEB128 u32, up to 5 bytes."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint32(buf, pos):
    """(value, new_pos); None when the buffer ends first.

    Matches the fast path of 0x5f09b10 (a first byte below
    0x80 is the length) and the 0x61bd4f0 contract for longer
    forms; returns None when the varint runs past the end.
    """
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return (result & MASK32, pos)
        shift += 7
        if shift >= 35:
            return None
    return None


def hash32(data, seed):
    """Mirror 0x61c34a0 (rocksdb::Hash): h = len * 0xc6a4a793
    ^ seed, then one 4-byte word at a time (h += word;
    h *= 0xc6a4a793; h ^= h >> 16), then the 1..3 tail bytes
    folded in with a final multiply and xor-shift >> 24."""
    h = ((len(data) * HASH32_MULT) & MASK32) ^ (seed & MASK32)
    n = len(data)
    i = 0
    while i + 4 <= n:
        word = int.from_bytes(data[i:i + 4], "little")
        h = (h + word) & MASK32
        h = (h * HASH32_MULT) & MASK32
        h ^= h >> 16
        i += 4
    tail = n - i
    if tail == 3:
        h += (data[i + 2] if data[i + 2] < 0x80 else data[i + 2] - 0x100) << 16
        h &= MASK32
        tail = 2
    if tail == 2:
        h += (data[i + 1] if data[i + 1] < 0x80 else data[i + 1] - 0x100) << 8
        h &= MASK32
        tail = 1
    if tail == 1:
        h += data[i] if data[i] < 0x80 else data[i] - 0x100
        h &= MASK32
        h = (h * HASH32_MULT) & MASK32
        h ^= h >> 24
    return h & MASK32


def build_key(part1, part2, keypart, typ, width):
    """Mirror the key build in 0x5f0e890: varint(L1+8) +
    part1 + trailer + varint(L2) + part2 + width zero bytes.
    The trailer is (keypart << 8 | type) as 8 little-endian
    bytes; the tail is where the resolve step stores."""
    length1 = len(part1) + 8
    out = bytearray()
    out += encode_varint32(length1)
    out += part1
    out += ((keypart << 8) | (typ & 0xFF)).to_bytes(8, "little")
    out += encode_varint32(len(part2))
    out += part2
    out += bytes(width)
    return bytes(out)


def key_total(part1, part2, width):
    """Total buffer size: the two varints, both parts, the
    8-byte trailer and the width-byte tail."""
    return (varint_len(len(part1) + 8) + len(part1) + 8
            + varint_len(len(part2)) + len(part2) + width)


def resolve_value(direct, slice_a, slice_b, byte_in, qword_in,
                  width, hash64):
    """Mirror 0x5f09e90. When direct is not None the resolved
    value is that qword and no hash runs; otherwise it is the
    four-way xor-fold of the 64-bit hash callee over slice_a
    (seed 0), slice_b (seed 0xd28aad72f49bd50b), one byte_in
    byte (seed 0xa5155ae5e937aa16) and the qword_in as 8 bytes
    (seed 0x77a00858ddd37f21). The store writes the value
    truncated to width bytes (1/2/4/8); width 0 stores
    nothing. Returns the stored bytes."""
    if width == 0:
        return b""
    if direct is not None:
        value = direct & MASK64
    else:
        value = (hash64(slice_a[0], slice_a[1], HASH64_SEEDS[0])
                 ^ hash64(slice_b[0], slice_b[1], HASH64_SEEDS[1])
                 ^ hash64(bytes([byte_in & 0xFF]), 1, HASH64_SEEDS[2])
                 ^ hash64(qword_in.to_bytes(8, "little"), 8,
                          HASH64_SEEDS[3])) & MASK64
    if width == 1:
        return bytes([value & 0xFF])
    if width == 2:
        return (value & 0xFFFF).to_bytes(2, "little")
    if width == 4:
        return (value & MASK32).to_bytes(4, "little")
    if width == 8:
        return value.to_bytes(8, "little")
    return b""


def validate_key(buf, capacity, protection, hash64):
    """Mirror 0x5f09b10. Returns (True, None) on success, else
    (False, message bytes) for the Corruption status. The
    buffer is varint(key_len) + key + varint(value_len) +
    value + 8-byte trailer; key_len covers the key payload
    plus the 8-byte trailer. The fold is h_shifted ^
    h_key ^ protection ^ h_value == h_tag, where h_tag
    hashes the trailer low byte with seed
    0xa5155ae5e937aa16."""
    parsed = decode_varint32(buf, 0)
    if parsed is None:
        return (False, VALIDATE_MESSAGES["parse_key_len"][1])
    key_len, pos = parsed
    if key_len < capacity + 8:
        return (False, VALIDATE_MESSAGES["key_too_short"][1])
    if key_len > len(buf) - pos:
        return (False, VALIDATE_MESSAGES["key_too_long"][1])
    key_end = pos + key_len
    parsed = decode_varint32(buf, key_end)
    if parsed is None:
        return (False, VALIDATE_MESSAGES["parse_value_len"][1])
    value_len, vpos = parsed
    if value_len < len(buf) - vpos:
        return (False, VALIDATE_MESSAGES["value_too_short"][1])
    if value_len > len(buf) - vpos:
        return (False, VALIDATE_MESSAGES["value_too_long"][1])
    trailer = buf[pos + key_len - 8:pos + key_len]
    shifted = int.from_bytes(trailer, "little") >> 8
    tag_byte = bytes([trailer[0]])
    fold = (hash64(shifted.to_bytes(8, "little"), 8, HASH64_SEEDS[3])
            ^ hash64(buf[pos:pos + key_len - 8], key_len - 8,
                     HASH64_SEEDS[0])
            ^ protection
            ^ hash64(buf[vpos:vpos + value_len], value_len,
                     HASH64_SEEDS[1]))
    tag = hash64(tag_byte, 1, HASH64_SEEDS[2])
    if fold != tag:
        return (False, VALIDATE_MESSAGES["protection_mismatch"][1])
    return (True, None)


def bloom_insert(words, first, num_probes, data):
    """Mirror one bit-set loop (0x5f0eb8c / 0x5f0f0a7 /
    0x5f0f206): hash the data with seed 0xbc9f1d34, mix with
    the golden ratio, then for probe i in 0..num_probes-1
    set two bits in word (first_mix ^ i), where the bit
    positions come from the rolling hash (low 6 bits and
    bits 6..11), the hash rolling right by 12 each probe.
    `words` is a dict index -> u64, standing in for the
    filter's word array (sparse, so any index is valid)."""
    h = hash32(data, HASH32_SEED)
    mix_hi = (((first & MASK32) * h) & MASK64) >> 32
    state = (h * GOLDEN64) & MASK64
    for i in range(num_probes):
        index = (mix_hi ^ i) & MASK64
        bits = ((1 << (state & 63)) | (1 << ((state >> 6) & 63)))
        words[index] = words.get(index, 0) | bits
        state = ((state >> 12) | ((state & 0xFFF) << 52)) & MASK64


def _cas_min_install(c18, c20, rbx):
    """Sequential equivalent of the two CAS loops at
    0x5f0ec22..0x5f0ec64. Block A installs rbx into +0xc18
    when (old - 1) >= rbx unsigned (old 0 installs any rbx;
    old 1 installs only rbx 0). Block B runs only when
    +0xc20 is the sentinel or rbx < +0xc20; its first CAS
    expects +0xc18 == +0xc20, and on failure the retry
    installs rbx when +0xc18 is the sentinel or rbx <
    +0xc18. Returns the new +0xc18."""
    old = c18
    if ((old - 1) & MASK64) >= rbx:
        c18 = rbx
    if c20 == C20_SENTINEL or rbx < c20:
        if c18 == c20:
            c18 = rbx
        elif c18 == C20_SENTINEL or rbx < c18:
            c18 = rbx
    return c18


def min_install(c18, c20, rbx):
    """The full +0xc18/+0xc20 install of 0x5f0e890: the CAS
    loops, then the first-install path at 0x5f0f188 when
    +0xc18 is still 0 (store rbx, and copy it to +0xc20
    when +0xc20 is still the sentinel). Returns (c18, c20)."""
    c18 = _cas_min_install(c18, c20, rbx)
    if c18 == 0:
        c18 = rbx
        if c20 == C20_SENTINEL:
            c20 = rbx
    return (c18, c20)


def fresh_owner(width=8, table_bits=0):
    """An owner as the tail init leaves the fields this
    packet touches: products keyed by type, filter slots
    empty, +0xc18/+0xc20 unset, counters zero."""
    return {
        "width": width,
        "products": {0xA50: None, 0xA58: None},
        "filter_obj": None,   # +0xc58 object (slots 0xa0/0x98)
        "filter_state": None,  # +0xc60 state {first, probes,
                               # words: dict index -> u64}
        "filter78_obj": None,  # +0xc78 object (slots 0xa0/0x98)
        "c18": 0, "c20": C20_SENTINEL, "c30": 0, "cap_offset": 0,
        "a60": 0, "a68": 0, "a70": 0, "a78": 0,
        "d10": [], "d18": table_bits,
        "ce8_locked": False,
        "counters": {"total": 0, "count": 0, "typed": 0},
        "installed": [],  # shared_ptr table entries (type 0xf)
        "big_use": 0,
    }


def pick_product(owner, typ):
    """The product for a type: +0xa58 when type is 0xf,
    +0xa50 otherwise (0x5f0e959..0x5f0e97f)."""
    return owner["products"][0xA58 if typ == TYPE_TABLE else 0xA50]


def get_buffer(product, size):
    """Mirror the buffer fetch at 0x5f0e993..0x5f0e9b1: when
    the product's vtable slot 0 is the forwarder 0x5f04dc0
    the inner object's slot 2 supplies the buffer; any
    other slot 0 is called with a one-element out slot and
    supplies it. A product is a dict with 'slot0' (None for
    the forwarder, else a callable taking (out, size)) and
    'inner_slot2' (a callable taking size, returning a
    bytearray)."""
    if product["slot0"] is None:
        return product["inner_slot2"](size)
    out = [None]
    product["slot0"](out, size)
    return out[0]


def dispatch_commit(product, context, keybuf, map_value=None):
    """Mirror the product slot dispatch. `product` maps slot
    offsets to 'canonical' or a callable returning a bool
    (for the gated slots) or None (for the ungated ones).
    Returns ('ok', callee) or ('try_again', callee). The
    gated slots are 0x30 and 0x40 on the flag path and 0x20
    on the map path; a false result builds the TryAgain
    status. The context pointer being null selects the
    slot-0x40 arm; otherwise slots 0x30, then 0x28, then
    0x38 are tried in order."""
    slots = product["slots"]
    if context is None:
        if slots[0x40] == "canonical":
            return ("ok", 0x38)
        result = slots[0x40](keybuf)
        return ("ok" if result else "try_again", 0x40)
    if slots[0x30] != "canonical":
        result = slots[0x30](keybuf, context)
        return ("ok" if result else "try_again", 0x30)
    if slots[0x28] != "canonical":
        slots[0x28](keybuf, context)
        return ("ok", 0x28)
    return ("ok", 0x38)


def dispatch_flag0_direct(product, keybuf):
    """Mirror the flag==0 direct arm at 0x5f0ede5..0x5f0ee06:
    slot 0x10 against its canonical 0x5f04cf0; when it is
    not canonical it is called and its bool gates
    continuation, when it is canonical slot 0x8 is called
    instead and the result is not tested. Returns
    ('ok', callee) or ('try_again', callee)."""
    slots = product["slots"]
    if slots[0x10] != "canonical":
        result = slots[0x10](keybuf)
        return ("ok" if result else "try_again", 0x10)
    slots[0x08](keybuf)
    return ("ok", 0x08)


def dispatch_map(product, keybuf, map_value):
    """Mirror the flag==0 dispatch at 0x5f0f052..0x5f0f084:
    slot 0x20 against its canonical, else slot 0x18, else
    slot 0x8. Only slot 0x20's bool gates continuation."""
    slots = product["slots"]
    if slots[0x20] != "canonical":
        result = slots[0x20](keybuf, map_value)
        return ("ok" if result else "try_again", 0x20)
    if slots[0x18] != "canonical":
        slots[0x18](keybuf, map_value)
        return ("ok", 0x18)
    slots[0x08](keybuf, map_value)
    return ("ok", 0x08)


def install_shared(owner):
    """Mirror the type-0xf install loop (0x5f0ec70..0x5f0ed4a
    and 0x5f0f1d0..0x5f0f1fc): one 0x48-byte control holding
    the 0x38-byte cache object, then one 0x20-byte control
    per table entry (N = 1 << *(owner+0xd18)). The big
    control's use count ends at N; each small control's
    temporary reference is released (use 2 -> 1); the old
    entry controls are released. The +0xce8 mutex is held
    only when the flag is non-zero; +0xa60 ends at 0."""
    count = 1 << owner["d18"]
    owner["installed"] = [
        {"big": "cache", "small_use": 1} for _ in range(count)]
    owner["big_use"] = count
    owner["a60"] = 0
    owner["ce8_locked"] = False
    return count


def record_insert(owner, out, part1, part2, keypart, typ,
                  direct=None, protection=None, flag=0,
                  context=None, counters=None, hash64=None):
    """Mirror 0x5f0e890 end to end. `out` is a 16-byte
    bytearray (the status struct; bytes 6..7 preserved).
    `part1`/`part2` are the key parts as (data, length)
    slices; `keypart` is the rdx qword; `typ` the type
    byte; `direct` the direct-value pointer value or None;
    `protection` the protection qword or None (validation
    skipped when None); `flag` the stack flag byte;
    `context` the stack context pointer or None; `counters`
    the counters struct or None; `hash64` the injected
    64-bit hash (data, length, seed) -> int. Returns
    (status, events) where status is 'ok', 'corruption' or
    'try_again' and events lists the phases that ran."""
    events = []
    width = owner["width"]
    product = pick_product(owner, typ)
    total = key_total(part1[0], part2[0], width)
    keybuf = get_buffer(product, total)
    events.append("buffer")
    built = build_key(part1[0], part2[0], keypart, typ, width)
    keybuf[:len(built)] = built
    # Resolve the value into the tail (0x5f09e90).
    stored = resolve_value(
        direct, part1, part2, len(part1[0]) & 0xFF, keypart,
        width, hash64)
    keybuf[total - width:total] = stored
    events.append("resolve")
    # Validate, only when a protection object is present.
    # The validated length is total - width (0x5f0ea61):
    # the width-byte tail holding the resolved value is
    # not part of the ProtectionInfo record.
    if protection is not None:
        ok, message = validate_key(
            bytes(keybuf[:total - width]), owner.get("capacity", 0),
            protection, hash64)
        if not ok:
            events.append("validate_fail")
            out[0:6] = bytes(6)
            out[8:16] = bytes(8)
            # The record move-assign (0x5f05310) copies the
            # validate status into out; the code byte is
            # pinned here, the heap message pointer is not
            # an address in this model (the message is the
            # returned value).
            out[0] = STATUS_CORRUPTION
            return ("corruption", message, events)
        events.append("validate_ok")
    # The two key pairs, as the binary builds them:
    # pair78 is the part-1 slice after its varint prefix
    # (0x5f0edc0), pair2 is the part-1 slice with its length
    # shortened by *(owner+0x10+0x28) (0x5f0ea9e).
    vlen1 = varint_len(len(part1[0]) + 8)
    pair78 = (built[vlen1:vlen1 + len(part1[0])], len(part1[0]))
    pair2 = (part1[0], part1[1] - owner.get("cap_offset", 0))
    # Commit branch.
    if flag != 0:
        outcome, callee = dispatch_commit(
            product, context, bytes(keybuf[:total]))
        events.append("commit:%#x" % callee)
        if outcome != "ok":
            return ("try_again", TRY_AGAIN_MESSAGE, events)
        # The caller's counters struct (0x5f0eb0a..0x5f0eb21);
        # this path never touches the owner counter fields.
        if counters is not None:
            counters["count"] += 1
            counters["total"] += total
            if typ != 0:
                counters["typed"] += 1
            events.append("counters")
    else:
        filter78 = owner["filter78_obj"]
        if filter78 is not None and filter78["slot_a0"](pair78):
            data, length = filter78["slot_98"](pair78)
            value_slot = map_find_or_insert(
                owner, data, length)
            outcome, callee = dispatch_map(
                product, bytes(keybuf[:total]), value_slot)
            events.append("map:%#x" % callee)
            if outcome != "ok":
                return ("try_again", TRY_AGAIN_MESSAGE, events)
        else:
            # The +0xc78 gate is absent or false: the direct
            # arm runs the slot-0x10 check and slot 0x8.
            outcome, callee = dispatch_flag0_direct(
                product, bytes(keybuf[:total]))
            events.append("direct:%#x" % callee)
            if outcome != "ok":
                return ("try_again", TRY_AGAIN_MESSAGE, events)
        # The owner counter fields (0x5f0ee09..0x5f0ee46);
        # this path never touches the caller's counters struct.
        owner["a70"] += 1
        owner["a68"] += total
        if typ <= 0x14 and (TYPE_CLASS_BITS >> typ) & 1:
            owner["a78"] += 1
        events.append("owner_counters")
    # Bloom insert (0x5f0eb36..0x5f0ec09, 0x5f0f206).
    # Variant 1: the +0xc58 filter's slot 0xa0 gates on
    # pair2 and slot 0x98 supplies the hashed pair. Variant
    # 2, when *(owner+0x30) != 0: pair2 hashed directly.
    state = owner["filter_state"]
    obj = owner["filter_obj"]
    if state is not None and obj is not None:
        if obj["slot_a0"](pair2):
            data, length = obj["slot_98"](pair2)
            bloom_insert(state["words"], state["first"],
                         state["probes"], data[:length])
            events.append("bloom")
        if owner["c30"] != 0:
            bloom_insert(state["words"], state["first"],
                         state["probes"],
                         pair2[0][:pair2[1]])
            events.append("bloom2")
    # The +0xc18/+0xc20 min-install (0x5f0ec22..0x5f0f1b7).
    owner["c18"], owner["c20"] = min_install(
        owner["c18"], owner["c20"], keypart)
    events.append("min_install")
    # Tail by type.
    if typ == TYPE_TABLE:
        if flag != 0:
            owner["ce8_locked"] = True
            events.append("mutex_lock")
        install_shared(owner)
        events.append("shared_install")
    else:
        events.append("once_resolver")
    # Zero the out status (bytes 0..5 and 8..15).
    out[0:6] = bytes(6)
    out[8:16] = bytes(8)
    return ("ok", None, events)


def map_find_or_insert(owner, data, length):
    """Mirror 0x5f0e660: hash the key with seed 0x18d,
    walk the bucket chain comparing the cached hash and
    the key bytes, and on a miss allocate a 0x28-byte node
    holding the key and its hash. Returns the node's value
    slot (a one-element list). The table lives on the owner
    as 'map' ({'buckets': [...], 'count': int}); rehash
    doubles the bucket count when the load would exceed
    one element per bucket (libstdc++ _Prime_rehash_policy
    with max load factor 1.0, cited not re-derived)."""
    table = owner.setdefault(
        "map", {"buckets": [[] for _ in range(8)], "count": 0})
    buckets = table["buckets"]
    h = hash32(data[:length], MAP_HASH_SEED)
    index = h % len(buckets)
    for node in buckets[index]:
        if node["hash"] == h and node["key"] == data[:length]:
            return node["value"]
    if table["count"] + 1 > len(buckets):
        new = [[] for _ in range(len(buckets) * 2)]
        for chain in buckets:
            for node in chain:
                new[node["hash"] % len(new)].append(node)
        table["buckets"] = new
        buckets = new
        index = h % len(buckets)
    node = {"key": data[:length], "hash": h, "value": [None]}
    buckets[index].append(node)
    table["count"] += 1
    return node["value"]
