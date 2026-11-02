"""Private scalar word equations from native arithmetic, never an evaluator.

Credit the merged RE-001 alias feed and #1077's round mathematics. This file
does not import Rust, decode/dispatch instructions or run any captured code.
It models the newly selected variable-length original-key + ff wrappers.
"""
MASK = (1 << 64) - 1
CONSTANTS = (0x736F6D6570736575, 0x646F72616E646F6D,
             0x6C7967656E657261, 0x7465646279746573)


def rotate(value, count):
    return ((value << count) | (value >> (64-count))) & MASK


def logical_round(v):
    a, b, c, d = v
    a = (a+b) & MASK
    b = rotate(b, 13) ^ a
    a = rotate(a, 32)
    c = (c+d) & MASK
    d = rotate(d, 16) ^ c
    a = (a+d) & MASK
    d = rotate(d, 21) ^ a
    c = (c+b) & MASK
    b = rotate(b, 17) ^ c
    c = rotate(c, 32)
    return [a, b, c, d]


def bulk_payload(keys, payload):
    """Whole concatenated bytes; logical state order and direct word chunks."""
    k0, k1 = keys
    v = [CONSTANTS[i] ^ (k0 if i % 2 == 0 else k1) for i in range(4)]
    def absorb(word):
        nonlocal v
        v[3] ^= word
        v = logical_round(v)
        v[0] ^= word
    complete = len(payload)//8*8
    for at in range(0, complete, 8):
        absorb(int.from_bytes(payload[at:at+8], 'little'))
    final = int.from_bytes(payload[complete:], 'little') | ((len(payload)&255) << 56)
    absorb(final)
    v[2] ^= 255
    for _ in range(3):
        v = logical_round(v)
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def physical_round(words):
    """Independent native memory order v0,v2,v1,v3 and paired scheduling."""
    a, c, b, d = words
    ab = (a+b) & MASK
    cd = (c+d) & MASK
    bb = ((b >> 51) | (b << 13)) & MASK
    dd = ((d >> 48) | (d << 16)) & MASK
    b = bb ^ ab
    d = dd ^ cd
    a = (((ab >> 32) | (ab << 32)) + d) & MASK
    c = (cd+b) & MASK
    b = (((b >> 47) | (b << 17)) & MASK) ^ c
    d = (((d >> 43) | (d << 21)) & MASK) ^ a
    c = ((c >> 32) | (c << 32)) & MASK
    return [a, c, b, d]


def stream_key(keys, data, delimiter=255):
    """Two writes with an explicit retained tail and per-write state snapshots."""
    k0, k1 = keys
    w = [CONSTANTS[0]^k0, CONSTANTS[2]^k0,
         CONSTANTS[1]^k1, CONSTANTS[3]^k1]
    pending = bytearray()
    total = 0
    snapshots = []
    def absorb(word):
        nonlocal w
        w[3] ^= word
        w = physical_round(w)
        w[0] ^= word
    for chunk in (data, bytes([delimiter])):
        total = (total+len(chunk)) & MASK
        pending.extend(chunk)
        while len(pending) >= 8:
            word = 0
            for lane in range(8):
                word += pending[lane] * (256**lane)
            absorb(word)
            del pending[:8]
        snapshots.append({'words_v0_v2_v1_v3': [f'{x:016x}' for x in w],
                          'total_u64': total, 'tail_hex': bytes(pending).hex(),
                          'tail_len': len(pending)})
    final = sum(byte * (256**i) for i, byte in enumerate(pending))
    final |= (total & 255) * (1 << 56)
    absorb(final)
    w[1] ^= 255
    for _ in range(3):
        w = physical_round(w)
    return w[0] ^ w[1] ^ w[2] ^ w[3], snapshots, final
