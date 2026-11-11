"""Model of node #115 routine 0x61c2cb0: the hash-long
with-seed body (inputs of 241 bytes and longer).

The routine (FDE 0x61c2cb0..0x61c3221, 1393 bytes) is the
callee the merged hash packet for the parent dispatch
(RE-001-hash-callee-61c3530-115, PR #3486) left by contract
only for lengths 241 and above: the parent restores the
argument registers and tail-jumps here from 0x61c3808, its
sole entry (no direct call site exists anywhere in the
binary). The RE-002 vendor census registers this body as
librocksdb-sys 0.11.0+8.1.1 `XXPH3_hashLong_64b_withSeed`;
that identity is cited, not re-asserted -- this model pins
the body's own instructions.

Signature: hash(data=rdi, length=rsi, seed=rdx) -> rax,
the same three arguments the parent received. The input is
read, never written; the only writes are to the routine's
own 0x118-byte stack frame (an 8-qword accumulator array at
frame +0x00..+0x40 and a 192-byte customised secret at
frame +0x40..+0x100, plus the stack-canary slot at
frame +0x108).

What the routine does, in its own instruction order:

  1. Seed delegation. If seed == 0 it checks the canary,
     restores rsp and tail-jumps to the seedless body at
     0x61c2890 (FDE 0x61c2890..0x61c2cad) with rdi/rsi/rdx
     untouched -- the arguments pass through verbatim. That
     body is by contract only here.
  2. Custom secret. For seed != 0 it builds a 192-byte
     secret on the stack from the 192-byte default secret
     held as scattered .rodata constants: even qwords get
     +seed, odd qwords get -seed (mod 2^64). The exact
     wiring -- which .rodata qword feeds each secret qword,
     and with which sign -- is pinned in SECRET_SOURCES
     below; the compiler deinterleaved the default secret
     into an even-qword vector set and an odd-qword vector
     set and interleaved the two adjusted halves back with
     punpcklqdq/punpckhqdq, which is why the sources are not
     address-ordered.
  3. Accumulator init. Eight qwords, loaded from four
     .rodata chunks (0x455960, 0x455950, 0x453a30,
     0x4525e0) and also stored to frame +0x00..+0x40:
     ACC_INIT below.
  4. Block loop. nb_blocks = length >> 10. Each
     1024-byte block runs 16 stripes of 64 bytes (stripe s
     reads its secret at byte offset 8*s of the custom
     secret), then one scramble of the accumulators
     against the custom secret's last 64 bytes.
  5. Remaining stripes. nb = (length >> 6) & 0xf stripes
     are accumulated from data + (length & ~1023), at the
     same secret offsets 8*s.
  6. Last stripe. If length & 63 != 0, one final stripe is
     accumulated from the input's last 64 bytes
     (data + length - 64) against the custom secret at
     byte offset 121 (= 192 - 64 - 7). That offset is not
     qword-aligned: the body loads the secret bytes with
     movdqu directly (at frame +0xb9, +0xc9, +0xd9, +0xe9),
     so the key words straddle the secret's qwords.
  7. Merge hand-off. The routine calls the merge callee
     0x61c27f0 (FDE 0x61c27f0..0x61c2888) once, with
     rdi = the accumulator array (frame +0x00),
     rsi = the custom secret + 11 bytes, and
     rdx = length * 0x9e3779b185ebca87 (mod 2^64), and
     returns its rax after re-checking the canary. That
     body is by contract only here; the model answers the
     call with merge_accs() below, the standard fold-and-
     avalanche contract, and the packet claims only the
     hand-off (arguments, order, return flow), not the
     callee's internals.

The accumulate step (identical instruction pattern in the
block loop, the remaining-stripes loop and the last
stripe), per 16-byte lane pair j = 0..3 of a stripe, with
secret byte offset o = stripe_offset + 16*j:

    key_lo = data64[2*j]   XOR secret64[o]
    key_hi = data64[2*j+1] XOR secret64[o + 8]
    acc[2*j]   += data64[2*j]   + lo32(key_lo) * hi32(key_lo)
    acc[2*j+1] += data64[2*j+1] + lo32(key_hi) * hi32(key_hi)

all mod 2^64. The scramble step, per lane pair j:

    x = acc[i] XOR secret64[128 + 8*i] XOR (acc[i] >> 47)
    acc[i] = x * 0x9e3779b1            (mod 2^64)

for i = 0..7, using the custom secret's bytes 128..192.

Callee contracts (bodies not claimed by this packet):
  * delegate(data, length): the seedless body at
    0x61c2890, entered by tail jump with the arguments
    unchanged (rdx is still 0); its rax is this routine's
    return value on the seed == 0 path.
  * merge(acc, secret, start): the merge callee at
    0x61c27f0, called once with the accumulator tuple, the
    192-byte custom secret (of which it is handed the
    pointer at byte offset 11) and
    start = length * PRIME64_1; its rax is this routine's
    return value on every seed != 0 path.

Memory interface: `mem` is a bytearray addressed by
absolute address minus MEM_BASE (MEM_BASE = 0 in the
model's own coordinate system; callers translate). The two
callees are supplied as one `env` object with
delegate/merge callables, so the tests and the
differential answer them with recording stubs.
"""

MASK64 = 0xFFFFFFFFFFFFFFFF
PRIME32_1 = 0x9E3779B1
PRIME64_1 = 0x9E3779B185EBCA87

ROUTINE = 0x61C2CB0
DELEGATE = 0x61C2890
MERGE = 0x61C27F0

# The 192-byte default secret, as 24 qwords in secret
# order, read out of the binary's .rodata at the source
# addresses in SECRET_SOURCES.
DEFAULT_SECRET = [
    0xBE4BA423396CFEB8, 0x1CAD21F72C81017C,
    0xDB979083E96DD4DE, 0x1F67B3B7A4A44072,
    0x78E5C0CC4EE679CB, 0x2172FFCC7DD05A82,
    0x8E2443F7744608B8, 0x4C263A81E69035E0,
    0xCB00C391BB52283C, 0xA32E531B8B65D088,
    0x4EF90DA297486471, 0xD8ACDEA946EF1938,
    0x3F349CE33F76FAA8, 0x1D4F0BC7C7BBDCF9,
    0x3159B4CD4BE0518A, 0x647378D9C97E9FC8,
    0xC3EBD33483ACC5EA, 0xEB6313FAFFA081C5,
    0x49DAF0B751DD0D17, 0x9E68D429265516D3,
    0xFCA1477D58BE162B, 0xCE31D07AD1B8F88F,
    0x280416958F3ACB45, 0x7E404BBBCAFBD7AF,
]

# (source .rodata address, sign) for each custom-secret
# qword: the qword stored at secret byte offset 8*i is
# read64(source) + sign * seed (mod 2^64). Even qwords
# take +seed from one deinterleaved constant set, odd
# qwords take -seed from the other.
SECRET_SOURCES = [
    (0x455F90, +1), (0x455CF0, -1),
    (0x455F98, +1), (0x455CF8, -1),
    (0x454BC0, +1), (0x4532E0, -1),
    (0x454BC8, +1), (0x4532E8, -1),
    (0x452290, +1), (0x4562E0, -1),
    (0x452298, +1), (0x4562E8, -1),
    (0x455980, +1), (0x4522A0, -1),
    (0x455988, +1), (0x4522A8, -1),
    (0x4548E0, +1), (0x453ED0, -1),
    (0x4548E8, +1), (0x453ED8, -1),
    (0x4514C0, +1), (0x450E30, -1),
    (0x4514C8, +1), (0x450E38, -1),
]

ACC_INIT = [
    0x00000000C2B2AE3D, 0x9E3779B185EBCA87,
    0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9,
    0x85EBCA77C2B2AE63, 0x0000000085EBCA77,
    0x27D4EB2F165667C5, 0x000000009E3779B1,
]
ACC_INIT_SOURCES = [0x455960, 0x455968, 0x455950, 0x455958,
                    0x453A30, 0x453A38, 0x4525E0, 0x4525E8]

MERGE_SECRET_OFFSET = 11
LAST_STRIPE_SECRET_OFFSET = 121
SCRAMBLE_SECRET_OFFSET = 128


def _rd64(mem, addr):
    return int.from_bytes(mem[addr:addr + 8], "little")


def custom_secret(seed):
    """The 192-byte stack secret for a nonzero seed, as a
    list of 24 qwords: even qwords are the default secret
    plus the seed, odd qwords are the default secret minus
    the seed (all mod 2^64)."""
    out = []
    for i, word in enumerate(DEFAULT_SECRET):
        if i % 2 == 0:
            out.append((word + seed) & MASK64)
        else:
            out.append((word - seed) & MASK64)
    return out


def secret_bytes(secret):
    """Serialise a 24-qword secret to its 192 bytes."""
    return b"".join(word.to_bytes(8, "little") for word in secret)


def _secret64(secret, byte_offset):
    """Read one secret qword at an arbitrary byte offset.
    The stripe offsets in the block and remaining-stripes
    loops are multiples of 8, but the last stripe reads at
    byte offset 121, which is not qword-aligned: the body
    loads those secret bytes with movdqu straight from the
    stack secret, so the model reads bytes too."""
    raw = secret_bytes(secret)
    return int.from_bytes(raw[byte_offset:byte_offset + 8], "little")


def accumulate_512(acc, mem, data_addr, secret, secret_byte_offset):
    """One 64-byte stripe: the accumulate step quoted in
    the module docstring, applied in place to the 8-qword
    accumulator list `acc`."""
    for j in range(4):
        o = secret_byte_offset + 16 * j
        for k in range(2):
            i = 2 * j + k
            data_word = _rd64(mem, data_addr + 8 * i)
            key = data_word ^ _secret64(secret, o + 8 * k)
            prod = (key & 0xFFFFFFFF) * (key >> 32)
            acc[i] = (acc[i] + data_word + prod) & MASK64


def scramble_acc(acc, secret):
    """The per-block scramble: xor each accumulator with
    the custom secret's last 64 bytes and with its own
    value shifted right by 47, then multiply by
    PRIME32_1 (mod 2^64)."""
    for i in range(8):
        x = acc[i] ^ _secret64(secret, SCRAMBLE_SECRET_OFFSET + 8 * i)
        x ^= acc[i] >> 47
        acc[i] = (x * PRIME32_1) & MASK64


def _fold64(a, b):
    product = a * b
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def merge_accs(acc, secret_window, start):
    """The merge contract the model answers the 0x61c27f0
    call with: fold the eight accumulators against the 64
    secret bytes starting at the handed pointer (custom
    secret + 11), sum onto `start`, and avalanche. This is
    the contract function shared with the differential; the
    callee's own body is not claimed by the packet."""
    result = start & MASK64
    for i in range(4):
        lo = int.from_bytes(secret_window[16 * i:16 * i + 8], "little")
        hi = int.from_bytes(secret_window[16 * i + 8:16 * i + 16],
                            "little")
        result = (result + _fold64(acc[2 * i] ^ lo,
                                   acc[2 * i + 1] ^ hi)) & MASK64
    result ^= result >> 37
    result = (result * 0x165667B19E3779F9) & MASK64
    result ^= result >> 32
    return result


def hash_long_seed(mem, data, length, seed, env):
    """Run the hash-long with-seed body 0x61c2cb0 against
    the model memory.

    `data` is the input address and `length` its byte
    length (the parent's contract reaches this body only
    for length >= 241, but the body itself imposes no
    check). For seed == 0 the body delegates:
    env.delegate(data, length) is entered with the
    arguments unchanged and its return value is returned.
    For seed != 0 the body accumulates as documented and
    finishes through env.merge(acc, secret, start), with
    acc the final accumulator tuple, secret the 192-byte
    custom secret and start = length * PRIME64_1 mod 2^64;
    its return value is returned.
    """
    seed &= MASK64
    if seed == 0:
        return env.delegate(data, length)
    secret = custom_secret(seed)
    acc = list(ACC_INIT)
    nb_blocks = length >> 10
    for block in range(nb_blocks):
        base = data + block * 1024
        for stripe in range(16):
            accumulate_512(acc, mem, base + 64 * stripe,
                           secret, 8 * stripe)
        scramble_acc(acc, secret)
    remaining = (length >> 6) & 0xF
    rest = data + (length & 0xFFFFFFFFFFFFFC00)
    for stripe in range(remaining):
        accumulate_512(acc, mem, rest + 64 * stripe,
                       secret, 8 * stripe)
    if length & 63:
        accumulate_512(acc, mem, data + length - 64,
                       secret, LAST_STRIPE_SECRET_OFFSET)
    start = (length * PRIME64_1) & MASK64
    return env.merge(tuple(acc), secret_bytes(secret), start)
