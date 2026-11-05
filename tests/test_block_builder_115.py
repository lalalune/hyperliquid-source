"""Pure-model checks for tools/block_builder_115.py.

Run from the repository root:
    python3 tests/test_block_builder_115.py

Prints the number of checks and "checks pass" on success.
"""

import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.block_builder_115 import (  # noqa: E402
    BlockBuilder,
    HashIndexAnnex,
    LengthError,
    encode_varint32,
    hash32,
    num_buckets,
    trailer_word,
    varint32_len,
)

CHECKS = 0


def check(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        raise AssertionError(msg)


def eq(got, want, msg):
    check(got == want, "%s: got %r want %r" % (msg, got, want))


# -- varint32 --------------------------------------------------------

for value, want in [(0, b"\x00"), (1, b"\x01"), (0x7F, b"\x7f"),
                    (0x80, b"\x80\x01"), (0x3FFF, b"\xff\x7f"),
                    (0x4000, b"\x80\x80\x01"),
                    (0x1FFFFF, b"\xff\xff\x7f"),
                    (0x200000, b"\x80\x80\x80\x01"),
                    (0xFFFFFFF, b"\xff\xff\xff\x7f"),
                    (0x10000000, b"\x80\x80\x80\x80\x01"),
                    (0xFFFFFFFF, b"\xff\xff\xff\xff\x0f")]:
    eq(encode_varint32(value), want, "varint32 %#x" % value)
    eq(varint32_len(value), len(want), "varint32_len %#x" % value)

rng = random.Random(115)
for _ in range(2000):
    v = rng.randrange(0, 1 << 32)
    enc = encode_varint32(v)
    # canonical LEB128 round trip
    out = 0
    shift = 0
    for byte in enc:
        out |= (byte & 0x7F) << shift
        shift += 7
    eq(out, v, "varint round trip")
    eq(len(enc), varint32_len(v), "varint len matches")

# -- Hash ------------------------------------------------------------

# Hand-derived from the body: empty input returns the seed term
# with no final mix (h = seed ^ 0).
eq(hash32(b"", 0x18D), 0x18D, "hash empty")
eq(hash32(b"", 0), 0, "hash empty seed 0")
# One byte 0x00: h = seed ^ m; tail adds s8(0)=0; final mix.
m = 0xC6A4A793
h = (0x18D ^ m) & 0xFFFFFFFF
h = (h * m) & 0xFFFFFFFF
h ^= h >> 24
eq(hash32(b"\x00", 0x18D), h, "hash one zero byte")
# A 4-byte group with no tail: final mix is skipped.
h = (7 ^ (4 * m)) & 0xFFFFFFFF
h = (h + 0x04030201) & 0xFFFFFFFF
h = (h * m) & 0xFFFFFFFF
h ^= h >> 16
eq(hash32(b"\x01\x02\x03\x04", 7), h, "hash one group no tail")
# Sign extension of tail bytes: 0xff contributes -1, not 255.
h = (0 ^ (1 * m)) & 0xFFFFFFFF
h = (h - 1) & 0xFFFFFFFF
h = (h * m) & 0xFFFFFFFF
h ^= h >> 24
eq(hash32(b"\xff", 0), h, "hash tail sign extension")
check(hash32(b"\xff", 0) != hash32(b"\x7f", 0), "sign matters")

for _ in range(500):
    n = rng.randrange(0, 40)
    data = bytes(rng.randrange(256) for _ in range(n))
    seed = rng.randrange(1 << 32)
    # Structural invariants only; exact vectors come from the
    # Unicorn differential run recorded in the packet.
    v = hash32(data, seed)
    check(0 <= v <= 0xFFFFFFFF, "hash range")
    eq(hash32(data, seed), v, "hash deterministic")

# -- trailer word / num_buckets --------------------------------------

eq(trailer_word(0, 0), 0, "trailer 0")
eq(trailer_word(1, 0), 1, "trailer plain")
eq(trailer_word(1, 1), 0x80000001, "trailer hash bit")
eq(trailer_word(0x1234, 2), 0x1234, "trailer flag != 1")
eq(num_buckets(0.0), 1, "buckets zero acc")
eq(num_buckets(1.0), 1, "buckets 1")
eq(num_buckets(2.0), 3, "buckets 2")
eq(num_buckets(3.9), 3, "buckets trunc")
eq(num_buckets(65536.0), 1, "buckets low16 wrap")
eq(num_buckets(float("nan")), 1, "buckets NaN")

# -- plain builder: byte-exact block layout --------------------------

b = BlockBuilder(16, 0, 0, 0, 0.75)
eq(b.estimate, 8, "ctor estimate")
eq(b.restarts, [0], "ctor restarts")
b.add(b"key-0001" + b"\x01" * 8, b"v1")
b.add(b"key-0002" + b"\x01" * 8, b"v2")
block = b.finish()
# entry: shared=0 (no delta), non_shared=16, vlen=2, key, value
e1 = b"\x00\x10\x02" + b"key-0001" + b"\x01" * 8 + b"v1"
e2 = b"\x00\x10\x02" + b"key-0002" + b"\x01" * 8 + b"v2"
want = e1 + e2 + struct.pack("<I", 0) + struct.pack("<I", 1)
eq(block, want, "plain block bytes")
eq(b.finished, 1, "finished flag")

# -- delta encoding: shared prefixes ---------------------------------

b = BlockBuilder(2, 1, 0, 0, 0.75)
b.add(b"aaaa" + b"\x00" * 8, b"1")
b.add(b"aaab" + b"\x00" * 8, b"2")
# second entry: shared=3 ("aaa"), non_shared=9, vlen=1
b.add(b"zzzz" + b"\x00" * 8, b"3")  # counter hits interval -> restart
block = b.finish()
e1 = b"\x00\x0c\x01" + b"aaaa" + b"\x00" * 8 + b"1"
e2 = b"\x03\x09\x01" + b"b" + b"\x00" * 8 + b"2"
e3 = b"\x00\x0c\x01" + b"zzzz" + b"\x00" * 8 + b"3"
want = e1 + e2 + e3 + struct.pack("<II", 0, len(e1) + len(e2))
want += struct.pack("<I", 2)  # num_restarts = 2, no hash bit
eq(block, want, "delta block bytes")
eq(b.restarts, [0, len(e1) + len(e2)], "restart offsets")
eq(b.estimate, len(want), "estimate invariant")
eq(bytes(b.last_key), b"zzzz" + b"\x00" * 8, "last key kept")

# -- value delta encoding ---------------------------------------------

b = BlockBuilder(16, 1, 1, 0, 0.75)
b.add(b"kkkk" + b"\x00" * 8, b"value-one")
b.add(b"kkkk" + b"\x00" * 8, b"value-two", value_delta=b"D")
block = b.finish()
# entry1: header (0, 12) only two varints, then key, then full value
e1 = b"\x00\x0c" + b"kkkk" + b"\x00" * 8 + b"value-one"
# entry2: shared=12 -> header (12, 0), no key bytes, delta appended
e2 = b"\x0c\x00" + b"D"
want = e1 + e2 + struct.pack("<I", 0) + struct.pack("<I", 1)
eq(block, want, "value delta block bytes")
# with shared == 0 the delta slice is ignored, full value appended
b = BlockBuilder(16, 1, 1, 0, 0.75)
b.add(b"aaaa" + b"\x00" * 8, b"full", value_delta=b"X")
block = b.finish()
e1 = b"\x00\x0c" + b"aaaa" + b"\x00" * 8 + b"full"
eq(block, e1 + struct.pack("<I", 0) + struct.pack("<I", 1),
   "value delta ignored at shared 0")

# -- hash annex --------------------------------------------------------

b = BlockBuilder(16, 1, 0, 1, 0.75)
eq(b.annex.increment, 1.0 / 0.75, "annex increment")
eq(b.annex.enabled, 1, "annex enabled")
keys = []
for i in range(6):
    key = ("user-key-%02d" % i).encode() + struct.pack("<Q", i)
    keys.append(key)
    b.add(key, b"v")
eq(len(b.annex.entries), 6, "annex entries recorded")
for i, (digest, restart_byte) in enumerate(b.annex.entries):
    eq(digest, hash32(keys[i][:-8], 0x18D), "annex hash %d" % i)
    eq(restart_byte, 0, "annex restart byte %d" % i)
block = b.finish()
count = num_buckets(b.annex.accumulator)
# repeated double addition of 4/3 six times gives 7.999999999999999,
# so (int32)acc is 7 and the bucket count is 7 | 1 = 7
eq(count, 7, "annex bucket count")
block_body = block[:len(block) - 4]
trailer = struct.unpack("<I", block[-4:])[0]
eq(trailer, 0x80000001, "hash trailer word")
# bucket section sits between the restarts array and the trailer:
# layout: entries..., restarts (4 bytes), buckets (count), count16
bucket_section = block_body[-(count + 2):]
eq(struct.unpack("<H", bucket_section[-2:])[0], count, "bucket count word")
buckets = bucket_section[:-2]
eq(len(buckets), count, "bucket bytes")
for digest, restart_byte in b.annex.entries:
    check(buckets[digest % count] in (restart_byte, 0xFE),
          "bucket slot populated")

# bucket-count check via the accumulator formula directly
annex = HashIndexAnnex(4.0 / 3.0, 1)
for i in range(6):
    annex.add(b"k" * 12, 0)
want_acc = 0.0
for _ in range(6):
    want_acc += 4.0 / 3.0
eq(annex.accumulator, want_acc, "accumulator sum")
eq(annex.accumulator, 7.999999999999999, "accumulator fp value")

# restart index above 0xfd disables the annex for good
annex = HashIndexAnnex(1.0, 1)
annex.add(b"abc", 0xFD)
eq(annex.enabled, 1, "0xfd accepted")
annex.add(b"abc", 0xFE)
eq(annex.enabled, 0, "0xfe disables")
eq(len(annex.entries), 1, "disabling add records nothing")

# sticky disable across Reset: Reset's annex call is gated on the
# same flag, so a cleared flag is never restored by reset()
b = BlockBuilder(1, 0, 0, 1, 1.0)  # restart every entry
for i in range(300):
    b.add(("k%03d" % i).encode() + b"\x00" * 8, b"v")
check(b.annex.enabled == 0, "annex disabled by >0xfd restarts")
entries_before = len(b.annex.entries)
b.reset()
eq(b.annex.enabled, 0, "disable is sticky across reset")
eq(len(b.annex.entries), entries_before, "entries kept while disabled")

# -- Reset -------------------------------------------------------------

b = BlockBuilder(2, 1, 0, 0, 0.75)
b.add(b"aaaa" + b"\x00" * 8, b"1")
b.add(b"aaab" + b"\x00" * 8, b"2")
b.add(b"aaac" + b"\x00" * 8, b"3")
b.reset()
eq(b.restarts, [0], "reset restarts truncated")
eq(b.estimate, 8, "reset estimate")
eq(b.counter, 0, "reset counter")
eq(b.finished, 0, "reset finished")
eq(len(b.buffer), 0, "reset buffer")
eq(bytes(b.last_key), b"", "reset last key")

# -- EstimateSizeAfterKV ------------------------------------------------

b = BlockBuilder(16, 0, 0, 0, 0.75)
eq(b.estimate_after_kv(10, 5),
   8 + 10 + 5 + 4 + varint32_len(10) + varint32_len(5),
   "estimate plain")
b = BlockBuilder(1, 0, 0, 0, 0.75)  # counter 0 >= interval 1? no: 0 < 1
b.add(b"12345678", b"v")
eq(b.counter, 1, "counter after add")
# now counter (1) >= interval (1): restart imminent -> allowance 8
before = b.estimate
eq(b.estimate_after_kv(200, 3),
   before + 200 + 3 + 8 + varint32_len(200) + varint32_len(3),
   "estimate restart imminent")
b = BlockBuilder(16, 1, 1, 0, 0.75)
eq(b.estimate_after_kv(10, 100),
   8 + 10 + (100 >> 1) + 4 + varint32_len(10),
   "estimate value delta")

# -- length guard --------------------------------------------------------

from tools.block_builder_115 import _GuardedBuffer  # noqa: E402

buf = _GuardedBuffer()
buf.data = bytearray(8)
try:
    # Pretend the string is already at the maximum: emulate by
    # calling append with a piece longer than the headroom left
    # under a shrunken STRING_MAX via a subclass-free trick:
    import tools.block_builder_115 as model
    saved = model.STRING_MAX
    model.STRING_MAX = 10
    try:
        buf.append(b"12345")  # 8 + 5 > 10 -> guard trips
        check(False, "guard should have raised")
    except LengthError as exc:
        check(exc.message == "basic_string::append", "guard message")
    finally:
        model.STRING_MAX = saved
except LengthError:
    check(False, "unexpected LengthError")

print("%d checks pass" % CHECKS)
