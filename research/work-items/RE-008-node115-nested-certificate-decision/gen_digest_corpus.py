#!/usr/bin/env python3
"""Oracle for the digest side of the per-signature check: relations-digest.tsv, written before the Rust.

Usage: python3 -I gen_digest_corpus.py <new, empty output directory>

Writes cases-keccak.tsv, cases-digest.tsv, cases-recover.tsv and cases-primitives.tsv. The output directory must
not exist or must be empty; nothing else is written and no input is modified.

Rule list (the reading of relations-digest.tsv; none of it calls Rust):
  K1  hasher = Keccak with rate 136 bytes, delimiter byte 0x01, 32 byte output: pad (data, delimiter, zeros,
      0x80 in the last byte of the block), absorb little endian lanes, 24 rounds of the FIPS 202 permutation.
      Here the permutation is derived from the FIPS 202 text (round constants from the LFSR of algorithm 5,
      rotation offsets from the walk of algorithm 2), not copied from any table, so it shares no table with
      the Rust code. With delimiter 0x06 the same code is SHA3-256.
  E1  preimage = "Hyperliquid Consensus Payload" (29 bytes) || 0x01 || signer (20 bytes) ||
      varint(w0) || varint(w1) || varint(w2) || varint(w3) || varint(w4) || hash (32 bytes)
      where (w0, w1) is the certificate pair, w2 = f30, w3 = f38, w4 = f40 (frame offsets +0x20..+0x40) and
      varint(v) = v (1 byte) if v < 251; 0xfb + 2 bytes LE if v < 2^16; 0xfc + 4 bytes LE if v < 2^32;
      else 0xfd + 8 bytes LE.
  E2  digest = Keccak(preimage).
  R1  signature = 65 bytes: r = bytes 0..32, s = bytes 32..64 (each a little endian 32 byte number), v = byte
      64. The curve routine gets r and s byte reversed (big endian), the recovery id and the digest.
  R2  recovery id: v in {0, 27} -> 0; v in {1, 28} -> 1; v in 2..=26 or 29..=34 -> error 6 without calling the
      curve routine; v >= 35 -> (~v) & 1.
  R3  the curve routine fails (parse or recover) -> error 3. Otherwise it yields 64 bytes (X || Y); the address
      is Keccak(X || Y)[12..32].
"""
import hashlib
import os
import random
import sys

M64 = (1 << 64) - 1
PREFIX = b"Hyperliquid Consensus Payload"


def rotl(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def _rc_bit(t):
    """FIPS 202 algorithm 5."""
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


ROUND_CONSTANTS = []
for _ir in range(24):
    _v = 0
    for _j in range(7):
        if _rc_bit(_j + 7 * _ir):
            _v |= 1 << ((1 << _j) - 1)
    ROUND_CONSTANTS.append(_v)

RHO = [[0] * 5 for _ in range(5)]
_x, _y = 1, 0
for _t in range(24):
    RHO[_x][_y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def keccak_f(a):
    for ir in range(24):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], RHO[x][y])
        a = [b[x + 5 * y] ^ (((~b[(x + 1) % 5 + 5 * y]) & M64) & b[(x + 2) % 5 + 5 * y]) for y in range(5) for x in range(5)]
        a[0] ^= ROUND_CONSTANTS[ir]
    return a


def sponge(data, delim, rate=136, outlen=32):
    buf = bytearray(data) + bytes([delim])
    while len(buf) % rate:
        buf.append(0)
    buf[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(buf[off + 8 * i:off + 8 * i + 8], "little")
        state = keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:outlen]


def keccak256(data):
    return sponge(data, 0x01)


def varint(v):
    if v < 251:
        return bytes([v])
    if v < 1 << 16:
        return b"\xfb" + v.to_bytes(2, "little")
    if v < 1 << 32:
        return b"\xfc" + v.to_bytes(4, "little")
    return b"\xfd" + v.to_bytes(8, "little")


def preimage(signer, words, h):
    return PREFIX + b"\x01" + signer + b"".join(varint(w) for w in words) + h


def recid_of(v):
    if v in (0, 27):
        return 0
    if v in (1, 28):
        return 1
    if v <= 34:
        return None
    return (~v) & 1


def ramp(n):
    return bytes((7 * i + 3) & 0xFF for i in range(n))


GX = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
GY = bytes.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

# Public values (sources in README.md, "Public vectors"): none of these is produced by this script's permutation.
PUBLIC = [
    ("sha3-256 empty (FIPS 202 example)", 0x06, b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    ("sha3-256 abc (FIPS 202 example)", 0x06, b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    ("keccak-256 empty", 0x01, b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    ("keccak-256 abc", 0x01, b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    ("keccak-256 quick brown fox", 0x01, b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
]
G_ADDRESS = "7e5f4552091a69125d5dfcb7b8c2659029395bdf"  # Ethereum address of private key 1, public key = G


def self_check():
    for name, delim, msg, want in PUBLIC:
        got = sponge(msg, delim).hex()
        assert got == want, (name, got)
    assert keccak256(GX + GY)[12:].hex() == G_ADDRESS
    # the sponge, padding and permutation against the standard library's SHA3-256 on every length that
    # matters around the 136 byte rate
    for n in list(range(0, 300)) + [407, 408, 409, 543, 544, 545, 680, 1000]:
        assert sponge(ramp(n), 0x06) == hashlib.sha3_256(ramp(n)).digest(), n


def hexs(b):
    return b.hex() if b else "-"


def main():
    out = sys.argv[1]
    if os.path.exists(out) and os.listdir(out):
        sys.exit("output directory must be new or empty: " + out)
    os.makedirs(out, exist_ok=True)
    self_check()
    rng = random.Random(0xD16E57)

    # ---- cases-keccak.tsv -------------------------------------------------------------------------------------
    rows = ["id\tgroup\tdelim\tkind\tdata\tdigest"]
    n = 0
    for name, delim, msg, want in PUBLIC:
        n += 1
        rows.append("k%04d\tpublic\t%02x\thex\t%s\t%s" % (n, delim, msg.hex() or "-", want))
    lengths = list(range(0, 141)) + list(range(255, 276)) + [400, 407, 408, 409, 543, 544, 545, 680, 1000]
    for ln in lengths:
        n += 1
        rows.append("k%04d\tsha3-256-library\t06\tramp\t%d\t%s" % (n, ln, hashlib.sha3_256(ramp(ln)).hexdigest()))
    for ln in lengths:
        n += 1
        rows.append("k%04d\tkeccak-256\t01\tramp\t%d\t%s" % (n, ln, keccak256(ramp(ln)).hex()))
    write(out, "cases-keccak.tsv", rows)

    # ---- cases-digest.tsv -------------------------------------------------------------------------------------
    cols = "id\tgroup\tsigner\tw0\tw1\tw2\tw3\tw4\thash\tpreimage\tdigest"
    rows = [cols]
    n = 0

    def add(group, signer, words, h):
        nonlocal n
        n += 1
        pre = preimage(signer, words, h)
        rows.append("\t".join(["d%04d" % n, group, signer.hex()] + ["%x" % w for w in words]
                              + [h.hex(), pre.hex(), keccak256(pre).hex()]))

    base_signer = bytes(range(0xA0, 0xB4))
    base_hash = bytes((0x30 + i) & 0xFF for i in range(32))
    base_words = [7, 9, 11, 13, 15]
    edge = [0, 1, 250, 251, 252, 255, 256, 65535, 65536, 65537, (1 << 32) - 1, 1 << 32, (1 << 32) + 1, (1 << 63), M64]
    for pos in range(5):
        for v in edge:
            w = list(base_words)
            w[pos] = v
            add("word%d-edge" % pos, base_signer, w, base_hash)
    for pos in range(20):
        s = bytearray(20)
        s[pos] = 0x80 | pos
        add("signer-byte%d" % pos, bytes(s), base_words, base_hash)
    for pos in range(32):
        h = bytearray(32)
        h[pos] = 0x40 + pos
        add("hash-byte%d" % pos, base_signer, base_words, bytes(h))
    add("all-zero", bytes(20), [0] * 5, bytes(32))
    add("all-ones", b"\xff" * 20, [M64] * 5, b"\xff" * 32)
    for _ in range(150):
        words = [rng.choice([rng.getrandbits(b) for b in (3, 8, 12, 16, 20, 31, 32, 33, 48, 64)]) for _ in range(5)]
        add("random", bytes(rng.getrandbits(8) for _ in range(20)), words, bytes(rng.getrandbits(8) for _ in range(32)))
    write(out, "cases-digest.tsv", rows)

    # ---- cases-recover.tsv ------------------------------------------------------------------------------------
    # backend column: pub:<128 hex> (the curve routine returns this key) or none (it reports failure)
    rows = ["id\tgroup\tsig\tmsg\tbackend\tcalls\targs\tresult"]
    n = 0

    def rec(group, sig, msg, backend):
        nonlocal n
        n += 1
        v = sig[64]
        rid = recid_of(v)
        if rid is None:
            calls, args, res = 0, "-", "err6"
        else:
            calls = 1
            args = "%s:%s:%d" % (sig[0:32][::-1].hex(), sig[32:64][::-1].hex(), rid)
            res = "err3" if backend == "none" else "addr:" + keccak256(bytes.fromhex(backend[4:]))[12:].hex()
        rows.append("r%04d\t%s\t%s\t%s\t%s\t%d\t%s\t%s" % (n, group, sig.hex(), msg.hex(), backend, calls, args, res))

    pub = bytes(rng.getrandbits(8) for _ in range(64))
    sig0 = bytes(rng.getrandbits(8) for _ in range(64))
    msg0 = bytes(rng.getrandbits(8) for _ in range(32))
    for v in range(256):
        rec("v-sweep", sig0 + bytes([v]), msg0, "pub:" + pub.hex())
    for v in (0, 1, 27, 28, 35, 36, 37, 254, 255):
        rec("curve-failure", sig0 + bytes([v]), msg0, "none")
    for pos in range(64):
        s = bytearray(64)
        s[pos] = 0x11 + pos
        rec("byte-order", bytes(s) + b"\x1b", msg0, "pub:" + pub.hex())
    rec("generator-key", sig0 + b"\x1c", msg0, "pub:" + (GX + GY).hex())
    for _ in range(40):
        rec("random", bytes(rng.getrandbits(8) for _ in range(65)), bytes(rng.getrandbits(8) for _ in range(32)),
            "pub:" + bytes(rng.getrandbits(8) for _ in range(64)).hex())
    write(out, "cases-recover.tsv", rows)

    # ---- cases-primitives.tsv: whole certificates, real digest + stand-in curve routine -----------------------
    cols = "id\tcert\tsigner\tpub\tsig\tw0\tw1\tw2\tw3\tw4\thash\tdigest\trecid\tr_be\ts_be"
    rows = [cols]
    n = 0
    for cert, (count, words, vs) in enumerate([
        (4, [3, 5, 300, 70000, 1 << 40], [27, 28, 0, 1]),
        (3, [0, 251, 65536, 1 << 32, 99], [35, 36, 37]),
        (1, [1, 2, 3, 4, 5], [28]),
        (5, [M64, M64 - 1, 250, 65535, 0], [27, 27, 28, 28, 36]),
    ]):
        h = bytes(rng.getrandbits(8) for _ in range(32))
        for i in range(count):
            n += 1
            pubkey = bytes(rng.getrandbits(8) for _ in range(64))
            signer = keccak256(pubkey)[12:]
            sig = bytes(rng.getrandbits(8) for _ in range(64)) + bytes([vs[i]])
            dig = keccak256(preimage(signer, words, h))
            rows.append("\t".join([
                "p%04d" % n, str(cert), signer.hex(), pubkey.hex(), sig.hex()]
                + ["%x" % w for w in words]
                + [h.hex(), dig.hex(), str(recid_of(vs[i])), sig[0:32][::-1].hex(), sig[32:64][::-1].hex()]))
    write(out, "cases-primitives.tsv", rows)


def write(out, name, rows):
    with open(os.path.join(out, name), "w", newline="\n") as f:
        f.write("\n".join(rows) + "\n")


main()
