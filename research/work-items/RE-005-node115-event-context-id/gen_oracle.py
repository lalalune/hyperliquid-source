#!/usr/bin/env python3
"""Generate the expected-value corpus for node #115 `0x421dc00` (event context id).

The corpus is written before the Rust crate and is derived from public
specifications, not from the Rust code:

* Keccak-f[1600] constants and rotation offsets come from the FIPS 202
  construction rules (LFSR and triangular offsets), not from a copied table.
* The sponge is checked against `hashlib.sha3_256` (same permutation, pad 0x06,
  lengths 0..300 so several blocks are covered) and against published
  Keccak-256 vectors (pad 0x01).
* MessagePack bytes follow the public format specification and are checked
  against the specification's own examples.
* ABI bytes are three big-endian 32-byte words (Solidity `abi.encode` of three
  uint256 values).

What this does NOT make independent: the mode/threshold rules, the arithmetic
constants and the final overlay rule are this author's reading of the node
bytes (see README). Here they are written in a different notation from the
Rust crate (half-open ranges, `bit_length`, space left in the 32-byte buffer),
so a transcription slip in either place shows up as a mismatch.

Usage: gen_oracle.py --outdir NEW_DIRECTORY   (refuses existing paths)
       gen_oracle.py --selftest               (checks only, writes nothing)
"""
import argparse
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

from tool_common import fresh_outdir

M64 = (1 << 64) - 1
U64_MAX = M64
K = 0xF1357AEA2E62A9C5
SEEDS = (0x89ABD75173154E28, 0xEA62407FF1EA5BB8, 0xB1825C50E63CE358, 0x78C3727A71762F98)


# ---------------------------------------------------------------- Keccak (FIPS 202)
def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def _round_constants():
    def rc_bit(t):
        t %= 255
        if t == 0:
            return 1
        r = 1
        for _ in range(t):
            r <<= 1
            if r & 0x100:
                r ^= 0x171
        return r & 1

    table = []
    for ir in range(24):
        value = 0
        for j in range(7):
            if rc_bit(j + 7 * ir):
                value |= 1 << ((1 << j) - 1)
        table.append(value)
    return table


def _rho_offsets():
    offsets = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        offsets[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


RC = _round_constants()
RHO = _rho_offsets()


def _f1600(a):
    for rc in RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], RHO[(x, y)])
        a = [b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]) for y in range(5) for x in range(5)]
        a[0] ^= rc
    return a


def sponge256(message, pad, rate=136):
    data = bytearray(message)
    data.append(pad)
    while len(data) % rate:
        data.append(0)
    data[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(data), rate):
        block = data[start:start + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _f1600(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def keccak256(message):
    return sponge256(message, 0x01)


# ------------------------------------------------------------ MessagePack (public spec)
def mp_uint(n):
    assert 0 <= n <= U64_MAX
    if n < 0x80:
        return bytes([n])
    for marker, width in ((0xCC, 1), (0xCD, 2), (0xCE, 4), (0xCF, 8)):
        if n < 1 << (8 * width):
            return bytes([marker]) + n.to_bytes(width, "big")
    raise AssertionError


def mp_array3(items):
    assert len(items) == 3
    return bytes([0x90 | 3]) + b"".join(mp_uint(v) for v in items)


def abi3(items):
    return b"".join(v.to_bytes(32, "big") for v in items)


# --------------------------------------------------------------------- the flow
def source(mode, a):
    """Half-open ranges: [0, abi_end) ABI, [abi_end, mp_end) MessagePack, rest arithmetic."""
    if mode < 2:
        return "arith"
    abi_end, mp_end = (0x0DF59BC0, 0x19067A35) if mode == 2 else (0x0D377BE1, 0x2A166DE9)
    return "abi" if a < abi_end else "msgpack" if a < mp_end else "arith"


def arith_bytes(a, b, c):
    s = (((a * K + b) & M64) * K) & M64
    out = b""
    for seed in SEEDS:
        h = ((((seed * K) & M64) + c + s) & M64) * K & M64
        out += _rol(h, 20).to_bytes(8, "big")
    return out


def length_prefixed(v):
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    return bytes([len(raw)]) + raw


def context(mode, a, b, c):
    src = source(mode, a)
    if src == "arith":
        pre, base = b"", arith_bytes(a, b, c)
    else:
        pre = abi3((a, b, c)) if src == "abi" else mp_array3((a, b, c))
        base = keccak256(pre)
    buf = bytearray(base)
    pos = 10
    for v in (a, b):
        piece = length_prefixed(v)
        buf[pos:pos + len(piece)] = piece
        pos += len(piece)
    piece = length_prefixed(c)
    if pos + len(piece) <= 32:
        buf[pos:pos + len(piece)] = piece
    return src, pre, base, bytes(buf)


# ------------------------------------------------------------------------ checks
KECCAK_VECTORS = (
    # Published Keccak-256 (original padding) vectors.
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"The quick brown fox jumps over the lazy dog",
     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
    (b"The quick brown fox jumps over the lazy dog.",
     "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"),
    # Ethereum function selector hash, widely published.
    (b"transfer(address,uint256)", "a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b"),
)


def selftest():
    for message, expected in KECCAK_VECTORS:
        assert keccak256(message).hex() == expected, message
    for length in (0, 1, 3, 55, 135, 136, 137, 271, 272, 300):
        message = bytes((7 * i + length) & 0xFF for i in range(length))
        assert sponge256(message, 0x06) == hashlib.sha3_256(message).digest(), length
    for value, expected in ((0, "00"), (127, "7f"), (128, "cc80"), (255, "ccff"), (256, "cd0100"),
                            (65535, "cdffff"), (65536, "ce00010000"), (0xFFFFFFFF, "ceffffffff"),
                            (1 << 32, "cf0000000100000000"), (U64_MAX, "cfffffffffffffffff")):
        assert mp_uint(value).hex() == expected, value
    assert mp_array3((1, 2, 3)) == bytes([0x93, 1, 2, 3])
    assert abi3((1, 2, 3)) == bytes(31) + b"\x01" + bytes(31) + b"\x02" + bytes(31) + b"\x03"
    assert len(RC) == 24 and RC[0] == 1 and RC[23] == 0x8000000080008008 and RC[1] == 0x8082


# ------------------------------------------------------------------- the corpus
WIDTHS = (0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF, 1 << 32, U64_MAX)
EDGE_A = (0, 1, 0x0D377BDF, 0x0D377BE0, 0x0D377BE1, 0x0DF59BBF, 0x0DF59BC0, 0x0DF59BC1, 0x19067A33,
          0x19067A34, 0x19067A35, 0x2A166DE7, 0x2A166DE8, 0x2A166DE9, 1 << 32, U64_MAX)
MODES = (0, 1, 2, 3, 4, 255)


def n_bytes_min(n):
    return 0 if n == 0 else 1 << (8 * (n - 1))


def n_bytes_max(n):
    return (1 << (8 * n)) - 1


def corpus():
    rows = []

    def add(group, mode, a, b, c):
        rows.append((group, mode, a, b, c))

    for mode in MODES:
        for a in EDGE_A:
            add("source-edge", mode, a, 3, 0)
    for a in (0, 0x100, 0x0D377BE0):
        for b in WIDTHS:
            for c in (0, 0x100, U64_MAX):
                add("abi-width", 3, a, b, c)
    for mode, a in ((3, 0x0D377BE1), (3, 0x2A166DE8), (2, 0x0DF59BC0), (2, 0x19067A34)):
        for b in WIDTHS:
            for c in (0, 0x80, 0x10000, U64_MAX):
                add("msgpack-width", mode, a, b, c)
    for a in (0, 0xFF, 0x100, 0x10000, 1 << 32, U64_MAX):
        for b in WIDTHS:
            for c in (0, 0x10000):
                add("arith-width", 1, a, b, c)
    for la in range(4, 9):
        for lb in range(4, 9):
            if la + lb < 12:
                continue
            limit = 19 - la - lb  # longest c that still fits after a and b
            for lc in (limit - 1, limit, limit + 1):
                if 0 <= lc <= 8:
                    for c in {n_bytes_min(lc), n_bytes_max(lc)}:
                        add("overlay-fit", 0, n_bytes_max(la), n_bytes_max(lb), c)
    for mode, a in ((3, 0x100), (3, 0x0D377BE1), (3, 1 << 32), (2, 0x0DF59BC0)):
        b, c = 0x11223344, 0x55
        add("one-field-pair", mode, a, b, c)
        add("one-field-pair", mode ^ 1, a, b, c)
        add("one-field-pair", mode, a + 1, b, c)
        add("one-field-pair", mode, a, b + 1, c)
        add("one-field-pair", mode, a, b, c + 1)
    return rows


def write_corpus(path):
    lines = ["#id\tgroup\tmode\ta\tb\tc\tsource\tpreimage\tbase\tcontext"]
    for i, (group, mode, a, b, c) in enumerate(corpus()):
        src, pre, base, final = context(mode, a, b, c)
        lines.append("\t".join((str(i), group, str(mode), f"{a:x}", f"{b:x}", f"{c:x}", src,
                                pre.hex() or "-", base.hex(), final.hex())))
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return len(lines) - 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--outdir")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    selftest()
    if args.selftest:
        print("selftest ok: 5 Keccak vectors, 10 sha3 length cross-checks, MessagePack/ABI examples")
        return
    if not args.outdir:
        parser.error("--outdir is required unless --selftest")
    out = fresh_outdir(args.outdir)
    here = Path(__file__).resolve()
    cases = out / "cases.tsv"
    count = write_corpus(cases)
    (out / "ORACLE_FROZEN.txt").write_text(
        "oracle frozen before the Rust crate existed\n"
        f"utc: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"gen_oracle.py sha256: {hashlib.sha256(here.read_bytes()).hexdigest()}\n"
        f"cases.tsv sha256: {hashlib.sha256(cases.read_bytes()).hexdigest()}\n"
        f"rows: {count}\n"
        "self-checks passed before writing: 5 Keccak-256 vectors, 10 sha3_256 length cross-checks,\n"
        "10 MessagePack format examples, ABI word layout\n",
        encoding="ascii")
    print(f"wrote {count} rows to {out}")


if __name__ == "__main__":
    sys.exit(main())
