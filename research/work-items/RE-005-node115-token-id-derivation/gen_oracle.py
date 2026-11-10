#!/usr/bin/env python3
"""Oracle for the node #115 TokenSpec token-id derivation (RE-005 token-id packet).

Writes ONLY into a new --outdir (refused if it exists, or lies inside this packet or the
crate). Never opens any repository file for writing and never reads the Rust sources.

Two pieces are written here from public specifications, without library help:
  * a MessagePack encoder (https://github.com/msgpack/msgpack/blob/master/spec.md),
    shortest-form integers and str8/16/32 strings;
  * Keccak-256 (Keccak team specification summary, https://keccak.team/keccak_specs_summary.html):
    lane state as a 5x5 matrix, rho offsets and round constants derived from their defining
    recurrences (no copied tables), whole-message padding, then block absorption.
What #115 does with those bytes (field order, widths, which digest bytes) is NOT taken from
the standards: it comes from the pinned instruction evidence in README.md and `pins.json`.
"""
import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, '..', '..', '..'))
CRATE = os.path.join(ROOT, 'src', 'node115-token-id')
MASK = (1 << 64) - 1


# ---------------------------------------------------------------- Keccak (spec recurrences)
def _rc_bit(t):
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


ROUND_CONSTANTS = [sum(_rc_bit(7 * i + j) << ((1 << j) - 1) for j in range(7)) for i in range(24)]


def _rho_offsets():
    off = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        off[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RHO = _rho_offsets()


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK if n else v


def keccak_f(a):
    """a[x][y], 25 lanes of 64 bits; 24 rounds."""
    for rc in ROUND_CONSTANTS:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], RHO[(x, y)])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) & MASK for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def sponge(msg, rate, delim, outlen):
    padded = bytearray(msg) + bytes([delim])
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            lane = int.from_bytes(padded[off + 8 * i: off + 8 * i + 8], 'little')
            a[i % 5][i // 5] ^= lane
        a = keccak_f(a)
    out = b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(25))
    return out[:outlen]


def keccak256(msg):
    return sponge(msg, 136, 0x01, 32)


# ---------------------------------------------------------------- MessagePack (spec)
def mp_uint(n):
    assert 0 <= n < 1 << 64
    if n < 0x80:
        return bytes([n])
    for limit, marker, width in ((1 << 8, 0xcc, 1), (1 << 16, 0xcd, 2), (1 << 32, 0xce, 4), (1 << 64, 0xcf, 8)):
        if n < limit:
            return bytes([marker]) + n.to_bytes(width, 'big')


def mp_str(raw):
    n = len(raw)
    if n < 32:
        return bytes([0xa0 | n]) + raw
    for limit, marker, width in ((1 << 8, 0xd9, 1), (1 << 16, 0xda, 2), (1 << 32, 0xdb, 4)):
        if n < limit:
            return bytes([marker]) + n.to_bytes(width, 'big') + raw
    raise ValueError('str too long')


def mp_array(items):
    n = len(items)
    assert n < 16
    return bytes([0x90 | n]) + b''.join(items)


def mp_map(pairs):
    n = len(pairs)
    assert n < 16
    return bytes([0x80 | n]) + b''.join(k + v for k, v in pairs)


# ---------------------------------------------------------------- the token id model
def spec_map(name, sz, wei, order=('name', 'szDecimals', 'weiDecimals')):
    vals = {'name': mp_str(name), 'szDecimals': mp_uint(sz), 'weiDecimals': mp_uint(wei)}
    return mp_map([(mp_str(k.encode()), vals[k]) for k in order])


def preimage(name, sz, wei, index):
    return mp_array([spec_map(name, sz, wei), mp_uint(index)])


def derive(name, sz, wei, index):
    pre = preimage(name, sz, wei, index)
    d = keccak256(pre)
    return pre, d, d[:16]


# Deliberately wrong variants: each must produce a different id from #115's for every case.
def wrong_variants(name, sz, wei, index):
    good = preimage(name, sz, wei, index)
    d = keccak256(good)
    return {
        'map_order_swapped': keccak256(mp_array([spec_map(name, sz, wei, ('name', 'weiDecimals', 'szDecimals')), mp_uint(index)]))[:16],
        'array_swapped': keccak256(mp_array([mp_uint(index), spec_map(name, sz, wei)]))[:16],
        # the spec map alone: no outer array AND no index (so the id is the same for every index)
        'map_only_no_index': keccak256(spec_map(name, sz, wei))[:16],
        # map then index written back to back, only the outer array header (0x92) missing
        'map_then_index_no_outer_array': keccak256(spec_map(name, sz, wei) + mp_uint(index))[:16],
        'index_fixed_u64': keccak256(mp_array([spec_map(name, sz, wei), b'\xcf' + index.to_bytes(8, 'big')]))[:16],
        'digest_tail16': d[16:],
        'sha3_256_padding': hashlib.sha3_256(good).digest()[:16],
    }


def name_bytes(spec):
    if spec.startswith('hex:'):
        return bytes.fromhex(spec[4:])
    assert spec.startswith('rep:')
    byte, count = spec[4:].split('*')
    return bytes.fromhex(byte) * int(count)


def name_spec(raw):
    if len(raw) > 64 and len(set(raw)) == 1:
        return 'rep:%02x*%d' % (raw[0], len(raw))
    return 'hex:' + raw.hex()


def build_cases():
    cases = []

    def add(group, raw, sz, wei, index):
        cases.append((group, raw, sz, wei, index))

    add('anchor', b'X', 6, 8, 0)
    for idx in (1, 126, 127, 128, 129, 254, 255, 256, 257, 65534, 65535, 65536, 65537, 99998, 99999,
                (1 << 32) - 1, 1 << 32, (1 << 32) + 1, 1 << 63, (1 << 64) - 1):
        add('index', b'X', 6, 8, idx)
    for sz in (0, 1, 5, 6, 127, 128, 255):
        for wei in (0, 1, 8, 127, 128, 255):
            add('decimals', b'T', sz, wei, 1)
    for n in (0, 1, 2, 30, 31, 32, 33, 254, 255, 256, 257, 65535, 65536, 65537):
        add('name-length', b'a' * n, 6, 8, 3)
    add('name-utf8', 'é'.encode(), 6, 8, 3)
    add('name-utf8', '日本語'.encode(), 6, 8, 3)
    add('name-utf8', '😀'.encode(), 6, 8, 3)
    add('name-utf8', b'a\x00b', 6, 8, 3)
    add('name-utf8', 'é'.encode() * 15 + b'a', 6, 8, 3)   # 31 bytes, 16 chars
    add('name-utf8', 'é'.encode() * 16, 6, 8, 3)           # 32 bytes, 16 chars
    # total preimage length around Keccak-256 rate multiples (136), name length derived
    for target in (134, 135, 136, 137, 138, 270, 271, 272, 273, 406, 407, 408, 409):
        for hdr in (1, 2):
            n = target - 33 - hdr
            if (n < 32) == (hdr == 1) and n >= 0:
                add('block-boundary', b'q' * n, 6, 8, 0)
    # one-field-changed pairs against a base: every id must differ from the base id and each other
    base = (b'ABC', 6, 8, 5)
    add('pair-base', *base)
    add('pair-name', b'ABD', 6, 8, 5)
    add('pair-name', b'abc', 6, 8, 5)
    add('pair-name', b'ABC ', 6, 8, 5)
    add('pair-sz', b'ABC', 7, 8, 5)
    add('pair-wei', b'ABC', 6, 9, 5)
    add('pair-index', b'ABC', 6, 8, 6)
    add('pair-swap-decimals', b'ABC', 8, 6, 5)
    return cases


def write_new(path, text):
    with open(path, 'x', newline='\n') as fh:
        fh.write(text)


def selftest():
    vectors = [
        (b'', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
        (b'abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
        (b'The quick brown fox jumps over the lazy dog', '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'),
    ]
    for msg, want in vectors:
        assert keccak256(msg).hex() == want, ('public keccak256 vector', msg)
    # permutation, rate, multi-block absorption and padding mechanics against the OS hashlib SHA3-256
    # (same sponge, delimiter 0x06): lengths around every rate boundary up to 5 blocks.
    for n in list(range(0, 700)) + [1000, 4096]:
        msg = bytes((i * 7 + n) & 255 for i in range(n))
        assert sponge(msg, 136, 0x06, 32) == hashlib.sha3_256(msg).digest(), n
    spec_examples = [
        (mp_uint(0), '00'), (mp_uint(127), '7f'), (mp_uint(128), 'cc80'), (mp_uint(255), 'ccff'),
        (mp_uint(256), 'cd0100'), (mp_uint(65535), 'cdffff'), (mp_uint(65536), 'ce00010000'),
        (mp_uint((1 << 32) - 1), 'ceffffffff'), (mp_uint(1 << 32), 'cf0000000100000000'),
        (mp_uint((1 << 64) - 1), 'cfffffffffffffffff'),
        (mp_str(b''), 'a0'), (mp_str(b'a' * 31)[:1], 'bf'), (mp_str(b'a' * 32)[:2], 'd920'),
        (mp_str(b'a' * 255)[:2], 'd9ff'), (mp_str(b'a' * 256)[:3], 'da0100'),
        (mp_str(b'a' * 65535)[:3], 'daffff'), (mp_str(b'a' * 65536)[:5], 'db00010000'),
    ]
    for got, want in spec_examples:
        assert got.hex() == want, (got.hex(), want)
    # anchor recorded by the scout (Node crypto / OpenSSL, not re-run by this tool)
    pre, d, tid = derive(b'X', 6, 8, 0)
    assert pre.hex() == '9283a46e616d65a158aa737a446563696d616c7306ab776569446563696d616c730800'
    assert d.hex() == '9058f4586f457c793b70c2871d15c2d5aeaff298b6045f98bd02ee96b891dd40'
    print('oracle selftest ok: 3 keccak vectors, 702 sha3 cross-lengths, %d msgpack spec examples, scout anchor' % len(spec_examples))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--outdir')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    selftest()
    if args.selftest and not args.outdir:
        return 0
    if not args.outdir:
        ap.error('--outdir is required')
    out = os.path.realpath(args.outdir)
    for guarded in (HERE, CRATE):
        if out == guarded or out.startswith(guarded + os.sep):
            sys.exit('refusing --outdir inside the packet or the crate: ' + out)
    if os.path.lexists(args.outdir):
        sys.exit('refusing existing --outdir: ' + out)
    rows, neg, seen = [], [], {}
    for n, (group, raw, sz, wei, index) in enumerate(build_cases()):
        pre, d, tid = derive(raw, sz, wei, index)
        cid = '%s-%03d' % (group, n)
        hexpre = pre.hex() if len(pre) <= 600 else '-'
        rows.append('\t'.join([cid, group, name_spec(raw), str(sz), str(wei), str(index), str(len(pre)),
                               hashlib.sha256(pre).hexdigest(), hexpre, d.hex(), tid.hex()]))
        seen.setdefault(tid, []).append(cid)
        if len(pre) <= 600:
            for variant, wrong in sorted(wrong_variants(raw, sz, wei, index).items()):
                if wrong == tid:
                    # a fixed 8-byte index IS the minimal encoding from 2**32 up; nothing else may coincide
                    assert variant == 'index_fixed_u64' and index >= 1 << 32, (cid, variant)
                    continue
                neg.append('\t'.join([cid, variant, wrong.hex()]))
    assert all(len(v) == 1 for v in seen.values()), ('two cases share a token id', [v for v in seen.values() if len(v) > 1])
    os.makedirs(out)
    header ='case\tgroup\tname\tszDecimals\tweiDecimals\tindex\tpreimage_len\tpreimage_sha256\tpreimage_hex\tkeccak256\ttoken_id\n'
    write_new(os.path.join(out, 'corpus.tsv'), header + '\n'.join(rows) + '\n')
    write_new(os.path.join(out, 'wrong-variants.tsv'), 'case\tvariant\twrong_token_id\n' + '\n'.join(neg) + '\n')
    print('wrote %d cases and %d wrong-variant ids to %s' % (len(rows), len(neg), out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
