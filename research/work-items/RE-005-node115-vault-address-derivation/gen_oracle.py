#!/usr/bin/env python3
"""Oracle for the node #115 CreateVault address derivation (RE-005 vault-address packet).

Writes ONLY into a new --outdir (refused if it exists, or lies inside this packet or the
crate). Never opens any repository file for writing and never reads the Rust sources.

Two pieces are written here from public specifications, without library help:
  * a MessagePack encoder (https://github.com/msgpack/msgpack/blob/master/spec.md),
    shortest-form integers and str8/16/32 strings;
  * Keccak-256 (Keccak team specification summary, https://keccak.team/keccak_specs_summary.html):
    lane state as a 5x5 matrix, rho offsets and round constants derived from their defining
    recurrences (no copied tables), whole-message padding, then block absorption.
What #115 does with those bytes (field order, widths, which digest bytes, which request field is
left out, the two checks of the caller) is NOT taken from the standards: it comes from the pinned
instruction evidence in README.md and `pins.json`. The numeric bound of the caller's amount check
is recomputed here as floor((2**64 - 1) / 20) and compared with the constant read from the binary.
"""
import argparse
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, '..', '..', '..'))
CRATE = os.path.join(ROOT, 'src', 'node115-vault-address')
MASK = (1 << 64) - 1
NAME_LIMIT = 100                       # caller 0x2bdd3b0 rejects name length >= 0x65 before deriving
AMOUNT_BOUND = (1 << 64) // 20         # 0x0ccccccccccccccc: caller rejects initialUsd / maxUsdcFee >= this
assert AMOUNT_BOUND == 0x0ccccccccccccccc


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
    assert len(items) < 16
    return bytes([0x90 | len(items)]) + b''.join(items)


def mp_map(pairs):
    assert len(pairs) < 16
    return bytes([0x80 | len(pairs)]) + b''.join(k + v for k, v in pairs)


# ---------------------------------------------------------------- the vault address model
def creator_text(creator):
    return b'0x' + creator.hex().encode()          # lowercase hex, 40 digits


def request_map(name, desc, usd, nonce, order=('name', 'description', 'initialUsd', 'nonce')):
    vals = {'name': mp_str(name), 'description': mp_str(desc), 'initialUsd': mp_uint(usd), 'nonce': mp_uint(nonce)}
    return mp_map([(mp_str(k.encode()), vals[k]) for k in order])


def preimage(creator, name, desc, usd, nonce):
    return mp_array([mp_str(creator_text(creator)), request_map(name, desc, usd, nonce)])


def derive(creator, name, desc, usd, nonce):
    pre = preimage(creator, name, desc, usd, nonce)
    d = keccak256(pre)
    return pre, d, d[:20]


def caller_outcome(name, usd, fee):
    """What caller 0x2bdd3b0 decides before it goes on to its state probes (not modelled here)."""
    if len(name) > NAME_LIMIT:
        return 'name_too_long'                     # tag 0x158, before the address is derived
    if usd >= AMOUNT_BOUND:
        return 'amount_too_large:%d' % usd         # tag 0x154, after the address is derived
    if fee is not None and fee >= AMOUNT_BOUND:
        return 'amount_too_large:%d' % fee
    return 'ok'


# Deliberately wrong variants: each must give a different address from #115's.
def wrong_variants(creator, name, desc, usd, nonce, fee):
    good = preimage(creator, name, desc, usd, nonce)
    d = keccak256(good)
    cre = mp_str(creator_text(creator))
    plain = request_map(name, desc, usd, nonce)
    fee_pair = (mp_str(b'maxUsdcFee'), mp_uint(0 if fee is None else fee))
    five = mp_map([(mp_str(k.encode()), v) for k, v in (
        ('name', mp_str(name)), ('description', mp_str(desc)), ('initialUsd', mp_uint(usd)), ('nonce', mp_uint(nonce)))]
        + [fee_pair])

    def fixed(n):
        return b'\xcf' + n.to_bytes(8, 'big')
    out = {
        'creator_uppercase_hex': keccak256(mp_array([mp_str(b'0x' + creator.hex().upper().encode()), plain]))[:20],
        'creator_without_0x': keccak256(mp_array([mp_str(creator.hex().encode()), plain]))[:20],
        'creator_as_bin8': keccak256(mp_array([b'\xc4\x14' + creator, plain]))[:20],
        'map_order_nonce_before_usd': keccak256(mp_array([cre, request_map(name, desc, usd, nonce,
                                                ('name', 'description', 'nonce', 'initialUsd'))]))[:20],
        'map_order_description_first': keccak256(mp_array([cre, request_map(name, desc, usd, nonce,
                                                ('description', 'name', 'initialUsd', 'nonce'))]))[:20],
        'fee_key_always_included': keccak256(mp_array([cre, five]))[:20],
        'fields_as_positional_array': keccak256(mp_array([cre, mp_array([mp_str(name), mp_str(desc), mp_uint(usd), mp_uint(nonce)])]))[:20],
        'no_outer_array': keccak256(cre + plain)[:20],
        'request_map_only_no_creator': keccak256(plain)[:20],
        'digest_tail20': d[12:],
        'sha3_padding': hashlib.sha3_256(good).digest()[:20],
        'full_width_unsigned': keccak256(mp_array([cre, mp_map([(mp_str(b'name'), mp_str(name)), (mp_str(b'description'), mp_str(desc)),
                                                                 (mp_str(b'initialUsd'), fixed(usd)), (mp_str(b'nonce'), fixed(nonce))])]))[:20],
    }
    if fee is not None:
        out['fee_key_included_when_present'] = keccak256(mp_array([cre, five]))[:20]
    return out


# ---------------------------------------------------------------- corpus
def blob(spec):
    if spec.startswith('hex:'):
        return bytes.fromhex(spec[4:])
    assert spec.startswith('rep:')
    byte, count = spec[4:].split('*')
    return bytes.fromhex(byte) * int(count)


def spec_of(raw):
    if len(raw) > 64 and len(set(raw)) == 1:
        return 'rep:%02x*%d' % (raw[0], len(raw))
    return 'hex:' + raw.hex()


Z20 = bytes(20)
BASE = (bytes(range(0x10, 0x24)), b'vault', b'my vault', 1000, 7)      # creator contains hex letters a-f


def build_cases():
    cases, seen_requests = [], set()

    def add(group, creator=Z20, name=b'v', desc=b'', usd=1, nonce=2, fee=None):
        key = (creator, name, desc, usd, nonce, fee)
        if key not in seen_requests:           # a request that an earlier group already covers is kept once
            seen_requests.add(key)
            cases.append((group, creator, name, desc, usd, nonce, fee))

    add('anchor')
    widths = (0, 1, 126, 127, 128, 129, 254, 255, 256, 257, 65534, 65535, 65536, 65537,
              (1 << 32) - 1, 1 << 32, (1 << 32) + 1, AMOUNT_BOUND - 1, AMOUNT_BOUND, AMOUNT_BOUND + 1, 1 << 63, (1 << 64) - 1)
    for v in widths:
        add('initial-usd', usd=v)
    for v in widths:
        add('nonce', nonce=v)
    creators = [bytes([0xff] * 20), bytes([0xab, 0xcd, 0xef] + [0] * 17), bytes(range(0x01, 0x15)),
                bytes([0x00] * 19 + [0x01]), bytes([0x80] + [0] * 19), bytes.fromhex('0123456789abcdef0123456789abcdef01234567'),
                bytes.fromhex('deadbeefdeadbeefdeadbeefdeadbeefdeadbeef')]
    for c in creators:
        add('creator', creator=c)
    # name lengths: up to 100 pass the caller; 101.. are only reachable through the entry function itself
    for n in (0, 1, 2, 30, 31, 32, 33, 99, 100, 101, 102, 254, 255, 256, 257, 65535, 65536, 65537):
        add('name-length', name=b'n' * n)
    for n in (0, 1, 2, 30, 31, 32, 33, 254, 255, 256, 257, 4095, 65534, 65535, 65536, 65537, 200000):
        add('description-length', desc=b'd' * n)
    for raw in ('é'.encode(), '日本語'.encode(), '😀'.encode(), b'a\x00b', 'é'.encode() * 15 + b'a', 'é'.encode() * 16):
        add('utf8-name', name=raw)
        add('utf8-description', desc=raw)
    # preimage length around the Keccak-256 rate multiples (136, 272, 408), solved through the description length
    for target in (134, 135, 136, 137, 138, 270, 271, 272, 273, 406, 407, 408, 409):
        for hdr in (1, 2):
            n = target - 84 - hdr              # 84 = everything but the description encoding for name 'v', usd 1, nonce 2
            if n >= 0 and (n < 32) == (hdr == 1) and (n < 256):
                add('block-boundary', desc=b'q' * n)
    # the caller's checks, and the order of the two
    add('caller-check', name=b'x' * 100)
    add('caller-check', name=b'x' * 101)
    add('caller-check', name=b'x' * 101, usd=AMOUNT_BOUND)                  # name check wins, before derivation
    add('caller-check', usd=AMOUNT_BOUND - 1)
    add('caller-check', usd=AMOUNT_BOUND)
    add('caller-check', usd=AMOUNT_BOUND, fee=AMOUNT_BOUND + 5)             # initialUsd is reported first
    add('caller-check', fee=AMOUNT_BOUND - 1)
    add('caller-check', fee=AMOUNT_BOUND)
    add('caller-check', fee=(1 << 64) - 1)
    # fields that must NOT change the address: maxUsdcFee absent / zero / any value
    for fee in (None, 0, 1, 127, 128, 255, 256, 65536, 1 << 32, AMOUNT_BOUND - 1, AMOUNT_BOUND, (1 << 64) - 1):
        add('fee-invariance', creator=BASE[0], name=BASE[1], desc=BASE[2], usd=BASE[3], nonce=BASE[4], fee=fee)
    # one field changed against a base: every address must differ from the base address and from each other
    c0, n0, d0, u0, k0 = BASE
    add('pair-base', c0, n0, d0, u0, k0)
    add('pair-creator-last-bit', c0[:-1] + bytes([c0[-1] ^ 1]), n0, d0, u0, k0)
    add('pair-creator-first-byte', bytes([c0[0] ^ 0x80]) + c0[1:], n0, d0, u0, k0)
    add('pair-name', c0, b'vaulT', d0, u0, k0)
    add('pair-name', c0, b'vault ', d0, u0, k0)
    add('pair-description', c0, n0, b'my vaulT', u0, k0)
    add('pair-description', c0, n0, b'', u0, k0)
    add('pair-initial-usd', c0, n0, d0, u0 + 1, k0)
    add('pair-nonce', c0, n0, d0, u0, k0 + 1)
    add('pair-swap-name-description', c0, d0, n0, u0, k0)
    add('pair-swap-usd-nonce', c0, n0, d0, k0, u0)
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
    # permutation, rate, multi-block absorption and padding mechanics against hashlib SHA3-256
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
        (mp_array([]), '90'), (mp_array([b'\x01', b'\x02']), '920102'), (mp_map([(b'\xa1a', b'\x01')]), '81a16101'),
    ]
    for got, want in spec_examples:
        assert got.hex() == want, (got.hex(), want)
    # anchor recorded by the scout (Node crypto / OpenSSL keccak-256, not re-run by this tool)
    pre, d, addr = derive(Z20, b'v', b'', 1, 2)
    assert pre.hex() == ('92d92a' + (b'0x' + b'0' * 40).hex() + '84a46e616d65a176ab6465736372697074696f6e'
                         'a0aa696e697469616c55736401a56e6f6e636502')
    assert len(pre) == 85
    assert d.hex() == '91378d2649be144c8abfa4d4b7626d5413ceb45ee2038e0a306c1e6cdd4c676c'
    assert addr.hex() == '91378d2649be144c8abfa4d4b7626d5413ceb45e'
    print('oracle selftest ok: 3 keccak vectors, 702 sha3 cross-lengths, %d msgpack spec examples, scout anchor, '
          'amount bound floor(2^64/20) = 0x%x' % (len(spec_examples), AMOUNT_BOUND))


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
    for n, (group, creator, name, desc, usd, nonce, fee) in enumerate(build_cases()):
        pre, d, addr = derive(creator, name, desc, usd, nonce)
        cid = '%s-%03d' % (group, n)
        hexpre = pre.hex() if len(pre) <= 600 else '-'
        rows.append('\t'.join([cid, group, creator.hex(), spec_of(name), spec_of(desc), str(usd), str(nonce),
                               '-' if fee is None else str(fee), caller_outcome(name, usd, fee), str(len(pre)),
                               hashlib.sha256(pre).hexdigest(), hexpre, d.hex(), addr.hex()]))
        # the address must not depend on maxUsdcFee: same request without it gives the same row data
        if fee is None:
            seen.setdefault(addr, []).append(cid)
        if len(pre) <= 600:
            for variant, wrong in sorted(wrong_variants(creator, name, desc, usd, nonce, fee).items()):
                if wrong == addr:
                    # the only legitimate coincidences: a fixed-width unsigned is the minimal form only when both
                    # values need 8 bytes; upper-case hex is the same text when the creator has no digit a-f
                    ok = ((variant == 'full_width_unsigned' and usd >= 1 << 32 and nonce >= 1 << 32) or
                          (variant == 'creator_uppercase_hex' and creator.hex() == creator.hex().upper()))
                    assert ok, (cid, variant)
                    continue
                neg.append('\t'.join([cid, variant, wrong.hex()]))
    # every address distinct, except the fee-invariance rows (same request, only maxUsdcFee varies), which must agree
    assert all(len(v) == 1 for v in seen.values()), ('two cases share an address', [v for v in seen.values() if len(v) > 1])
    inv = {r.split('\t')[13] for r in rows if r.split('\t')[1] == 'fee-invariance'}
    # the base request of the pair group is the fee-invariance request without a fee (kept once, in that group);
    # `seen` (fee-free rows) being collision-free then covers "every one-field-changed address differs from the base"
    assert len(inv) == 1, 'maxUsdcFee changed the address'
    os.makedirs(out)
    header = ('case\tgroup\tcreator\tname\tdescription\tinitialUsd\tnonce\tmaxUsdcFee\tcaller_outcome\t'
              'preimage_len\tpreimage_sha256\tpreimage_hex\tkeccak256\taddress\n')
    write_new(os.path.join(out, 'corpus.tsv'), header + '\n'.join(rows) + '\n')
    write_new(os.path.join(out, 'wrong-variants.tsv'), 'case\tvariant\twrong_address\n' + '\n'.join(neg) + '\n')
    print('wrote %d cases and %d wrong-variant addresses to %s' % (len(rows), len(neg), out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
