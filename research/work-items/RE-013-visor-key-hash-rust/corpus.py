#!/usr/bin/env python3
"""Independent whole-message mathematical expectations, before production Rust.

No source-library hash, host hash API, captured execution, instruction decoder,
register state, flags, program counter or simulated native memory is used here.
The equations are bound by PROOF.md to the complete actual Visor bodies.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MASK = (1 << 64) - 1
CONSTANTS = (0x736f6d6570736575, 0x646f72616e646f6d,
             0x6c7967656e657261, 0x7465646279746573)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rotate(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK


def permutation(words):
    x0, x1, x2, x3 = words
    a = (x0 + x1) & MASK
    b = rotate(x1, 13) ^ a
    c = (x2 + x3) & MASK
    d = rotate(x3, 16) ^ c
    f = (rotate(a, 32) + d) & MASK
    e = (c + b) & MASK
    return f, rotate(b, 17) ^ e, rotate(e, 32), rotate(d, 21) ^ f


def block(words, message_word):
    a, b, c, d = words
    a, b, c, d = permutation((a, b, c, d ^ message_word))
    return a ^ message_word, b, c, d


def little_word(data):
    return sum(byte * (1 << (8 * index)) for index, byte in enumerate(data))


def expected(seed, data):
    k0, k1 = seed
    require(0 <= k0 <= MASK and 0 <= k1 <= MASK, 'seed range')
    message = data + b'\xff'
    words = tuple(k ^ c for k, c in zip((k0, k1, k0, k1), CONSTANTS, strict=True))
    complete, remainder = divmod(len(message), 8)
    for index in range(complete):
        words = block(words, little_word(message[index * 8:index * 8 + 8]))
    tail = little_word(message[complete * 8:])
    require(tail < (1 << (8 * remainder)), 'tail high bits')
    last = tail | ((len(message) % 256) * (1 << 56))
    words = block(words, last)
    words = words[0], words[1], words[2] ^ 255, words[3]
    for _ in range(3):
        words = permutation(words)
    return words[0] ^ words[1] ^ words[2] ^ words[3]


def seeds():
    values = [(0, 0), (MASK, 0), (0, MASK), (MASK, MASK),
              (0x0123456789abcdef, 0xfedcba9876543210),
              (0xfedcba9876543210, 0x0123456789abcdef),
              (1, 0), (0, 1), (0xaaaaaaaaaaaaaaaa, 0x5555555555555555),
              (0x8000000000000000, 0x7fffffffffffffff)]
    for bit in range(64):
        values += [(1 << bit, 0), (0, 1 << bit), (MASK ^ (1 << bit), MASK),
                   (MASK, MASK ^ (1 << bit))]
    return list(dict.fromkeys(values))


def cases():
    keys = seeds()
    edges = [b'', b'\0', b'\xff', b'a', b'skip-download', b'child-args',
             b'\0\xff\x80\x7f', bytes(range(7)), bytes(range(8)), bytes(range(9)),
             b'\xff' * 7, b'\xff' * 8, b'\0' * 9]
    for seed in keys:
        for data in edges:
            yield 'seed-bits-and-carry-edges', seed, data
    for seed in keys[:10]:
        for byte in range(256):
            yield 'every-single-byte', seed, bytes([byte])
    lengths = sorted(set(range(81)) | {127, 128, 129, 511, 512, 513, 1023, 1024, 1025,
                                      4095, 4096, 4097} | set(range(247, 266)))
    for seed in keys[:6]:
        for length in lengths:
            patterns = [bytes(length), b'\xff' * length,
                        bytes(i % 256 for i in range(length)),
                        bytes(255 - i % 256 for i in range(length)),
                        bytes((i * 73 + (i >> 3) * 19 + 41) % 256 for i in range(length))]
            for data in patterns:
                yield 'block-tail-and-length-byte-boundaries', seed, data
    for seed in keys[:6]:
        for length in (7, 8, 9, 15, 16, 17):
            for bit in range(length * 8):
                data = bytearray(length)
                data[bit // 8] = 1 << (bit % 8)
                yield 'single-message-bit', seed, bytes(data)
    for seed in keys[:6]:
        for text in [b'\xc0\x80', b'\xed\xa0\x80', b'\xf4\x90\x80\x80',
                     b" a\t\0'\"^/", '한글'.encode(), b'key\xff', b'key\xff\xff']:
            yield 'opaque-binary-input-no-text-policy', seed, text


def algebra():
    # Pure quotient/remainder certificates, not execution of the feed body.
    lengths = sorted(set(range(1025)) | {(1 << b) + d for b in range(3, 63) for d in (-1, 0, 1)} |
                     {(1 << 63) - d for d in range(1, 9)})
    count = 0
    for q in range(8):
        for n in lengths:
            if q and n < 8 - q:
                require(q + n < 8, 'partial bound')
            else:
                gap = 0 if q == 0 else 8 - q
                k, remainder = divmod(n - gap, 8)
                prefix = 0 if q == 0 else 1
                require(prefix + k == (q + n) // 8 and remainder == (q + n) % 8, 'word/suffix count')
                if k:
                    require(gap + 8 * (k - 1) < 8 * k <= gap + 8 * k, 'bulk comparison endpoint')
                require(gap + 8 * k + remainder == n, 'complete span consumed')
            count += 1
    basis = 0
    for length in range(8):
        widths = ([4] if length >= 4 else []) + ([2] if length % 4 >= 2 else []) + ([1] if length % 2 else [])
        require(sum(widths) == length, '4/2/1 decomposition')
        for bit in range(8 * length):
            data = bytearray(length)
            data[bit // 8] = 1 << (bit % 8)
            packed, offset = 0, 0
            for width in widths:
                packed |= little_word(data[offset:offset + width]) << (8 * offset)
                offset += width
            require(packed == 1 << bit, 'packing basis')
            basis += 1
    # Cancellation identity follows algebraically for arbitrary words in PROOF;
    # these finite words are additional falsifiers, not a universal test proof.
    vectors = [(0, 0, 0, 0), (MASK, MASK, MASK, MASK)]
    vectors += [(1 << b, MASK ^ (1 << b), b, MASK - b) for b in range(64)]
    for v in vectors:
        a = (v[0] + v[1]) & MASK
        b = rotate(v[1], 13) ^ a
        c = (v[2] + v[3]) & MASK
        d = rotate(v[3], 16) ^ c
        e = (c + b) & MASK
        shortened = rotate(b, 17) ^ e ^ rotate(e, 32) ^ rotate(d, 21)
        full = permutation(v)
        require(shortened == full[0] ^ full[1] ^ full[2] ^ full[3], 'final cancellation')
    return dict(quotient_remainder_rows=count, distinct_lengths=len(lengths),
                little_endian_packing_basis_bits=basis, cancellation_falsifiers=len(vectors),
                scope='Finite arithmetic certificates supporting manual universal proof; no native instruction evaluator.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh corpus output required')
    args.out.mkdir(parents=True)
    seen, categories = set(), Counter()
    inputs, outputs, provenance, witnesses = [], [], [], []
    for category, seed, data in cases():
        key = seed, data
        if key in seen:
            continue
        seen.add(key)
        name = f'c{len(inputs):06d}'
        result = expected(seed, data)
        inputs.append(f'{name}\t{seed[0]:016x}\t{seed[1]:016x}\t' + (data.hex() or '-') + '\n')
        outputs.append(f'{name}\t{result:016x}\n')
        provenance.append(f'{name}\t{category}\n')
        categories[category] += 1
        if seed in seeds()[:2] and data in [b'', b'\0', b'\xff', b'skip-download', b'child-args', bytes(range(7)), bytes(range(8)), bytes(range(9))]:
            witnesses.append(dict(id=name, seed=[hex(x) for x in seed], input_hex=data.hex(), expected_u64=hex(result)))
    streams = []
    for name, lines in [('inputs.tsv.gz', inputs), ('expected.tsv.gz', outputs), ('provenance.tsv.gz', provenance)]:
        raw = ''.join(lines).encode('ascii')
        stored = gzip.compress(raw, mtime=0)
        (args.out / name).write_bytes(stored)
        streams.append(dict(path=name, rows=len(lines), bytes=len(stored), sha256=sha(stored),
                            raw_bytes=len(raw), raw_sha256=sha(raw)))
    result = dict(cases=len(inputs), distinct_seeds=len(seeds()), categories=dict(sorted(categories.items())),
                  streams=streams, algebra=algebra(), witnesses=witnesses,
                  generator_sha256=sha(Path(__file__).read_bytes()),
                  protocol='Opaque case ID,seed0hex16,seed1hex16,inputhex-or-minus; expected ID,u64hex16; TAB fields and LF terminator.',
                  basis='Manual full Visor value proof; direct whole-message mathematical decomposition. No target execution or existing hash library.')
    (args.out / 'corpus.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps(dict(status='PASS: pre-code mathematical corpus', cases=len(inputs),
                          seeds=result['distinct_seeds'], algebra_rows=result['algebra']['quotient_remainder_rows'])))


if __name__ == '__main__':
    main()
