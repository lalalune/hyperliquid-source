#!/usr/bin/env python3
"""Independent closed-form expectations for actual affine-table reads."""
import gzip
import struct
from verify_static import PACKET, ROOT, TARGET, encoded, require, sha

MASK = 2 ** 64 - 1
MAX_WORDS = (2 ** 63 - 1) // 8  # Qualified 64-bit Rust slice object limit.
INPUT = struct.Struct('<IIQQQ')  # index, count field, actual length, seed, step
OUTPUT = struct.Struct('<BQBQ')  # required tag/value, sum tag/value


def fixtures():
    rows = set()
    for exponent in range(7):
        n = 2 ** exponent
        for index in [0, 1, 6599, 6600]:
            needed = index + (n - 1) * 6600 + 1
            for seed, step in [(7, 3), (MASK, 0), (MASK - 5, 2 ** 63 + 1)]:
                rows.add((index, exponent, needed, seed, step))
            rows.add((index, exponent, needed - 1, 19, 5))
            rows.add((index, exponent, needed + 1, 23, 7))
        for field in [exponent + 64, exponent + 0x80000000, exponent + 0xffffffc0]:
            rows.add((1, field, 2 + (n - 1) * 6600, MASK - 2, 11))
    for residue in range(64):
        for field in [residue, residue + 64, residue + 0xffffffc0]:
            for index in [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]:
                rows.add((index, field, 0, 7, 3))
    rows = sorted(rows)
    expected, accepted, span_rejected, short = bytearray(), 0, 0, 0
    valid_counts = set()
    for index, field, length, seed, step in rows:
        n = 2 ** (field % 64)
        needed = index + (n - 1) * 6600 + 1
        representable = needed <= MAX_WORDS
        admitted = representable and needed <= length
        # Every actual table word at j is (seed + step*j) mod 2**64.
        # Arithmetic progression formula; no indexed summation or loop model.
        total = (n * seed + step * (n * index + 6600 * n * (n - 1) // 2)) % (2 ** 64)
        expected.extend(OUTPUT.pack(representable, needed if representable else 0,
                                    admitted, total if admitted else 0))
        accepted += admitted
        span_rejected += not representable
        short += representable and not admitted
        if admitted:
            valid_counts.add(n)
    inputs = b''.join(INPUT.pack(*row) for row in rows)
    record = {'target_sha256': TARGET, 'cases': len(rows), 'accepted': accepted,
              'unrepresentable_span': span_rejected, 'short_slice': short,
              'valid_counts': sorted(valid_counts), 'all_count_residues': sorted({r[1] % 64 for r in rows}),
              'maximum_physical_table_words': max(r[2] for r in rows),
              'inputs_sha256': sha(inputs), 'expected_sha256': sha(expected),
              'descriptor_bytes': INPUT.size, 'output_record_bytes': OUTPUT.size,
              'table_value': '(seed + step*position) modulo 2**64',
              'oracle': '(n*seed + step*(n*index + 6600*n*(n-1)/2)) modulo 2**64; unbounded integers',
              'safe_span': 'index + (2**(field%64)-1)*6600 + 1 <= floor((2**63-1)/8)',
              'refusals': 'new safe API results, not claimed target outputs'}
    require(record['all_count_residues'] == list(range(64)), 'missing count residue')
    return inputs, bytes(expected), record


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-strided-array-sum').exists(), 'Rust source must not yet exist')
    inputs, expected, record = fixtures()
    record['rust_source_existed_at_freeze'] = False
    record['oracle_sha256_at_freeze'] = sha((PACKET / 'oracle.py').read_bytes())
    record['static_sha256_at_freeze'] = sha((PACKET / 'static.json').read_bytes())
    for name, raw in [('inputs.bin.gz', inputs), ('expected.bin.gz', expected)]:
        with (PACKET / name).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('xb') as stream:
        stream.write(encoded(record))
    print(encoded(record).decode(), end='')


if __name__ == '__main__':
    main()
