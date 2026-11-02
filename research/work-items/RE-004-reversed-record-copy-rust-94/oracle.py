#!/usr/bin/env python3
"""Frozen byte-provenance composition, independent of Rust block copies."""
import gzip
import struct
from verify_static import PACKET, ROOT, TARGET, encoded, require, sha

SIZE = 256
MAX = 2 ** 64 - 1
INPUT = struct.Struct('<QQQQQ')  # source, destination, available length, seed, pattern
OUTPUT = struct.Struct('<BQ')  # admission tag, destination-offset projection of RAX


def initial(seed, pattern):
    if pattern == 0:
        return bytes((position + seed) % 256 for position in range(SIZE))
    if pattern == 1:
        return bytes([seed % 256]) * SIZE
    require(pattern == 2, 'unknown fixture pattern')
    return bytes(128 if position == seed else 0 for position in range(SIZE))


def provenance(source, destination):
    # Each expression pulls an output byte back through earlier writes. It
    # never performs writes, SIMD operations or captured-instruction evaluation.
    intervals = [(destination + 16, source + 48, 4, False),
                 (destination, source + 32, 16, False),
                 (destination + 20, source + 16, 16, True),
                 (destination + 36, source, 16, True)]
    def origin(position, before):
        for stage in range(before - 1, -1, -1):
            write, read, width, reverse = intervals[stage]
            if write <= position < write + width:
                offset = position - write
                return origin(read + (width - 1 - offset if reverse else offset), stage)
        return position
    return bytes(origin(position, len(intervals)) for position in range(SIZE))


def fixtures():
    cases = set()
    deltas = list(range(-52, 53)) + [-80, 80]
    for phase in range(16):
        for delta in deltas:
            cases.add((80 + phase, 80 + phase + delta, SIZE, 0, 0))
    for delta in deltas:
        for seed in [128, 255]:
            cases.add((80, 80 + delta, SIZE, seed, 0))
    for value in range(256):
        cases.add((80, 0, SIZE, value, 1))
    for delta in [-51, -16, 0, 1, 16, 51]:
        for position in range(80, 132):
            cases.add((80, 80 + delta, SIZE, position, 2))
    for source in [0, 1, 16, 52, 80, 204]:
        for destination in [0, 1, 16, 52, 80, 204]:
            needed = max(source, destination) + 52
            for length in [0, 51, 52, 53, needed - 1, needed, 255, 256]:
                cases.add((source, destination, length, 17, 0))
    for huge in [MAX, MAX - 1, MAX - 51, MAX - 52, MAX - 53, 2 ** 63, 2 ** 32]:
        cases.add((huge, 0, SIZE, 23, 0)); cases.add((0, huge, SIZE, 23, 0))
    for index in range(256):
        raw = bytes.fromhex(sha(f'reversed-record94:{index}'.encode()))
        cases.add((raw[0] % 205, raw[1] % 205, SIZE, raw[2], 0))
    cases = sorted(cases)
    outputs, admitted, overlap = bytearray(), 0, 0
    overlap_deltas, source_alignments = set(), set()
    for source, destination, length, seed, pattern in cases:
        data = initial(seed, pattern)
        # Unbounded inequalities, not wrapping/checked usize arithmetic.
        valid = source + 52 <= length and destination + 52 <= length
        if valid:
            data = bytes(data[index] for index in provenance(source, destination))
            admitted += 1
            source_alignments.add(source % 16)
            if abs(destination - source) < 52:
                overlap += 1; overlap_deltas.add(destination - source)
        outputs.extend(OUTPUT.pack(valid, destination if valid else 0)); outputs.extend(data)
    inputs = b''.join(INPUT.pack(*case) for case in cases)
    maps = b''.join(struct.pack('<h', delta) + provenance(80, 80 + delta) for delta in deltas)
    require(overlap_deltas == set(range(-51, 52)), 'missing overlap displacement')
    require(source_alignments == set(range(16)), 'missing alignment phase')
    record = {'target_sha256': TARGET, 'cases': len(cases), 'admitted': admitted,
              'refused_without_changes': len(cases) - admitted, 'overlap_cases': overlap,
              'all_overlap_deltas': sorted(overlap_deltas), 'source_alignment_phases': sorted(source_alignments),
              'constant_byte_values': 256, 'arena_bytes': SIZE, 'input_record_bytes': INPUT.size,
              'output_record_bytes': OUTPUT.size + SIZE, 'inputs_sha256': sha(inputs),
              'expected_sha256': sha(outputs), 'provenance_maps_sha256': sha(maps),
              'method': 'recursive preimages of four interval writes; evaluate initial bytes only',
              'refusal': 'new safe range refusal, with entire backing arena unchanged',
              'return_projection': 'Some(destination offset) represents original RAX=arena base+destination'}
    return inputs, bytes(outputs), maps, record


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'], 'only --freeze is supported')
    require(not (ROOT / 'src/node94-reversed-record-copy').exists(), 'freeze must precede Rust')
    inputs, expected, maps, record = fixtures()
    record['rust_source_existed_at_freeze'] = False
    record['oracle_sha256_at_freeze'] = sha((PACKET / 'oracle.py').read_bytes())
    record['static_sha256_at_freeze'] = sha((PACKET / 'static.json').read_bytes())
    for name, raw in [('inputs.bin.gz', inputs), ('expected.bin.gz', expected), ('provenance-maps.bin.gz', maps)]:
        with (PACKET / name).open('xb') as stream:
            stream.write(gzip.compress(raw, mtime=0))
    with (PACKET / 'frozen.json').open('xb') as stream:
        stream.write(encoded(record))
    print(encoded({k: v for k, v in record.items() if k not in ['all_overlap_deltas', 'source_alignment_phases']}).decode(), end='')


if __name__ == '__main__':
    main()
