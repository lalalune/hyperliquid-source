#!/usr/bin/env python3
"""Finite mathematical consequences, not captured execution or an ISA model."""
import itertools
import json

U64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def split_plan(index):
    if index < 5:
        return 4, False, index
    if index == 5:
        return 5, False, 5
    if index == 6:
        return 5, True, 0
    return 6, True, index - 7


def stream_fold(records, guard, initial, fallback):
    samples = {k: list(v) for k, v in initial.items()}
    fallbacks = dict(fallback)
    processed = 0
    for key, tag, value in records:
        if tag == 2:
            break
        processed += 1
        if tag & 1:
            if guard == 3:
                fallbacks[key] = value
        else:
            samples.setdefault(key, []).append(value)
    return samples, fallbacks, processed


def stream_oracle(records, guard, initial, fallback):
    stop = next((i for i, row in enumerate(records) if row[1] == 2), len(records))
    prefix = records[:stop]
    samples = {}
    for key in set(initial) | {k for k, t, _ in prefix if t % 2 == 0}:
        samples[key] = list(initial.get(key, ())) + [v for k, t, v in prefix if k == key and t % 2 == 0]
    fallbacks = dict(fallback)
    if guard == 3:
        for key in {k for k, t, _ in prefix if t % 2 == 1}:
            fallbacks[key] = next(v for k, t, v in reversed(prefix) if k == key and t % 2 == 1)
    return samples, fallbacks, stop


def check():
    split_cases = []
    for index in range(12):
        # Pair tokens include independent 24-byte patterns: values are not numbers
        # to convert, and the incoming pair cannot accidentally equal an old pivot.
        old = [(2 * i + 2, bytes([i + 1]) * 24) for i in range(11)]
        incoming = (2 * index + 1, bytes.fromhex('000000000000000008000000000000000000000000000000'))
        pivot, right, local = split_plan(index)
        left_pairs, right_pairs = old[:pivot], old[pivot + 1:]
        selected = right_pairs if right else left_pairs
        selected[local:local] = [incoming]
        expected = old[:index] + [incoming] + old[index:]
        require(left_pairs + [old[pivot]] + right_pairs == expected, 'split pair conservation')
        require((len(left_pairs), len(right_pairs)) in ((5, 6), (6, 5)), 'split child occupancy')
        require(selected[local] == incoming and old[pivot] != incoming, 'selected handle belongs to inserted pair')
        # The incoming right edge is spliced at index+1. Partition by old pivot
        # first, then insert into the selected node: the same 13 edges result.
        edges = list(range(12))
        left_edges, right_edges = edges[:pivot + 1], edges[pivot + 1:]
        target = right_edges if right else left_edges
        target[local + 1:local + 1] = ['incoming-right']
        require(left_edges + right_edges == edges[:index + 1] + ['incoming-right'] + edges[index + 1:],
                'split edge conservation')
        require(len(left_edges) == len(left_pairs) + 1 and len(right_edges) == len(right_pairs) + 1,
                'split edge cardinality')
        split_cases.append({'index': index, 'pivot': pivot, 'right': right, 'local': local,
                            'left_length': len(left_pairs), 'right_length': len(right_pairs)})

    shifts = 0
    for count in range(11):
        for index in range(count + 1):
            old = [(i, bytes([i + 1]) * 24) for i in range(count)]
            # Snapshot slicing models the explicit memmove contract only; it
            # neither decodes nor interprets any captured instruction.
            shifted = list(old) + [None]
            shifted[index + 1:count + 1] = old[index:count]
            shifted[index] = ('new', b'\xff' * 24)
            require(shifted == old[:index] + [('new', b'\xff' * 24)] + old[index:], 'nonfull insertion')
            for stride in (8, 24):
                require(stride * (count - index) <= 10 * stride, 'bounded move byte length')
            shifts += 1

    links = 0
    for count in range(11):
        for index in range(count + 1):
            first = index + 1
            last_exclusive = count + 2
            remaining = last_exclusive - first
            remainder = remaining % 4
            visited = list(range(first, first + remainder))
            for base in range(first + remainder, last_exclusive, 4):
                visited.extend(range(base, base + 4))
            require(visited == list(range(first, last_exclusive)), 'unrolled child-index coverage')
            links += 1

    # All-u64 reciprocal proof by an exact global bound; samples are supplemental.
    multiplier = 0x346dc5d63886594b
    require(multiplier * 10000 == (1 << 75) + 432, 'reciprocal identity')
    require(U64 * 432 < (1 << 75), 'all-u64 reciprocal error bound')
    keys = sorted({0, 1, 9999, 10000, 10001, U64, U64 - 1,
                   *[q * 10000 + r for q in (1, 17, 1 << 31, 1 << 48)
                     for r in (0, 1, 9998, 9999) if q * 10000 + r <= U64]})
    for key in keys:
        quotient = key * multiplier // (1 << 75)
        require(quotient == key // 10000 and key - quotient * 10000 == key % 10000, 'remainder consequence')

    alphabet = [(key, tag, value) for key in (0, 7, U64)
                for tag in (0, 1, 2, 3, 4, 1 << 63, U64)
                for value in (0, 0x8000000000000000, 0x7ff8000000000042)]
    sequences = [[], *[[r] for r in alphabet], *[list(x) for x in itertools.product(alphabet, repeat=2)]]
    sequences += [[(7, 0, 1), (7, 1, 2), (7, 0, 3), (7, 1, 4)],
                  [(7, 0, 1), (7, 2, 2), (7, 0, 3), (U64, 1, 4)],
                  [(7, 4, 1), (7, 1 << 63, 2), (7, U64, 3)]]
    streams = 0
    for initial in ({}, {7: [0x7ff0000000000001], 9: [U64]}):
        for guard in (0, 1, 2, 3, 255):
            for records in sequences:
                require(stream_fold(records, guard, initial, {9: 17}) ==
                        stream_oracle(records, guard, initial, {9: 17}), 'stream prefix/fold consequence')
                streams += 1

    # Deliberately wrong high-level alternatives differ on independent witnesses.
    mutant_witnesses = {
        'sentinel-after-parity': stream_fold([(7, 2, 99), (7, 0, 100)], 3, {}, {})[0] != {7: [99, 100]},
        'tag-one-only-fallback': stream_fold([(7, 3, 99)], 3, {}, {})[1] == {7: 99},
        'first-fallback-wins': stream_fold([(7, 1, 1), (7, 1, 2)], 3, {}, {})[1] != {7: 1},
        'missing-key-dropped': stream_fold([(7, 0, 99)], 0, {}, {})[0] != {},
        'guard-nonzero': stream_fold([(7, 1, 99)], 1, {}, {})[1] != {7: 99},
        'raw-payload-converted': stream_fold([(7, 0, 0x7ff8000000000042)], 3, {}, {})[0][7][0] == 0x7ff8000000000042,
    }
    require(all(mutant_witnesses.values()), 'alternative consequence not distinguished')
    return {'split_positions': split_cases, 'nonfull_insertions': shifts,
            'child_link_intervals': links, 'reciprocal_boundary_keys': len(keys),
            'stream_cases': streams, 'wrong_alternative_witnesses': mutant_witnesses,
            'limit': 'Exact mathematical identities and contract consequences only; no captured execution, instruction interpreter, native-vs-model output comparison, Rust implementation or ABI equivalence.'}


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
