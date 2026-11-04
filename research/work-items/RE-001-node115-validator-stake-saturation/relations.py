#!/usr/bin/env python3
"""Algebraic checks of extracted local relations; does not execute/emulate the ELF."""
import hashlib
import itertools
import json
from pathlib import Path
import verify

MAX = (1 << 64) - 1
SITES = {'keyed': 0x4e44c77, 'flat': 0x4e40738, 'tree': 0x4e40796}


def carry_add(a, b, carry_select=True):
    """Unsigned ADD carry and the observed final CMOVB (or one counterfactual)."""
    value = a + b
    return MAX if carry_select and value > MAX else value & MAX


def fold(values, carry_select=True):
    acc = 0
    for value in values:
        if not 0 <= value <= MAX:
            raise ValueError('weight outside u64')
        acc = carry_add(acc, value, carry_select)
    return acc


def wide_predicate(selected, all_weights):
    left_low = (all_weights << 1) & MAX
    left_high = all_weights >> 63
    product = 3 * selected
    right_low, right_high = product & MAX, product >> 64
    borrow = int(left_low < right_low)
    return left_high < right_high + borrow


def spans(capacity, head, length):
    """Valid flat representation only; returns index spans, not raw pointers."""
    if not (0 < capacity < 1 << 63 and 0 <= head < 2 * capacity and 0 <= length <= capacity):
        raise ValueError('outside the declared flat-container domain')
    if length == 0:
        return ((0, 0), (0, 0))
    start = head - capacity if head >= capacity else head
    available = capacity - start
    if length > available:
        return ((start, capacity), (0, length - available))
    return ((start, start + length), (0, 0))


def flat_lookup_weight(capacity, data, head, length, status, index):
    """Post-lookup branch only: helper semantics are an explicit input boundary."""
    if status & 1 or index >= length:
        return None
    slot = head + index
    if slot >= capacity:
        slot -= capacity
    return data + 32 * slot + 24


def extracted_saturation(data, name):
    image = verify.Image(data)
    raw = image.get(SITES[name], 4)
    expected = {'keyed': bytes.fromhex('480f42d8'), 'flat': bytes.fromhex('480f42c7'),
                'tree': bytes.fromhex('480f42c1')}[name]
    verify.require(raw[:2] == expected[:2] and raw[3:] == expected[3:] and raw[2] in (0x42, 0x43),
                   'unrecognized selected carry instruction')
    return raw[2] == 0x42


def evaluate(data):
    # The caller must authenticate and bind all selected instruction windows first.
    for name in SITES:
        verify.require(extracted_saturation(data, name), 'unexpected authentic carry selection')
    values = (0, 1, 2, MAX // 2, (1 << 63), MAX - 1, MAX)
    digest = hashlib.sha256()
    folds = 0
    for length in range(5):
        for sequence in itertools.product(values, repeat=length):
            observed = fold(sequence)
            expected = min(MAX, sum(sequence))
            verify.require(observed == expected, 'saturating fold relation')
            digest.update((str(sequence) + ':' + str(observed) + '\n').encode())
            folds += 1
    predicates = 0
    pairs = set(itertools.product(values, repeat=2))
    for all_weight in range(1025):
        floor = 2 * all_weight // 3
        for selected in (max(0, floor - 1), floor, floor + 1, floor + 2):
            pairs.add((selected, all_weight))
    for all_weight in (MAX, MAX - 1, 1 << 63, (1 << 63) - 1):
        floor = 2 * all_weight // 3
        for selected in range(floor - 3, floor + 4):
            pairs.add((selected, all_weight))
    for selected, all_weight in sorted(pairs):
        verify.require(wide_predicate(selected, all_weight) == (2 * all_weight < 3 * selected),
                       'unsigned wide predicate')
        predicates += 1
    span_cases = lookup_cases = 0
    for capacity in range(1, 25):
        for head in range(2 * capacity):
            for length in range(capacity + 1):
                ranges = spans(capacity, head, length)
                indices = [i for start, end in ranges for i in range(start, end)]
                verify.require(indices == [(head + i) % capacity for i in range(length)], 'flat span relation')
                span_cases += 1
                # Lookup's head is canonical here. The broader head bound used for
                # total spans is NOT sufficient for one-subtraction index lookup.
                if head < capacity:
                    for status in (0, 1, 2, 3, 254, 255):
                        for index in (0, max(0, length - 1), length, MAX):
                            got = flat_lookup_weight(capacity, 0x1000, head, length, status, index)
                            expected = None if status & 1 or index >= length else 0x1000 + 32 * ((head + index) % capacity) + 24
                            verify.require(got == expected, 'flat lookup guard/index relation')
                            lookup_cases += 1
    controls = []
    for name, va in SITES.items():
        image = verify.Image(data)
        changed = bytearray(data)
        changed[image.off(va) + 2] = 0x43  # final CMOVB -> CMOVAE
        altered = fold((MAX, 1), extracted_saturation(changed, name))
        verify.require(altered == 0 and altered != fold((MAX, 1)), 'carry mutant is not distinguished')
        try:
            verify.observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            controls.append({'site': hex(va), 'role': name, 'change': 'final CMOVB -> CMOVAE',
                             'weights': [str(MAX), '1'], 'original_sum': str(MAX),
                             'counterfactual_sum': str(altered), 'rejected': str(error)})
        else:
            raise ValueError('carry mutant survived the instruction obligations')
    examples = []
    for selected, total in [([], []), ([2], [3]), ([3], [4]), ([MAX], [MAX, MAX]),
                            ([MAX, 1], [MAX, MAX]), ([1, 1, 1], [4])]:
        b, s = fold(selected), fold(total)
        examples.append({'selected_weights': list(map(str, selected)), 'all_weights': list(map(str, total)),
                         'B': str(b), 'S': str(s), 'predicate': wide_predicate(b, s)})
    return {'method': 'finite arithmetic and index checks plus all-domain manual proof; no machine-code execution',
            'fold_cases': folds, 'fold_corpus_sha256': digest.hexdigest(), 'wide_cases': predicates,
            'flat_span_cases': span_cases, 'flat_lookup_cases': lookup_cases,
            'actual_carry_counterfactuals': controls, 'examples': examples,
            'limits': 'Iterator, lookup, tree traversal validity, caller invariants and dynamic behavior are not simulated or proved.'}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.build(data)
    result = evaluate(data)
    text = verify.encoded(result)
    path = verify.PACKET / 'relations.json'
    if args.write:
        path.write_text(text)
    else:
        verify.require(path.read_text() == text, 'relations regeneration mismatch')
    print('PASS: ' + ', '.join(f'{key}={result[key]}' for key in ('fold_cases', 'wide_cases', 'flat_span_cases', 'flat_lookup_cases')))


if __name__ == '__main__':
    main()
