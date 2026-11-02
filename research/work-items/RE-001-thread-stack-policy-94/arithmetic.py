#!/usr/bin/env python3
"""Finite arithmetic lemmas for PROOF.md, not a captured-code interpreter."""
import json
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def verify_arithmetic():
    limit = (1 << 64) - 1
    for byte in range(256):
        require((((byte - 48) & 0xffffffff) <= 9) == (48 <= byte <= 57), 'ASCII digit classification')
    # Every unchecked 1..16 digit prefix fits; no target parser is implemented.
    for digits in range(1, 17):
        require(10 ** digits - 1 <= limit, 'unchecked length bound')
    q, rem = divmod(limit, 10)
    prefixes = (0, 1, q - 1, q, q + 1, limit)
    for prefix in prefixes:
        for digit in range(10):
            product = prefix * 10
            multiplication_overflows = product > limit
            addition_carries = (product & limit) + digit > limit
            accepted = not multiplication_overflows and not addition_carries
            require(accepted == (prefix < q or (prefix == q and digit <= rem)), 'checked digit bound')
    values = list(range(4097)) + [(1 << 63) - 1, 1 << 63, limit - 1, limit]
    for value in values:
        encoded = (value + 1) & limit
        require((encoded == 0) == (value == limit), 'cache sentinel collision')
        if encoded:
            require(encoded - 1 == value, 'cache inverse')
    # Decimal boundary expectations use Python's arbitrary precision, not an
    # instruction evaluator. The static proof connects them to the byte loops.
    decimals = ('0', '0000', '9999999999999999', '10000000000000000',
                '18446744073709551614', '18446744073709551615',
                '18446744073709551616', '99999999999999999999', '0' * 32 + '1')
    boundaries = [{'digits': text, 'fits_u64': int(text) <= limit,
                   'encoded_cache': hex((int(text) + 1) & limit) if int(text) <= limit else None}
                  for text in decimals]
    return {'byte_classifier_cases': 256, 'unchecked_digit_lengths': 16,
            'checked_prefix_digit_pairs': len(prefixes) * 10,
            'cache_values_checked': len(values), 'decimal_boundaries': boundaries,
            'scope': 'Arithmetic lemmas supporting the static proof; no target execution, emulation, parser implementation or runtime-equivalence claim'}


if __name__ == '__main__':
    result = verify_arithmetic()
    require(result == json.loads(Path(__file__).with_suffix('.json').read_text()), 'arithmetic record drift')
    print(json.dumps(result, indent=2))
