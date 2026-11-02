#!/usr/bin/env python3
"""Finite checks of the static partition/lane argument; no target execution."""
import json
from pathlib import Path


def require(value, message):
    if not value:
        raise ValueError(message)


def verify_coverage():
    # PCMPEQB produces a whole-byte mask. PANDN/PAND/POR select one value.
    for byte in range(256):
        mask = 255 if byte == 32 else 0
        selected = ((~mask & 255) & byte) | (mask & 95)
        require(selected == (95 if byte == 32 else byte), 'lane identity')
    configurations = positions = 0
    for n in range(4097):
        for vector_admitted in (False, True):
            # A partition from the written proof, not an instruction interpreter.
            n32 = (n // 32) * 32 if vector_admitted else 0
            n8 = (n // 8) * 8 if vector_admitted else 0
            residual_end = n8 + n % 4
            blocks = ([(i, i + 32) for i in range(0, n32, 32)] +
                      [(i, i + 8) for i in range(n32, n8, 8)] +
                      [(i, i + 1) for i in range(n8, residual_end)] +
                      [(i, i + 4) for i in range(residual_end, n, 4)])
            cursor = 0
            for start, end in blocks:
                require(start == cursor and start < end <= n, 'partition gap/overlap/bounds')
                cursor = end
            require(cursor == n, 'partition incomplete')
            configurations += 1
            positions += cursor
    # JS after CMP tests SF, not SF xor OF (JL). Include overflow counterexamples.
    edges = (0, 1, 255, 256, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1)
    mask64 = (1 << 64) - 1
    differences = 0
    for left in edges:
        for right in edges:
            wrapped = (left - right) & mask64
            sign = wrapped >> 63
            signed_left = left if left < 1 << 63 else left - (1 << 64)
            signed_right = right if right < 1 << 63 else right - (1 << 64)
            overflow = ((left ^ right) & (left ^ wrapped)) >> 63
            require((sign ^ overflow) == int(signed_left < signed_right), 'SF/OF identity')
            differences += sign != int(signed_left < signed_right)
    require(differences > 0, 'missing overflow counterexample')
    return {'byte_values_checked': 256, 'lengths_checked': 4097,
            'partition_configurations': configurations, 'covered_positions': positions,
            'subtraction_boundary_pairs': len(edges) ** 2,
            'SF_differs_from_signed_less_than_pairs': differences,
            'scope': 'Finite arithmetic checks supporting PROOF.md; no captured execution, emulation or runtime equivalence'}


if __name__ == '__main__':
    result = verify_coverage()
    expected = json.loads(Path(__file__).with_suffix('.json').read_text())
    require(result == expected, 'coverage record drift')
    print(json.dumps(result, indent=2))
