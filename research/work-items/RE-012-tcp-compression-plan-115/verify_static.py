#!/usr/bin/env python3
"""Regenerate static facts and check arithmetic consequences, not target execution."""
import argparse
import json
from pathlib import Path
import random
import struct
import collect as evidence


def verify():
    data = evidence.TARGET.read_bytes()
    image = evidence.Image(data)
    record, _ = evidence.collect(data)
    expected = json.loads((evidence.PACKET / 'records.json').read_text())
    evidence.require(record == expected, 'retained evidence differs')

    # Mutate one actual byte in every independent instruction obligation.
    # The narrow obligation check is deliberately tested without the whole-
    # file digest guard, so that a SHA rejection cannot hide a missing pin.
    rejected = []
    for name, (va, raw) in evidence.PINS.items():
        altered = bytearray(data)
        altered[image.offset(va, len(bytes.fromhex(raw))) + len(bytes.fromhex(raw))-1] ^= 1
        try:
            evidence.obligations(evidence.Image(altered))
        except ValueError as error:
            evidence.require(str(error) == 'changed obligation: ' + name, 'wrong negative-control rejection')
            rejected.append(name)
        else:
            raise ValueError('missed instruction mutation: ' + name)
    for altered in [data[:-1], bytes([data[0] ^ 1]) + data[1:]]:
        try:
            evidence.collect(altered)
        except ValueError as error:
            evidence.require(str(error) == 'wrong capture', 'wrong identity rejection')
        else:
            raise ValueError('missed identity mutation')

    # Independent symbolic consequence of the operand-width observation:
    # ((low16(field) - 4000) mod 65536) < 65534 iff field's low16 is
    # neither 3998 nor 3999. Exhaust all low words and representative high
    # words; this is integer algebra, not a target instruction interpreter.
    subtract = struct.unpack('<I', image.read(0x2b7a2e9, 4))[0]
    # The imm8 is at +3 of 66 83 fe fe; sign extension is explicit.
    ceiling = int.from_bytes(image.read(0x2b7a2f6, 1), 'little', signed=True) & 0xffff
    threshold = int.from_bytes(image.read(0x2b7a2e1, 4), 'little')
    evidence.require((subtract, ceiling, threshold) == (0xfffff060, 65534, 1025), 'operand extraction')
    cases = 0
    disabled = []
    for low in range(65536):
        if not ((low + subtract) & 0xffff) < ceiling:
            disabled.append(low)
        for high in [0, 1, 0x8000, 0xffff]:
            word = (high << 16) | low
            for length in [0, 1024, 1025, 65534, 65535, 0xffffffff]:
                from_operands = length >= threshold and ((word + subtract) & 0xffff) < ceiling
                from_excluded_set = length > 1024 and low not in (3998, 3999)
                evidence.require(from_operands == from_excluded_set, 'eligibility algebra')
                cases += 1
    evidence.require(disabled == [3998, 3999], 'excluded field values')

    # Magic-divisor proof: M=ceil(2^66/25), its error is 11/25.
    # z=floor(x/4) <= 2^62-1. Added error z*11/(25*2^66)
    # < 11/400 < 1/25, so it cannot cross the next integer.
    multiplier = int.from_bytes(image.read(0x2b7a37d, 8), 'little')
    evidence.require(25 * multiplier - 2**66 == 11, 'reciprocal identity')
    evidence.require(11 * 25 < 400, 'reciprocal error bound')
    rng = random.Random(115)
    xs = list(range(10000)) + [2**64-1-i for i in range(1000)]
    xs += [rng.getrandbits(64) for _ in range(10000)]
    for x in xs:
        evidence.require((((x >> 2) * multiplier) >> 66) == x // 100, 'allocation quotient')
    max_n = (2**64-1)//110
    evidence.require(max_n*110 <= 2**64-1 < (max_n+1)*110, 'multiply overflow boundary')

    # Ground the codec split in its immediate rather than an invented API.
    split = int.from_bytes(image.read(0x2b7a3db, 4), 'little')
    evidence.require(split == 65535, 'codec split operand')
    boundary = [{'length': n, 'context_field': 0, 'enabled': n >= threshold,
                 'slot': ('0x64e77a0' if n < split else '0x64e77a8') if n >= threshold else None,
                 'scratch_bytes': (8192 if n < split else 16384) if n >= threshold else None,
                 'allocation_bytes': (110*n)//100+24 if n >= threshold else None}
                for n in [1024, 1025, 65534, 65535, 65536]]
    return {'target_sha256': evidence.SHA, 'retained_record_equal': True,
            'instruction_mutations_rejected': rejected, 'identity_mutations_rejected': 2,
            'eligibility_algebra_cases': cases, 'excluded_low16_values': disabled,
            'reciprocal_spot_checks': len(xs), 'reciprocal_proof': 'README.md',
            'checked_multiply_max_input': max_n, 'boundary_table': boundary,
            'captured_code_executed_or_emulated': False,
            'implementation_or_runtime_equivalence_claimed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    evidence.require(not args.out.exists(), 'output must be fresh')
    result = verify()
    args.out.write_text(evidence.dump(result))
    print(evidence.dump(result))
