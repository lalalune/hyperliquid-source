#!/usr/bin/env python3
"""Finite/algebraic certificates, never an instruction or target evaluator."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import collect


def leap(y):
    return int(y % 4 == 0 and (y % 100 != 0 or y % 400 == 0))


def certificate(image):
    require = collect.require
    prefix = [sum(leap(y) for y in range(r)) for r in range(401)]
    flags = [(0 if leap(r) else 8) | ((365*r + prefix[r] + 3) % 7 + 1)
             for r in range(400)]
    require(image.at(0x7d692, 401) == bytes(prefix), 'leap-prefix formula')
    require(image.at(0x7d823, 400) == bytes(flags), 'year-flag formula')
    require(struct.unpack('<d', image.at(0x6e748, 8))[0] == 60.0, 'fixed duration')
    require(struct.unpack('<iII', image.at(0x7c7e4, 12)) ==
            (2147473118, 86399, 999999999), 'ordinary maximum')
    reciprocals = []
    for divisor, multiplier, shift, maximum in [
            (86400, 0x1845c8a0ce512957, 77, 8210266876799),
            (146097, 0x396b06bd, 47, 95745764)]:
        delta = divisor*multiplier - (1 << shift)
        qmax = maximum // divisor
        bound = qmax*delta + (divisor-1)*multiplier
        require(0 <= delta and bound < 1 << shift, 'whole-interval reciprocal')
        reciprocals.append(dict(divisor=divisor, multiplier=multiplier, shift=shift,
                                maximum=maximum, delta=delta, qmax=qmax,
                                remainder_bound=bound, scale=1 << shift))
    cycle_hash = hashlib.sha256()
    borrow_count = 0
    year = 0
    for c in range(146097):
        while c >= 365*(year+1) + prefix[year+1]:
            year += 1
        hi = (c*0x6719f361) >> 32
        estimate = (((c-hi) >> 1)+hi) >> 8
        require(estimate == c // 365, '365 reciprocal finite domain')
        t = c-365*estimate
        borrow = t < prefix[estimate]
        require(estimate == year+int(borrow), 'two possible estimates')
        if borrow:
            borrow_count += 1
            require(c >= 365 and 0 <= estimate-1 < 401, 'borrow bounds')
            require(t-prefix[estimate-1]+365 >= t, 'no unsigned underflow')
            ordinal = t-prefix[estimate-1]+366
        else:
            require(c <= 145999, 'no-borrow guard')
            ordinal = t-prefix[estimate]+1
        require(ordinal == c-365*year-prefix[year]+1, 'exact ordinal')
        require(1 <= ordinal <= 365+leap(year), 'canonical cycle date')
        require(((16*ordinal+flags[year]) & 0x1ff8) < 0x16e1, 'date admission mask')
        cycle_hash.update(struct.pack('<IHHB', c, year, ordinal, borrow))
    require(borrow_count == 19600, 'borrow count')
    year_hash = hashlib.sha256()
    for y in range(-262143, 262143):
        q = (y*0x51eb851f >> 39) + int(y < 0)
        trunc = abs(y)//400 * (-1 if y < 0 else 1)
        require(q == trunc, 'signed 400 quotient')
        residue = y-400*q
        cycle = q-int(residue < 0)
        residue %= 400
        require(cycle == y//400 and residue == y % 400, 'Euclidean year correction')
        year_hash.update(struct.pack('<iii', y, cycle, residue))
    seconds_hash = hashlib.sha256()
    for second in range(86400):
        t = second+60
        carry = (t*0x1845c8a0ce512957 >> 77)*86400
        require(carry == 86400*int(second >= 86340), 'fixed60 carry')
        require(t-carry == t % 86400, 'fixed60 second')
        seconds_hash.update(struct.pack('<III', second, t-carry, carry))
    mask = (1 << 64)-1
    guards = []
    for carry in (0, 86400):
        first = (carry+0xffdf3b645a1cac08) & mask
        second = (carry+0xffff574000000000) & mask
        require(first > 0xffbe76c8b4395810 and second >= 0xfffeae7ffffeae81,
                'both actual unsigned carry guards')
        require(carry*0x1845c8a0ce512957 >> 77 == carry//86400, 'caller day delta')
        guards.append(dict(carry=carry, first=first, second=second))
    # Whole Gregorian counts, separate from the native cycle-estimate formula.
    def before(y):
        return 365*y+(y+3)//4-(y+99)//100+(y+399)//400
    require(before(1970) == 719528 and before(262143) == 95745765, 'sample endpoints')
    require((before(262143)-before(1970))*86400-1 == 8210266876799, 'maximum sample')
    require(8192*262142+16*365+flags[262142 % 400] == 2147473118, 'packed maximum')
    require(60*1000000000 < (1 << 63)-1, 'fixed duration unclamped')
    require(60000000000*0x112e0be826d694b3 >> 90 == 60, 'caller duration division')
    # Exact binary64 significand/exponent arithmetic for the sole admitted 60.0.
    bits = int.from_bytes(image.at(0x6e748, 8), 'little')
    exponent = (bits >> 52) & 0x7ff
    significand = (bits & ((1 << 52)-1))+(1 << 52)
    shift = 1075-exponent
    require(1023 <= exponent < 1075 and significand >> shift == 60 and
            significand % (1 << shift) == 0, 'integral fixed60 fraction is zero')
    return dict(status='PASS: finite mathematics and whole-interval bounds only',
                target_sha256=collect.sha(image.data), reciprocal_bounds=reciprocals,
                tables=dict(leap_prefix_sha256=collect.sha(bytes(prefix)),
                            year_flags_sha256=collect.sha(bytes(flags))),
                cycle=dict(days=146097, borrow=borrow_count, no_borrow=146097-borrow_count,
                           sha256=cycle_hash.hexdigest()),
                signed_years=dict(count=524286, sha256=year_hash.hexdigest()),
                ordinary_seconds=dict(count=86400, sha256=seconds_hash.hexdigest()),
                actual_carry_guards=guards,
                scope='Manual native-to-formula proof remains required. No registers, PC, flags, pointers or captured instructions are evaluated.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=collect.REPO)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    collect.require(not args.out.exists(), 'fresh output required')
    pins = json.loads((collect.HERE/'BASIS-PINS.json').read_text())
    record = certificate(collect.authenticate(args.repo, pins))
    collect.write_json(args.out, record)
    print(json.dumps(dict(status=record['status'], cycle_days=146097, signed_years=524286)))


if __name__ == '__main__':
    main()
