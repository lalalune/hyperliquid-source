#!/usr/bin/env python3
"""Static arithmetic/branch deductions, not execution or emulation of hl-node."""
import argparse
import json
import math
import struct
from fractions import Fraction
import verify


def parameters(data):
    image = verify.Image(data)
    return {
        'ratio_branch': image.get(0x366fad3, 1)[0],
        'flag_operation': image.get(0x366fbab, 3).hex(),
        'late_branch': image.get(0x366fbb2, 1)[0],
        'flag_toggle': image.get(0x366fbb4 + 3, 1)[0],
        'late_code': struct.unpack('<I', image.get(0x366fbc5 + 1, 4))[0],
        'first_marker': image.get(0x366fb24 + 2, 1)[0],
        'latest_qword': image.get(0x366fb40 + 3, 1)[0],
        'latest_dword': image.get(0x366fb39 + 3, 1)[0],
        'default_threshold_bits': image.get(0x3f15c50 + 2, 8).hex(),
        'caller_branch': image.get(0x538149e, 1)[0],
    }


def compare(a, b):
    # UCOMISD with quiet NaNs and masked exceptions: ZF, PF, CF.
    if math.isnan(a) or math.isnan(b):
        return 1, 1, 1
    return int(a == b), 0, int(a < b)


def branch(opcode, flags):
    zf, _, cf = flags
    if opcode == 0x76:  # JBE
        return bool(cf or zf)
    if opcode == 0x72:  # JB, explicit counterfactual
        return bool(cf)
    raise ValueError('unsupported comparison branch')


def flag_tail(flag, elapsed, threshold, p):
    """Only the local normal-return tail; helpers are assumed to return."""
    flags = compare(elapsed, threshold)
    be = int(bool(flags[0] or flags[2]))
    if p['flag_operation'] == '4420e0':
        result = be & flag
    elif p['flag_operation'] == '4408e0':  # OR counterfactual
        result = be | flag
    else:
        raise ValueError('unsupported flag operation')
    request = (not branch(p['late_branch'], flags) and
               not ((flag ^ p['flag_toggle']) & 1))
    return (1 if request else result), request


def max_with_positive_zero(value):
    # MAXSD destination, +0 chooses source 2 for unordered or equal values.
    return value if value > 0.0 else 0.0


def ratio_retains_state(first, second, tolerance, p):
    """Admitted u64 values, second != 0, provider tag 0x1a2, valid lookup."""
    assert 0 <= first < 2**64 and 0 < second < 2**64
    low, high = min(first, second), max(first, second)
    ratio = float(high) / float(low) if low else math.inf
    distance = ratio - 1.0
    return branch(p['ratio_branch'], compare(max_with_positive_zero(tolerance), distance))


def project_pair(seconds, nanos):
    """Declared raw i64/i32 inputs; no timebase or provider semantics inferred."""
    assert -(2**63) <= seconds < 2**63 and -(2**31) <= nanos < 2**31
    adjust = seconds < 0 and nanos > 0
    s = seconds + int(adjust)
    n = nanos - (1_000_000_000 if adjust else 0)
    raw = float(s) + float(n) / 1_000_000_000.0
    value = max_with_positive_zero(raw)
    return 0.0 if value == math.inf or math.isnan(value) else value


def u64_lanes(value):
    """Algebraic interpretation of PUNPCKLDQ/SUBPD/ADDSD, not an ISA runner."""
    low = struct.unpack('<d', struct.pack('<Q', (0x43300000 << 32) | (value & 0xffffffff)))[0]
    high = struct.unpack('<d', struct.pack('<Q', (0x45300000 << 32) | (value >> 32)))[0]
    return (low - 2.0**52) + (high - 2.0**84)


def nearest_even_u64(value):
    """Integer-only rounding reference independent of the split-lane expression."""
    shift = max(0, value.bit_length() - 53)
    if not shift:
        return value
    q, r = divmod(value, 1 << shift)
    midpoint = 1 << (shift - 1)
    return (q + int(r > midpoint or (r == midpoint and q & 1))) << shift


def deductions(data):
    p = parameters(data)
    expected = {'ratio_branch': 0x76, 'flag_operation': '4420e0', 'late_branch': 0x76,
                'flag_toggle': 1, 'late_code': 8, 'first_marker': 8,
                'latest_qword': 20, 'latest_dword': 28,
                'default_threshold_bits': '0000000000002440', 'caller_branch': 0x75}
    verify.require(p == expected, 'relation parameters changed')
    categories = [('less', 9.0, 10.0), ('equal', 10.0, 10.0),
                  ('greater', 11.0, 10.0), ('unordered', 1.0, math.nan)]
    rows = []
    for label, elapsed, threshold in categories:
        for flag in range(256):
            result, request = flag_tail(flag, elapsed, threshold, p)
            verify.require(result == flag & 1, 'tail low-bit identity')
            verify.require(request == (label == 'greater' and bool(flag & 1)), 'strict late request')
        rows.append({'comparison': label, 'raw_flags_checked': 256,
                     'return': 'raw_flag & 1', 'code8_request': 'odd flag' if label == 'greater' else 'never'})
    # Hand-selected independent boundary expectations. True is the stateful route.
    cases = [(100, 100, 0.0, True), (100, 100, 0.01, False),
             (100, 200, 1.0, True), (200, 100, 1.0, True),
             (100, 200, math.nextafter(1.0, math.inf), False),
             (100, 200, math.nextafter(1.0, 0.0), True),
             (0, 100, math.inf, True), (1, 2**64-1, math.inf, False),
             (100, 100, math.nan, True), (100, 100, -1.0, True),
             (100, 100, -0.0, True), (100, 100, -math.inf, True),
             (2**64-2, 2**64-1, 0.0, True),
             (2**64-2, 2**64-1, 2**-52, False)]
    for a, b, t, expected_result in cases:
        verify.require(ratio_retains_state(a, b, t, p) == expected_result, 'ratio boundary')
    # Exact integer endpoints and neighbors at each exponent, including halfway ties.
    values = {0, 1, 2**64-1}
    for e in range(64):
        for delta in (-3, -2, -1, 0, 1, 2, 3):
            x = (1 << e) + delta
            if 0 <= x < 2**64:
                values.add(x)
        shift = max(0, e - 52)
        if shift:
            for q in (0, 1, 2, 3):
                for delta in (-1, 0, 1):
                    x = (1 << e) + (q << shift) + (1 << (shift-1)) + delta
                    if x < 2**64:
                        values.add(x)
    for value in values:
        verify.require(int(u64_lanes(value)) == nearest_even_u64(value), 'u64 lane rounding')
    pair_count = 0
    for s in (-(2**63), -2, -1, 0, 1, 2, 2**63-1):
        for n in (-(2**31), -1_000_000_000, -1, 0, 1, 999_999_999, 1_000_000_000, 2**31-1):
            adjust = s < 0 and n > 0
            a, b = s + int(adjust), n - 1_000_000_000 * int(adjust)
            verify.require(Fraction(s) + Fraction(n, 10**9) == Fraction(a) + Fraction(b, 10**9), 'exact pair normalization')
            value = project_pair(s, n)
            verify.require(math.isfinite(value) and value >= 0, 'finite nonnegative projection')
            pair_count += 1
    return {'schema': 1, 'scope': 'static deductions, no target execution or emulation',
            'parameters': p, 'tail_truth_table': rows, 'ratio_boundaries': len(cases),
            'u64_rounding_boundaries': len(values), 'pair_normalization_boundaries': pair_count,
            'limits': 'Default binary64 rounding, masked FP exceptions, quiet NaNs; valid memory and normal helper returns. Finite samples support the written general proof, not a complete runtime equivalence test.'}


def counterfacts(data):
    image = verify.Image(data)
    trials = [
        ('ratio strictness', 0x366fad3, 0x72, lambda p: ratio_retains_state(100, 200, 1.0, p)),
        ('late request tie', 0x366fbb2, 0x72, lambda p: flag_tail(1, 10.0, 10.0, p)),
        ('low-bit AND versus OR', 0x366fbab+1, 0x08, lambda p: flag_tail(0, 9.0, 10.0, p)),
        ('late flag toggle', 0x366fbb4+3, 0, lambda p: flag_tail(1, 11.0, 10.0, p)),
        ('request code', 0x366fbc5+1, 9, lambda p: p['late_code']),
        ('latest timestamp field', 0x366fb40+3, 24, lambda p: p['latest_qword']),
        ('initial threshold', 0x3f15c50+8, 0x34, lambda p: p['default_threshold_bits']),
        ('caller store gate', 0x538149e, 0x74, lambda p: p['caller_branch'] == 0x75),
    ]
    result = []
    for name, address, value, prediction in trials:
        changed = bytearray(data)
        changed[image.off(address)] = value
        before, after = prediction(parameters(data)), prediction(parameters(changed))
        verify.require(before != after, 'counterfactual did not affect relation: ' + name)
        # Persist the public report in JSON-native form for in-memory comparisons.
        before = list(before) if isinstance(before, tuple) else before
        after = list(after) if isinstance(after, tuple) else after
        try:
            verify.observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            result.append({'name': name, 'va': hex(address), 'before': before, 'after': after, 'rejection': str(error)})
        else:
            raise ValueError('counterfactual survived obligations: ' + name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong artifact')
    report = deductions(data)
    report['actual_byte_counterfacts'] = counterfacts(data)
    text = verify.encoded(report)
    path = verify.PACKET / 'relations.json'
    if args.write:
        path.write_text(text)
    else:
        verify.require(path.read_text() == text, 'relation regeneration differs')
    print('PASS: static low-bit identity, strict ratio/late gates, 8 actual-byte counterfacts')


if __name__ == '__main__':
    main()
