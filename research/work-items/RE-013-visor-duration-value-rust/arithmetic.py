#!/usr/bin/env python3
"""Integer/rational certificates for the manual proof, not an instruction VM."""
import argparse
from fractions import Fraction
import json
from pathlib import Path

import collect
import corpus


def even_quotient(numerator, denominator):
    quotient, remainder = divmod(numerator, denominator)
    return quotient + int(2*remainder > denominator or
                          (2*remainder == denominator and quotient % 2 == 1))


def split_projection(bits, boundary):
    """Closed integer equations derived in PROOF, no native registers or PC."""
    e = (bits >> 52) & 2047
    f = bits & corpus.MASK
    if bits & corpus.SIGN or e == 2047 or e < 992:
        return 0, 0
    m = (1 << 52)+f
    if e < 1023:
        rounded = even_quotient((m << (e-979))*1_000_000_000, 1 << 96)
        return divmod(rounded, 1_000_000_000)
    if e < 1075:
        seconds, fraction = divmod(m << (e-1023), 1 << 52)
        rounded = even_quotient(fraction*1_000_000_000, 1 << 52)
        carry, nano = divmod(rounded, 1_000_000_000)
        return seconds+carry, nano
    if e < 1087:
        return m << (e-1075), 0
    if bits >= boundary:
        return 0, 0
    seconds, microseconds = divmod((1 << 64)-1, 1_000_000)
    return seconds, microseconds*1000


def counterexamples(boundary):
    witnesses = []
    def add(name, bits, wrong):
        correct = corpus.expected(bits)
        collect.require(wrong != correct, 'false simplification lacks witness: '+name)
        witnesses.append(dict(name=name, bits=f'{bits:016x}', expected=list(correct), wrong=list(wrong)))
    x = corpus.finite_value(0x3fefffffffffffff)*corpus.BILLION
    add('truncate-nanoseconds', 0x3fefffffffffffff, divmod(x.numerator//x.denominator, corpus.BILLION))
    for bits, name, direction in [(0x3f50000000000000, 'half-up-even-tie', 1),
                                  (0x3f68000000000000, 'half-down-odd-tie', 0)]:
        value = corpus.finite_value(bits)*corpus.BILLION
        lower = value.numerator//value.denominator
        collect.require(value-lower == Fraction(1, 2), 'exact halfway witness')
        add(name, bits, divmod(lower+direction, corpus.BILLION))
    add('omit-billion-carry', 0x3fefffffffffffff, (0, corpus.nearest_integer(x)))
    bits = 0x3f50000000000000
    micros = corpus.nearest_integer(corpus.finite_value(bits)*corpus.MILLION)
    add('microsecond-rounding-for-ordinary-input', bits, (micros//corpus.MILLION, (micros%corpus.MILLION)*1000))
    add('negative-absolute-value', bits | corpus.SIGN, corpus.expected(bits))
    plateau = corpus.expected(0x43f0000000000000)
    add('infinity-saturates', corpus.INF, plateau)
    add('fallback-is-u64-seconds', 0x43f0000000000000, ((1 << 64)-1, 0))
    add('fallback-remainder-is-nanoseconds', 0x43f0000000000000, (plateau[0], plateau[1]//1000))
    add('overflow-boundary-one-early', boundary-1, (0, 0))
    add('overflow-boundary-one-late', boundary, plateau)
    add('fallback-before-two-to-64', 0x43efffffffffffff, plateau)
    # Deliberately wrong double rounding: first round x*1e9 to binary64,
    # then to integer. This is an abstract value model, not CPU execution.
    bits = 0x4330000000000001
    exact = corpus.finite_value(bits)*corpus.BILLION
    lo, hi = corpus.neighbor_bits(exact)
    low_value, high_value = corpus.finite_value(lo), corpus.finite_value(hi)
    rounded = low_value if exact-low_value < high_value-exact else high_value
    if exact-low_value == high_value-exact:
        rounded = low_value if lo % 2 == 0 else high_value
    add('binary64-rounded-total-nanoseconds', bits, divmod(corpus.nearest_integer(rounded), corpus.BILLION))
    return witnesses


def certificate(image, pins):
    f = collect.facts(image, pins)
    require = collect.require
    require([f[x] for x in ['small-exponent', 'one-exponent', 'integer-exponent', 'fallback-exponent']]
            == [992, 1023, 1075, 1087], 'exponent partition binding')
    require(f['subsecond-billion'] == f['fraction-billion'] == f['subsecond-carry-billion']
            == f['fraction-carry-billion'] == 1_000_000_000, 'billion scale/carry binding')
    require(f['fraction-half-bit'] == 51 and f['subsecond-shift-adjust'] == 45
            and f['integral-shift-adjust'] == 205, 'fraction/integer quantum binding')
    require(f['mantissa-mask'] == (1 << 52)-1 and f['fraction-tie-mask'] == (1 << 52)-512
            and f['subsecond-tie-mask'] == (1 << 32)-512, 'retained tie bits')
    require(corpus.finite_value(f['million-bits']) == 1_000_000 and
            corpus.finite_value(f['u64-upper-bits']) == (1 << 64) and
            corpus.finite_value(f['i64-upper-bits']) == (1 << 63) and
            corpus.finite_value(f['below-u64-upper-bits']) == (1 << 64)-2048,
            'fallback literal values')
    bias = corpus.finite_value(f['helper-bias-bits'])
    require(0 < bias < Fraction(1, 2) and f['sign-mask-low'] == (1 << 63)
            and f['helper-exponent'] == 1074 and f['helper-fraction-mask'] == 0xfff0000000000000,
            'reachable helper class binding')
    require(2*((1 << 53)-1)*1_000_000_000 < (1 << 84), 'small-input whole interval')
    partitions = []
    for e in range(992, 1023):
        shift = e-979
        require(13 <= shift <= 43 and ((e+45) & 255) == shift, 'subsecond shift domain')
        require((((1 << 53)-1) << shift) < (1 << 96), 'subsecond fixed-point bound')
        require(((((1 << 53)-1) << shift)*1_000_000_000) < (1 << 126), 'subsecond product bound')
        partitions.append(dict(exponent=e, denominator_power=96, shift=shift))
    require(1_000_000_000 % 512 == 0, 'discarded low nine product bits')
    for e in range(1023, 1075):
        require(0 <= e-1023 <= 51 and 1 <= 1075-e <= 52, 'fraction split domain')
    for e in range(1075, 1087):
        require(0 <= e-1075 <= 11 and (((1 << 53)-1) << (e-1075)) < (1 << 64), 'integral u64 domain')
    require(1_000_000_000 % 2 == 0, 'whole/fraction tie parity')
    # With x=M*2^952 in exponent2027 and 1e6=15625*2^6,
    # RN64 overflow iff M*15625 >= (2^54-1)*2^12.
    threshold = ((1 << 54)-1) << 12
    last_m = (threshold-1)//15625
    first_m = last_m+1
    require((1 << 52) <= last_m < first_m < (1 << 53), 'overflow exponent binade')
    require(last_m*15625 < threshold <= first_m*15625, 'adjacent overflow integer certificate')
    boundary = (2027 << 52)+(first_m-(1 << 52))
    require(corpus.finite_value(boundary-1)*1_000_000 < corpus.OVERFLOW_MIDPOINT <=
            corpus.finite_value(boundary)*1_000_000, 'independent Fraction midpoint')
    reciprocal = []
    for integer in (0, (1 << 64)-1):
        quotient = (integer*f['microsecond-reciprocal']) >> (64+f['microsecond-shift'])
        remainder = ((integer & 0xffffffff)-(quotient*f['microsecond-divisor'] & 0xffffffff)) & 0xffffffff
        require((quotient, remainder) == divmod(integer, 1_000_000), 'reachable reciprocal/remainder')
        require(f['microsecond-nano-scale'] == 1000 and remainder*1000 < 1_000_000_000, 'microsecond return units')
        reciprocal.append(dict(input=integer, seconds=quotient, nanos=remainder*1000))
    count = 0
    for bits, _ in corpus.cases():
        require(split_projection(bits, boundary) == corpus.expected(bits), 'split equations versus rational expectations')
        count += 1
    return dict(status='PASS mathematical domain certificates, not native execution',
                actual_facts=f, subsecond_exponents=partitions, fraction_exponents=52, integral_exponents=12,
                small_upper_bound=dict(numerator=2*((1 << 53)-1)*1_000_000_000, denominator=1 << 84),
                overflow=dict(exponent=2027, last_m=last_m, first_m=first_m, scaled_threshold=threshold,
                              last_gap=threshold-last_m*15625, next_gap=first_m*15625-threshold,
                              first_input_bits=f'{boundary:016x}'), reciprocal=reciprocal,
                rational_split_comparisons=count, wrong_model_witnesses=counterexamples(boundary),
                limits='Finite comparisons support the universal addressed proof; no instruction decoding/execution loop, original source inference or observed CPU state.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=collect.REPO)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    collect.require(not args.out.exists(), 'fresh certificate output')
    pins = json.loads((collect.HERE/'BASIS-PINS.json').read_text())
    image = collect.authenticate(args.repo, pins)
    result = certificate(image, pins)
    collect.write_json(args.out, result)
    print(json.dumps(dict(status=result['status'], comparisons=result['rational_split_comparisons'], witnesses=len(result['wrong_model_witnesses']))))


if __name__ == '__main__':
    main()
