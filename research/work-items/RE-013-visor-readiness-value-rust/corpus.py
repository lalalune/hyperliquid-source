#!/usr/bin/env python3
"""Independent whole-day mathematical expectations; no native evaluator.

No imports from the binding/arithmetic scripts or future production crate.
Year inversion is monotone binary search over mathematical Gregorian counts.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path

MIN_YEAR, MAX_YEAR = -262143, 262142
MAX_SAMPLE = 8210266876799
BILLION = 1000000000


def require(ok, message):
    if not ok:
        raise ValueError(message)


def leap(y):
    return int(y % 4 == 0 and (y % 100 != 0 or y % 400 == 0))


def before(y):
    return 365*y+(y+3)//4-(y+99)//100+(y+399)//400


def parts(y, ordinal, second, nano):
    if not (MIN_YEAR <= y <= MAX_YEAR and 1 <= ordinal <= 365+leap(y)
            and 0 <= second < 86400 and 0 <= nano < BILLION):
        return None
    flag = (0 if leap(y) else 8) | ((before(y % 400)+3) % 7+1)
    return (8192*y+16*ordinal+flag, second, nano)


def inverse(day):
    lo, hi = MIN_YEAR, MAX_YEAR+1
    require(before(lo) <= day < before(hi), 'inverse domain')
    while hi-lo > 1:
        mid = (lo+hi)//2
        if before(mid) <= day:
            lo = mid
        else:
            hi = mid
    return lo, day-before(lo)+1


def clock(seconds, nano):
    if not (0 <= seconds <= MAX_SAMPLE and 0 <= nano < BILLION):
        return None
    day, second = divmod(seconds, 86400)
    y, ordinal = inverse(before(1970)+day)
    return parts(y, ordinal, second, nano)


def deadline(fields):
    if parts(*fields) is None:
        return None
    y, ordinal, second, nano = fields
    # Oracle flattens the whole timestamp, including nanos, then clamps.
    absolute = ((before(y)+ordinal-1)*86400+second)*BILLION+nano+60*BILLION
    maximum = before(MAX_YEAR+1)*86400*BILLION-1
    absolute = min(absolute, maximum)
    day, subday = divmod(absolute, 86400*BILLION)
    second, nano = divmod(subday, BILLION)
    y, ordinal = inverse(day)
    return parts(y, ordinal, second, nano)


def answer(op, numbers):
    if op == 'P':
        result = parts(*numbers)
    elif op == 'C':
        result = clock(*numbers)
    elif op == 'D':
        result = deadline(numbers)
    elif op == 'R':
        source, current = numbers[:4], numbers[4:]
        current_value, limit = parts(*current), deadline(source)
        if current_value is None or limit is None:
            return ('DOMAIN',)
        return ('BOOL', int(current_value > limit))
    else:
        raise ValueError('unknown operation')
    return ('DOMAIN',) if result is None else ('OK', *result)


def generate():
    cases = []
    seen = set()
    def add(category, op, *numbers):
        key = (op, *numbers)
        if key not in seen:
            seen.add(key)
            cases.append((category, op, numbers))
    years = sorted(set(range(-400, 400)) | {MIN_YEAR, MIN_YEAR+1, MAX_YEAR-1, MAX_YEAR,
                                           -801, -800, -799, 1582, 1900, 1969, 1970, 2000, 2100, 2400})
    for y in years:
        for ordinal in sorted({1, 59, 60, 61, 364, 365, 365+leap(y)}):
            for second, nano in ((0, 0), (86339, 1), (86340, 500000000), (86399, 999999999)):
                add('canonical-parts-cycle-boundaries', 'P', y, ordinal, second, nano)
        for ordinal in sorted({1, 365+leap(y)}):
            for second in (0, 86339, 86340, 86399):
                for nano in (0, 1, 999999999):
                    add('fixed60-year-and-time-boundaries', 'D', y, ordinal, second, nano)
        for ordinal, second, nano in ((365+leap(y), 86339, 1), (365+leap(y), 86340, 0),
                                      (1, 0, 999999999)):
            source = (y, ordinal, second, nano)
            whole = ((before(y)+ordinal-1)*86400+second)*BILLION+nano+60*BILLION
            maximum = before(MAX_YEAR+1)*86400*BILLION-1
            for delta in (-1, 0, 1):
                current = min(whole, maximum)+delta
                if before(MIN_YEAR)*86400*BILLION <= current <= maximum:
                    d, rem = divmod(current, 86400*BILLION)
                    s, n = divmod(rem, BILLION)
                    cy, co = inverse(d)
                    add('strict-before-equal-after', 'R', *source, cy, co, s, n)
    days = {0, 1, 365, 366, MAX_SAMPLE//86400}
    for y in range(2000, 2401):
        for delta in (-2, -1, 0, 1, 2, 58, 59, 60, 364):
            days.add(before(y)-before(1970)+delta)
    for i in range(1024):
        days.add((i*92821+17) % (MAX_SAMPLE//86400+1))
    for day in sorted(days):
        for second, nano in ((0, 0), (1, 999999999), (86399, 1)):
            seconds = day*86400+second
            if 0 <= seconds <= MAX_SAMPLE:
                add('sample-day-cycle-and-range-boundaries', 'C', seconds, nano)
    for seconds in (0, 1, 59, 60, 61, 86339, 86340, 86399, 86400, MAX_SAMPLE-1, MAX_SAMPLE):
        for nano in (0, 1, 499999999, 500000000, 999999999):
            add('sample-fraction-boundaries', 'C', seconds, nano)
    invalid = [(MIN_YEAR-1, 1, 0, 0), (MAX_YEAR+1, 1, 0, 0), (-(1 << 31), 1, 0, 0),
               ((1 << 31)-1, 1, 0, 0), (1970, 0, 0, 0), (1970, 366, 0, 0),
               (2000, 367, 0, 0), (0, 65535, 0, 0), (1970, 1, 86400, 0),
               (1970, 1, 0xffffffff, 0), (1970, 1, 0, BILLION), (1970, 1, 0, 0xffffffff)]
    for fields in invalid:
        for op in ('P', 'D'):
            add('new-safe-api-refusal-not-native-error', op, *fields)
        add('new-safe-api-refusal-not-native-error', 'R', *fields, 1970, 1, 0, 0)
        add('new-safe-api-refusal-not-native-error', 'R', 1970, 1, 0, 0, *fields)
    for seconds, nano in ((-1, 0), (-(1 << 63), 0), (MAX_SAMPLE+1, 0), ((1 << 63)-1, 0),
                          (0, BILLION), (0, (1 << 64)-1), (-1, BILLION)):
        add('new-safe-api-refusal-not-native-error', 'C', seconds, nano)
    # Dates far apart exercise signed date ordering, not just equality corridors.
    for a, b in ((MIN_YEAR, MAX_YEAR), (MAX_YEAR, MIN_YEAR), (-1, 0), (0, -1), (1900, 2000)):
        add('signed-date-order', 'R', a, 1, 0, 0, b, 1, 0, 0)
    inputs, outputs, provenance = [], [], []
    counts = Counter()
    for i, (category, op, numbers) in enumerate(cases):
        identifier = f'{i:08x}'
        result = answer(op, numbers)
        inputs.append('\t'.join(map(str, (identifier, op, *numbers)))+'\n')
        outputs.append('\t'.join(map(str, (identifier, *result)))+'\n')
        provenance.append((identifier, category))
        counts[(op, result[0])] += 1
    raw_inputs, raw_outputs = ''.join(inputs).encode(), ''.join(outputs).encode()
    metadata = dict(cases=len(cases), counts={f'{k[0]}:{k[1]}': v for k, v in sorted(counts.items())},
                    inputs_sha256=hashlib.sha256(raw_inputs).hexdigest(),
                    expected_sha256=hashlib.sha256(raw_outputs).hexdigest(),
                    oracle='Whole Gregorian days + binary-search inverse + integer-nanosecond addition/clamp; no captured execution.',
                    native_scope='Successful canonical domain only; DOMAIN is new safe policy, never native error behavior.')
    return raw_inputs, raw_outputs, provenance, metadata


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), 'fresh output required')
    raw_inputs, raw_outputs, provenance, metadata = generate()
    args.out.mkdir(parents=True)
    for name, raw in [('inputs.tsv.gz', raw_inputs), ('expected.tsv.gz', raw_outputs)]:
        (args.out/name).write_bytes(gzip.compress(raw, mtime=0))
    # Semantic category labels are separate from both input-only driver streams.
    raw_provenance = ''.join(f'{identifier}\t{category}\n' for identifier, category in provenance).encode()
    (args.out/'provenance.tsv.gz').write_bytes(gzip.compress(raw_provenance, mtime=0))
    (args.out/'summary.json').write_text(json.dumps(metadata, sort_keys=True, separators=(',', ':'))+'\n')
    print(json.dumps(metadata, sort_keys=True))


if __name__ == '__main__':
    main()
