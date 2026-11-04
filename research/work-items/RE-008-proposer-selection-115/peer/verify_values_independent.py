#!/usr/bin/env python3
"""Recalculate value fixtures without importing the packet oracle or Rust."""
import argparse
import ast
import base64
from bisect import bisect_right
from collections import Counter
from fractions import Fraction
import gzip
import hashlib
import json
from pathlib import Path
import struct

MAX = (1 << 64) - 1
def require(ok, why):
    if not ok:
        raise ValueError(why)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def bits(value):
    return struct.unpack('<Q', struct.pack('<d', value))[0]
def moment(i, n, w, j):
    # CPython binary64 conversion/division/multiplication, then its independently
    # implemented exact Fraction->float rounding for the fused final operation.
    reciprocal = 1.0 / float(w)
    offset = (float(i) * reciprocal) / float(n)
    final = float(Fraction.from_float(reciprocal) * Fraction.from_float(float(j))
                  + Fraction.from_float(offset))
    return [bits(reciprocal), bits(offset), bits(final)]
def hist(base, keys, r):
    switch = MAX if base > MAX - 2000 else base + 2000
    q = base
    if r >= switch:
        delayed = (r - 200) & MAX
        if delayed > q:
            q = delayed
    return q, bisect_right(keys, q) - 1
def limit(stake, execution):
    return min(MAX, max(stake + 2000, execution + 201))
def prep(a, e, rows):
    # Outer join keys and two membership columns. A key's occurrence in both
    # input sets contributes once to the denominator, independent of map rows.
    joined = {}
    for key in a:
        joined[key] = [True, False, None]
    for key in e:
        joined.setdefault(key, [False, False, None])[1] = True
    for key, weight in rows:
        joined.setdefault(key, [False, False, None])[2] = weight
    denominator = sum(first or extra for first, extra, _ in joined.values())
    kept = [(key, value[2]) for key, value in sorted(joined.items())
            if not value[0] and value[2] is not None]
    total = min(MAX, sum(weight for _, weight in kept))
    threshold = (total - min(total, 1000)) // denominator if denominator else 0
    adjusted, fallback = [], []
    members = {key for key, (first, extra, _) in joined.items() if first or extra}
    for key, weight in kept:
        changed = max(0, weight - threshold) if key in members else min(MAX, 3 * weight)
        adjusted.append((key, changed))
        if key in members:
            fallback.append((min(MAX, 3 * changed), key))
    return total, threshold, adjusted, sorted(fallback, reverse=True), members
def order(events):
    def compare_key(event):
        word, tag, key = event
        negative = bool(word >> 63)
        return (0 if negative else 1, -word if negative else word, tag, key if tag else '')
    return sorted(events, key=compare_key)
def scheduling(a, e, rows, selected, image):
    _, _, adjusted, pool, members = prep(a, e, rows)
    events = []
    for index, (key, weight) in enumerate(adjusted):
        for j in range(weight):
            tag = int(key not in members)
            events.append((moment(index, len(adjusted), weight, j)[2], tag, key if tag else '-'))
    events = order(events)
    output = []
    for _, tag, key in events:
        if tag:
            output.append(key)
            continue
        if not pool:
            continue
        # Derive multiplicities before changing counts; this handles one/two
        # entries without reproducing the source's in-place three-store loop.
        if len(pool) == 1:
            chosen = [pool[0][1]] * 3
        elif len(pool) == 2:
            chosen = [pool[0][1], pool[1][1], pool[0][1]]
        else:
            chosen = [row[1] for row in pool[:3]]
        multiplicities = Counter(chosen)
        pool = sorted([(count - multiplicities[k], k) for count, k in pool
                       if count > multiplicities[k]], reverse=True)
        output.extend(chosen)
    image = bytearray.fromhex(image)
    image[0] = 0x2e if output else 0x0f
    if output:
        image[1:21] = bytes.fromhex(output[selected % len(output)])
    answer = [image.hex(), str(len(events))]
    for word, tag, key in events:
        answer.extend((f'{word:016x}', str(tag), key))
    answer.append(str(len(output)))
    answer.extend(output)
    return ' '.join(answer)
def evaluate(line):
    tokens = iter(line.split())
    def integer():
        return int(next(tokens))
    def keys():
        return [next(tokens) for _ in range(integer())]
    def rows():
        return [(next(tokens), integer()) for _ in range(integer())]
    command = next(tokens)
    if command == 'E':
        result = 'E ' + ' '.join(f'{v:016x}' for v in moment(*(integer() for _ in range(4))))
    elif command == 'H':
        base, query = integer(), integer()
        result = 'H %d %d' % hist(base, [integer() for _ in range(integer())], query)
    elif command == 'Q':
        values = [(int(next(tokens), 16), integer(), next(tokens)) for _ in range(integer())]
        result = 'Q ' + ' '.join(f'{word:016x} {tag} {key if tag else "-"}' for word, tag, key in order(values))
    elif command in ('P', 'S'):
        a, e, data = keys(), keys(), rows()
        if command == 'S':
            selected, image = integer(), next(tokens)
            result = 'S ' + scheduling(a, e, data, selected, image)
        else:
            total, threshold, adjusted, fallback, _ = prep(a, e, data)
            values = ['P', str(total), str(threshold), str(len(adjusted))]
            values.extend(v for k, w in adjusted for v in (k, str(w)))
            values.append(str(len(fallback)))
            values.extend(v for w, k in fallback for v in (str(w), k))
            result = ' '.join(values)
    elif command == 'G':
        stake, execution, base, query, counter = [integer() for _ in range(5)]
        q, index = hist(base, [integer() for _ in range(integer())], query)
        ceiling = limit(stake, execution)
        warning = int(query >= ceiling)
        result = f'G {ceiling} {q} {index} {(counter + warning) & MAX} {warning}'
    elif command == 'R':
        head, size, query, capacity = [integer() for _ in range(4)]
        physical = [integer() for _ in range(capacity)]
        logical = (physical[head:] + physical[:head])[:size]
        prefix = bisect_right(logical, query)
        predecessor = (head + prefix - 1) % capacity if prefix else -1
        result = f'R {prefix} {predecessor}'
    elif command == 'F':
        selected, query, base1, base2, execution, counter = [integer() for _ in range(6)]
        scratch = next(tokens)
        first = [(integer(), keys()) for _ in range(integer())]
        second = [(integer(), rows()) for _ in range(integer())]
        extra, image = keys(), next(tokens)
        q1, i1 = hist(base1, [r for r, _ in first], query)
        warning = int(query >= limit(base2, execution))
        counter = (counter + warning) & MAX
        q2, i2 = '-', '-'
        if i1 >= 0:
            q2, i2 = hist(base2, [r for r, _ in second], query)
            counter = (counter + warning) & MAX
        prefix = f'F {q1} {i1} {q2} {i2} {counter} '
        if i1 < 0 or i2 == -1:
            output = bytearray.fromhex(scratch)
            output[0] = 0x28
            output[8:16] = query.to_bytes(8, 'little')
            result = prefix + output.hex()
        else:
            result = prefix + scheduling(first[i1][1], extra, second[i2][1], selected, image)
    else:
        raise ValueError(command)
    require(not list(tokens), 'unparsed input')
    return result

ap = argparse.ArgumentParser()
ap.add_argument('--root', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
args = ap.parse_args()
packet = args.root.resolve() / 'research/work-items/RE-008-proposer-selection-115'
args.out.mkdir(parents=True, exist_ok=True)
inputs = gzip.decompress((packet/'inputs.txt.gz').read_bytes())
expected = gzip.decompress((packet/'expected.txt.gz').read_bytes())
freeze = json.loads((packet/'freeze.json').read_bytes())
require(sha(inputs) == freeze['files']['inputs']['raw_sha256'], 'inputs freeze')
require(sha(expected) == freeze['files']['expected']['raw_sha256'], 'expected freeze')
counts, differences, computed = Counter(), [], hashlib.sha256()
input_lines, expected_lines = inputs.decode().splitlines(), expected.decode().splitlines()
require(len(input_lines) == len(expected_lines) == 9243, 'record count')
for index, (line, wanted) in enumerate(zip(input_lines, expected_lines)):
    value = evaluate(line)
    computed.update((value + '\n').encode())
    counts[line[0]] += 1
    if value != wanted:
        differences.append({'index': index, 'input': line, 'expected': wanted, 'derived': value})
summary = {'cases': len(input_lines), 'counts': dict(counts), 'mismatches': len(differences),
           'derived_raw_sha256': computed.hexdigest(), 'frozen_raw_sha256': sha(expected),
           'source_sha256': sha((packet/'rust/lib.rs').read_bytes()),
           'independence': 'No packet modules imported; CPython binary64 and Fraction->float final rounding, joined membership columns, batched multiplicity subtraction, bisected histories/rings. This is not captured execution or a proof of generic-helper premises.'}
(args.out/'value-review.json').write_text(json.dumps(summary, indent=2)+'\n')
(args.out/'differences.json').write_text(json.dumps(differences, indent=2)+'\n')
print(json.dumps(summary, indent=2))
require(not differences, 'independent values differ')
