#!/usr/bin/env python3
"""Pre-source mathematical corpus. No target, Rust source or ISA model imported."""
import argparse
from collections import Counter
from dataclasses import dataclass
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random
import re

U64 = (1 << 64) - 1
HIGH = 1 << 63
SEED = 0x94000753544F5245


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass
class Case:
    group: str
    flag: int
    samples: dict
    fallbacks: dict
    records: list


def validate(case):
    require(0 <= case.flag <= 255, 'dex byte domain')
    words = list(case.samples) + list(case.fallbacks) + list(case.fallbacks.values())
    words += [word for values in case.samples.values() for word in values]
    words += [word for record in case.records for word in record]
    require(all(type(word) is int and 0 <= word <= U64 for word in words), 'u64 domain')
    require(all(len(record) == 3 for record in case.records), 'record width')


def expected(case):
    """Declarative prefix/filter/group relation, independent of sequential Rust."""
    stop = next((i for i, (_, tag, _) in enumerate(case.records) if tag == 2), len(case.records))
    prefix = case.records[:stop]
    sample_keys = set(case.samples) | {key for key, tag, _ in prefix if tag % 2 == 0}
    samples = {key: list(case.samples.get(key, ())) +
               [payload for row_key, tag, payload in prefix if row_key == key and tag % 2 == 0]
               for key in sorted(sample_keys)}
    fallback_keys = set(case.fallbacks)
    if case.flag == 3:
        fallback_keys |= {key for key, tag, _ in prefix if tag % 2 == 1}
    fallbacks = {
        key: (next((payload for row_key, tag, payload in reversed(prefix)
                    if row_key == key and tag % 2 == 1), case.fallbacks.get(key))
              if case.flag == 3 else case.fallbacks[key])
        for key in sorted(fallback_keys)
    }
    require(all(value is not None for value in fallbacks.values()), 'defined fallback state')
    return samples, fallbacks


def word(value):
    return f'{value:016x}'


def encode_samples(samples):
    return ';'.join(word(k) + ':' + ','.join(word(v) for v in samples[k])
                    for k in sorted(samples)) or '-'


def encode_fallbacks(fallbacks):
    return ';'.join(word(k) + ':' + word(fallbacks[k]) for k in sorted(fallbacks)) or '-'


def encode_records(records):
    return ';'.join(','.join(word(v) for v in record) for record in records) or '-'


def input_line(case_id, case):
    return '\t'.join([case_id, f'{case.flag:02x}', encode_samples(case.samples),
                      encode_fallbacks(case.fallbacks), encode_records(case.records)]) + '\n'


def output_line(case_id, result):
    return '\t'.join([case_id, encode_samples(result[0]), encode_fallbacks(result[1])]) + '\n'


def parse_word(text):
    require(re.fullmatch('[0-9a-f]{16}', text) is not None, 'canonical u64')
    return int(text, 16)


def parse_map(text, samples):
    if text == '-':
        return {}
    result = {}
    previous = -1
    for item in text.split(';'):
        parts = item.split(':')
        require(len(parts) == 2, 'map entry separator')
        key = parse_word(parts[0])
        require(key > previous, 'strict unsigned map order')
        previous = key
        result[key] = ([parse_word(v) for v in parts[1].split(',')] if parts[1] else []) if samples else parse_word(parts[1])
    return result


def decode_input(line):
    require(line.endswith('\n') and not line.endswith('\n\n'), 'input LF')
    fields = line[:-1].split('\t')
    require(len(fields) == 5 and re.fullmatch('C[0-9]{6}', fields[0]) is not None, 'input frame')
    require(re.fullmatch('[0-9a-f]{2}', fields[1]) is not None, 'canonical dex byte')
    records = [] if fields[4] == '-' else [tuple(parse_word(v) for v in row.split(',')) for row in fields[4].split(';')]
    case = Case('decoded', int(fields[1], 16), parse_map(fields[2], True), parse_map(fields[3], False), records)
    validate(case)
    return fields[0], case


def hand_cases():
    """Explicit expected maps, authored before the general oracle/candidate run."""
    yield 'empty-preserves-empty-vector', Case('hand', 3, {7: [], 9: [11]}, {2: 13}, []), ({7: [], 9: [11]}, {2: 13})
    yield 'new-sample', Case('hand', 0, {}, {}, [(7, 0, 99)]), ({7: [99]}, {})
    yield 'append-existing', Case('hand', 3, {7: [10]}, {7: 80}, [(7, 0, 11), (7, 4, 12)]), ({7: [10, 11, 12]}, {7: 80})
    yield 'stop-first', Case('hand', 3, {7: []}, {7: 80}, [(7, 2, 99), (7, 0, 100)]), ({7: []}, {7: 80})
    yield 'stop-middle', Case('hand', 3, {}, {}, [(7, 0, 1), (7, 2, 2), (7, 1, 3)]), ({7: [1]}, {})
    yield 'wide-low-byte-two', Case('hand', 3, {}, {}, [(7, 0x102, 1), (7, HIGH + 2, 2)]), ({7: [1, 2]}, {})
    yield 'high-even-tag', Case('hand', 3, {}, {}, [(7, HIGH, U64)]), ({7: [U64]}, {})
    yield 'high-odd-tag', Case('hand', 3, {}, {}, [(7, U64, HIGH)]), ({}, {7: HIGH})
    yield 'tag-three-fallback', Case('hand', 3, {7: []}, {}, [(7, 3, 1)]), ({7: []}, {7: 1})
    yield 'guard-one-ignores', Case('hand', 1, {7: [1]}, {7: 2}, [(7, 1, 3)]), ({7: [1]}, {7: 2})
    yield 'guard-255-ignores', Case('hand', 255, {}, {7: 2}, [(7, U64, 3)]), ({}, {7: 2})
    yield 'last-fallback-wins', Case('hand', 3, {}, {7: 0, 9: 4}, [(7, 1, 1), (7, 3, 2)]), ({}, {7: 2, 9: 4})
    yield 'mixed-same-key', Case('hand', 3, {7: [0]}, {7: 9}, [(7, 0, 1), (7, 1, 2), (7, 4, 3), (7, 5, 4)]), ({7: [0, 1, 3]}, {7: 4})
    yield 'raw-nan-and-sign-bits', Case('hand', 3, {}, {}, [(0, 0, 0x7ff8000000000042), (0, 0, HIGH), (0, 0, 0x7ff0000000000001)]), ({0: [0x7ff8000000000042, HIGH, 0x7ff0000000000001]}, {})
    yield 'unsigned-key-boundaries', Case('hand', 3, {}, {}, [(U64, 0, 1), (0, 0, 2), (HIGH, 0, 3), (HIGH - 1, 0, 4)]), ({0: [2], HIGH - 1: [4], HIGH: [3], U64: [1]}, {})
    yield 'even-max-minus-one', Case('hand', 2, {}, {0: 1}, [(0, U64 - 1, 2)]), ({0: [2]}, {0: 1})
    yield 'unrelated-initial-entries', Case('hand', 3, {1: [], 9: [U64]}, {1: 5, 9: 6}, [(7, 0, 8), (7, 1, 9)]), ({1: [], 7: [8], 9: [U64]}, {1: 5, 7: 9, 9: 6})
    yield 'append-initially-empty', Case('hand', 3, {7: []}, {}, [(7, 0, 0)]), ({7: [0]}, {})
    yield 'fallback-does-not-create-sample', Case('hand', 3, {}, {}, [(7, 1, 0)]), ({}, {7: 0})
    yield 'stop-after-fallback', Case('hand', 3, {}, {7: 9}, [(7, 1, 1), (7, 2, 2), (7, 1, 3)]), ({}, {7: 1})


def initial_state(key, present):
    other = key ^ 0x5555555555555555
    samples, fallbacks = {other: [U64]}, {other: HIGH}
    if present:
        samples[key] = [] if key % 2 else [0, U64]
        fallbacks[key] = 0x7ff8000000000001
    return samples, fallbacks


def cases():
    for _, case, result in hand_cases():
        validate(case)
        require(expected(case) == result, 'explicit hand expectation')
        yield case
    for flag, present in itertools.product(range(256), (False, True)):
        samples, fallbacks = initial_state(7, present)
        yield Case('all-dex-bytes', flag, samples, fallbacks,
                   [(7, 1, 10), (7, 0, 11), (7, 3, 12), (9, U64, 13),
                    (9, HIGH, 14), (7, 2, 15), (7, 0, 16), (9, 1, 17)])
    tags = (0, 1, 2, 3, 4, 5, 255, 256, 257, 258, HIGH - 2, HIGH - 1, HIGH, HIGH + 1, HIGH + 2, U64 - 1, U64)
    keys = (0, 1, 7, HIGH - 1, HIGH, U64)
    payloads = (0, 1, U64, HIGH, HIGH - 1, 0x7ff0000000000000,
                0xfff0000000000000, 0x7ff0000000000001, 0x7ff8000000000042, 0x0123456789abcdef)
    for tag, key, payload, flag, present in itertools.product(tags, keys, payloads, (0, 3, 255), (False, True)):
        samples, fallbacks = initial_state(key, present)
        yield Case('wide-tags-keys-payloads', flag, samples, fallbacks,
                   [(key, tag, payload), (key, 0, payload ^ U64), (key, 1, payload ^ HIGH)])
    pair_tags = (0, 1, 2, 3, 4, 258, HIGH, U64)
    for first, second, same, flag, present in itertools.product(pair_tags, pair_tags, (False, True), (2, 3), (False, True)):
        samples, fallbacks = initial_state(7, present)
        yield Case('ordered-tag-pairs', flag, samples, fallbacks,
                   [(7, first, 11), (7 if same else U64, second, 22)])
    for bit in range(64):
        mask = 1 << bit
        for which in range(6):
            key, tag, payload = [(mask, 0, U64), (mask ^ U64, 1, HIGH),
                                 (7, mask, U64), (7, mask ^ U64, HIGH),
                                 (7, 0, mask), (7, 1, mask ^ U64)][which]
            yield Case('single-bit-fields', 3, {9: []}, {9: U64},
                       [(key, tag, payload), (7, 0, 0x1234), (7, 1, 0x5678)])
    for count, flag, present in itertools.product((0, 1, 4, 5, 10, 11, 12, 22, 23, 64, 129, 513), (0, 3), (False, True)):
        samples = {k: [U64 - k] for k in range(17)} if present else {}
        fallbacks = {k: HIGH + k for k in range(17)} if present else {}
        records = [(i, 0 if i % 3 else 1, (i * 0x1020304050607) & U64) for i in reversed(range(count))]
        records += [(7, 0, i) for i in range(count)] + [(7, 1, U64 - i) for i in range(count)]
        yield Case('long-distinct-and-repeated', flag, samples, fallbacks, records)
    for count, position, flag in itertools.product((1, 2, 11, 12, 64, 257), ('start', 'middle', 'end'), (0, 3)):
        records = [(i % 13, i % 2, U64 - i) for i in range(count)]
        index = {'start': 0, 'middle': count // 2, 'end': count}[position]
        records[index:index] = [(7, 2, 123)]
        yield Case('sentinel-positions', flag, {7: [], 99: [1]}, {7: 2, 99: 3}, records)
    rng = random.Random(SEED)
    for _ in range(512):
        keyset = sorted({0, U64, HIGH, *[rng.getrandbits(64) for _ in range(9)]})
        samples = {key: [rng.getrandbits(64) for _ in range(rng.randrange(5))]
                   for key in keyset if rng.randrange(3) == 0}
        fallbacks = {key: rng.getrandbits(64) for key in keyset if rng.randrange(3) == 0}
        records = [(rng.choice(keyset), rng.choice(tags) if rng.randrange(3) else rng.getrandbits(64), rng.getrandbits(64))
                   for _ in range(rng.randrange(193))]
        yield Case('seeded-synthetic-streams', rng.choice((0, 1, 2, 3, 255)), samples, fallbacks, records)


def generate(out):
    require(not out.exists(), 'existing corpus output refused')
    inputs, outputs, witnesses = [], [], []
    groups = Counter()
    total_records = 0
    maximum_records = 0
    hand = list(hand_cases())
    for index, case in enumerate(cases()):
        validate(case)
        case_id = f'C{index:06d}'
        encoded = input_line(case_id, case)
        decoded_id, decoded = decode_input(encoded)
        require(decoded_id == case_id and decoded.flag == case.flag and
                decoded.samples == case.samples and decoded.fallbacks == case.fallbacks and
                decoded.records == case.records, 'input protocol round trip')
        result = expected(case)
        inputs.append(encoded)
        outputs.append(output_line(case_id, result))
        groups[case.group] += 1
        total_records += len(case.records)
        maximum_records = max(maximum_records, len(case.records))
        if index < len(hand):
            witnesses.append({'id': case_id, 'name': hand[index][0],
                              'input': encoded.rstrip('\n'), 'expected': outputs[-1].rstrip('\n')})
    raw_inputs, raw_outputs = ''.join(inputs).encode('ascii'), ''.join(outputs).encode('ascii')
    require(len(inputs) == len(outputs) and len(set(line.split('\t', 1)[0] for line in outputs)) == len(outputs),
            'complete unique output IDs')
    out.mkdir(parents=True)
    identities = {}
    for name, raw in [('cases.tsv.gz', raw_inputs), ('expected.tsv.gz', raw_outputs)]:
        stored = gzip.compress(raw, mtime=0)
        require(gzip.decompress(stored) == raw, 'gzip exact round trip')
        (out / name).write_bytes(stored)
        identities[name] = {'raw_bytes': len(raw), 'stored_bytes': len(stored),
                            'raw_sha256': hashlib.sha256(raw).hexdigest(),
                            'stored_sha256': hashlib.sha256(stored).hexdigest()}
    metadata = {'protocol': 1, 'cases': len(inputs), 'groups': dict(sorted(groups.items())),
                'input_records': total_records, 'maximum_records_per_case': maximum_records,
                'seed': hex(SEED), 'identities': identities,
                'oracle': 'First full-tag2 prefix, per-key even-payload concatenation, reverse-prefix last-odd selection for exact dex byte3.',
                'limit': 'Independent mathematical expectations before Rust source; no target execution, native-output observation, instruction evaluation or economic semantics.'}
    (out / 'corpus.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (out / 'hand-witnesses.json').write_text(json.dumps(witnesses, indent=2) + '\n')
    return metadata


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        summary = generate(arguments.out)
        print(json.dumps(summary, indent=2))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
