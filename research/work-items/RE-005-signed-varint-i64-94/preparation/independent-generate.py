#!/usr/bin/env python3
"""Independent byte-symbol mathematics and separate raw wire serialization."""
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1
MIN_SIGNED = -(1 << 63)
MAX_SIGNED = (1 << 63) - 1
cases = []
seen = set()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def add(symbols, flag, calls, reason):
    symbols = tuple(symbols)
    assert 0 <= flag <= 255 and 1 <= calls <= 4
    assert len(symbols) <= 4096 and all(0 <= byte <= 255 for byte in symbols)
    key = (symbols, flag, calls)
    if key in seen:
        return
    seen.add(key)
    cases.append({'id': f's{len(cases):06d}', 'wire_symbols': list(symbols),
                  'raw_DL': flag, 'calls': calls, 'reason': reason})


def serialize_symbols(symbols):
    return ''.join(format(symbol, '02x') for symbol in symbols)


def encode_payload(value, width, big):
    assert 0 <= value < 1 << (8 * width)
    little = [(value // (256 ** index)) % 256 for index in range(width)]
    return list(reversed(little)) if big else little


def encode_canonical_signed(value, big):
    assert MIN_SIGNED <= value <= MAX_SIGNED
    unsigned = 2 * value if value >= 0 else -2 * value - 1
    if unsigned < 251:
        return [unsigned]
    width, marker = ((2, 251) if unsigned < 1 << 16 else
                     (4, 252) if unsigned < 1 << 32 else (8, 253))
    return [marker] + encode_payload(unsigned, width, big)


for flag in [0, 1, 2, 128, 255]:
    add([], flag, 4, 'repeated-empty')
    for marker in range(256):
        for length in range(1, 13):
            tail = [(marker + 17 * index + 3) % 256 for index in range(length - 1)]
            add([marker] + tail, flag, 3 if length <= 8 else 4,
                'all-tags-each-length-through-fast-slow-boundary')

representatives = [[], [1] * 10, [251, 1, 2], [251, 1, 2] + [0] * 6,
                   [252, 1, 2, 3, 4], [252, 1, 2, 3, 4] + [0] * 4,
                   [253, 1, 2, 3, 4, 5, 6, 7],
                   [253, 1, 2, 3, 4, 5, 6, 7, 8],
                   [254], [254] + [0] * 8, [255], [255] + [0] * 8]
for flag in range(256):
    for symbols in representatives:
        add(symbols, flag, 3, 'all-raw-DL-bytes-both-dispatch-classes')

signed_values = {MIN_SIGNED, MIN_SIGNED + 1, -252, -251, -127, -126,
                 -125, -2, -1, 0, 1, 2, 125, 126, 127, 250, 251,
                 MAX_SIGNED - 1, MAX_SIGNED}
unsigned_values = {0, 1, 2, 3, 249, 250, 251, 252, 253, 254, 255, MAX - 1, MAX}
for bit in range(64):
    for delta in range(-2, 3):
        candidate = (1 << bit) + delta
        if 0 <= candidate <= MAX:
            unsigned_values.add(candidate)
        for signed in [candidate, -candidate]:
            if MIN_SIGNED <= signed <= MAX_SIGNED:
                signed_values.add(signed)
for value in sorted(signed_values):
    for flag in [0, 255]:
        encoded = encode_canonical_signed(value, flag != 0)
        for tail in [[], [1] * max(0, 9 - len(encoded)), [254, 2]]:
            add(encoded + tail, flag, 4, 'signed-endpoints-parity-and-power-boundaries')
for value in sorted(unsigned_values):
    for width, marker in [(2, 251), (4, 252), (8, 253)]:
        if value >= 1 << (width * 8):
            continue
        for flag in [0, 255]:
            encoded = [marker] + encode_payload(value, width, flag != 0)
            for tail in [[], [0] * max(0, 9 - len(encoded))]:
                add(encoded + tail, flag, 4, 'payload-boundaries-including-nonminimal-widths')

# Every possible byte in every position of the full-width payload, in both
# byte orders. The proof, rather than this finite basis, covers all u64 words.
for position in range(8):
    for byte in range(256):
        payload = [0] * 8
        payload[position] = byte
        for flag in [0, 255]:
            add([253] + payload, flag, 2, 'all-byte-values-at-each-u64-payload-position')

sequences = [[254, 4], [255, 251, 0, 1, 0], [254] + [1] * 8,
             [255] + [1] * 8, [251, 0, 0, 253, 1, 2, 3, 4, 5, 6, 7],
             [253] + [255] * 8 + [254], [1] * 11,
             [252, 0, 0, 0, 128, 251, 1], [251, 251, 0, 252, 1, 2, 3, 4]]
for flag in [0, 1, 127, 255]:
    for symbols in sequences:
        add(symbols, flag, 4, 'stateful-threshold-and-error-then-read-sequences')
for ordinal in range(1024):
    raw = hashlib.sha256(b'signed64-wire-math-v1:' + str(ordinal).encode()).digest()
    symbols = list(raw[:1 + ordinal % 24])
    add(symbols, raw[-1], 4, 'deterministic-mixed-wire-symbols')


def mathematical_read(symbols, cursor, flag):
    remaining = len(symbols) - cursor
    outcome = {'tag': None, 'value': None, 'bits': None, 'additional': None,
               'expected': None, 'found': None}
    if remaining == 0:
        outcome.update(tag=0, additional=1)
        return outcome, 0
    marker = symbols[cursor]
    fast = remaining > 8
    if marker >= 254:
        outcome.update(tag=3, expected=8 if fast else 9,
                       found=10 if marker == 254 else 12)
        return outcome, 0 if fast else 1
    if marker < 251:
        unsigned, consumed = marker, 1
    else:
        width = {251: 2, 252: 4, 253: 8}[marker]
        total = 1 + width
        if remaining < total:
            assert not fast
            outcome.update(tag=0, additional=total - remaining)
            return outcome, 1
        payload = symbols[cursor + 1:cursor + total]
        significance = list(reversed(payload)) if flag != 0 else payload
        unsigned = sum(symbol * 256 ** index for index, symbol in enumerate(significance))
        consumed = total
    # Integer quotient/parity formula, not a register/SHR/XOR evaluator.
    signed = unsigned // 2 if unsigned % 2 == 0 else -(unsigned // 2 + 1)
    assert MIN_SIGNED <= signed <= MAX_SIGNED
    bits = signed if signed >= 0 else (1 << 64) + signed
    outcome.update(tag=18, value=signed, bits=format(bits, '016x'))
    return outcome, consumed


inputs, observations = [], []
tags, dispatch, classes = Counter(), Counter(), Counter()
for case in cases:
    symbols, cursor = case['wire_symbols'], 0
    inputs.append(f"{case['id']}|{case['raw_DL']}|{serialize_symbols(symbols)}|{case['calls']}")
    for index in range(1, case['calls'] + 1):
        dispatch['fast' if len(symbols) - cursor > 8 else 'Reader'] += 1
        row, consumed = mathematical_read(symbols, cursor, case['raw_DL'])
        cursor += consumed
        row.update(id=case['id'], call=index, consumed=consumed, cursor=cursor,
                   remaining=len(symbols) - cursor, tail=serialize_symbols(symbols[cursor:]))
        tags[str(row['tag'])] += 1
        observations.append(json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
    classes[case['reason']] += 1

authority = {'schema': 'independent-signed64-wire-pre-source-authority-v1',
             'target_sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
             'primary_range': ['0x4b6fa60', '0x4b6fbc5'], 'primary_bytes': 357, 'primary_rows': 99,
             'proof_sha256': digest((ROOT / 'PROOF.md').read_bytes()),
             'native_review_sha256': digest((ROOT / 'NATIVE-REVIEW.json').read_bytes()),
             'cases': cases, 'stimulus_count': len(cases), 'observation_count': len(observations),
             'logical_tag_counts': dict(tags), 'mathematical_dispatch_counts': dict(dispatch),
             'case_classes': dict(classes),
             'limits': ['Mathematical byte-symbol model, no captured instruction or target execution.',
                        'Only active fields; null never means native padding is zero or unwritten.',
                        'Primary357 distinct from supporting previously established330 bytes.',
                        'No originalABI, enclosingcaller, fullcodec, newbyteidentity or gate claim.']}
files = {'authority.json': (json.dumps(authority, indent=2, sort_keys=True) + '\n').encode(),
         'inputs.tsv': ('\n'.join(inputs) + '\n').encode(),
         'expected.jsonl': ('\n'.join(observations) + '\n').encode()}
for name, raw in files.items():
    (ROOT / name).write_bytes(raw)
seal = {'schema': 'signed64-independent-pre-source-freeze-v1', 'stimuli': len(cases),
        'observations': len(observations), 'logical_tag_counts': dict(tags),
        'mathematical_dispatch_counts': dict(dispatch),
        'files': {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in files.items()},
        'proof_sha256': digest((ROOT / 'PROOF.md').read_bytes()),
        'native_review_sha256': digest((ROOT / 'NATIVE-REVIEW.json').read_bytes()),
        'generator_sha256': digest(Path(__file__).read_bytes()),
        'active_fields_only': True, 'captured_instruction_or_target_execution': False}
(ROOT / 'FREEZE.json').write_text(json.dumps(seal, indent=2, sort_keys=True) + '\n')
print(json.dumps({key: seal[key] for key in ['stimuli', 'observations', 'logical_tag_counts', 'mathematical_dispatch_counts']}, sort_keys=True))
