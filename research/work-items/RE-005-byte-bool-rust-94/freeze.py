#!/usr/bin/env python3
"""Independent integer/byte/suffix authority, frozen before new Rust."""
from pathlib import Path
import datetime
import hashlib
import json

ROOT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1
cases = []
seen = set()
families = {}


def add(family, kind, mode, counter, limit, raw):
    assert kind in ('u8', 'bool')
    assert 0 <= mode < 1 << 32 and 0 <= counter <= MAX and 0 <= limit <= MAX
    assert isinstance(raw, bytes)
    key = (kind, mode, counter, limit, raw)
    if key in seen:
        return
    seen.add(key)
    cases.append({'id': 'b%05d' % len(cases), 'family': family, 'kind': kind,
                  'mode': mode, 'counter': counter, 'limit': limit,
                  'input_hex': raw.hex()})
    families[family] = families.get(family, 0) + 1


def answer(case):
    raw = bytes.fromhex(case['input_hex'])
    counter = case['counter']
    written = case['mode'] == 1 and counter < MAX
    after = counter + int(written)
    rejected = case['mode'] == 1 and (counter == MAX or counter >= case['limit'])
    byte1 = None
    word8 = None
    used = 0
    if rejected:
        tag = 2
        word8 = 1 if case['kind'] == 'bool' else None
    elif not raw:
        tag = 0
        word8 = 1
    else:
        used = 1
        byte1 = raw[0]
        tag = 18 if case['kind'] == 'u8' or byte1 in (0, 1) else 8
    assert written == (after != counter)
    return {'id': case['id'], 'tag': tag, 'byte1_written': byte1,
            'word8_written': word8, 'counter_after': after,
            'counter_written': written, 'consumed': used,
            'remaining': len(raw) - used, 'tail_hex': raw[used:].hex()}


for kind in ('u8', 'bool'):
    for byte in range(256):
        for mode, counter, limit in ((0, 0, 0), (1, 0, 1)):
            for suffix in (b'', b'\x00\xff\x53\xa7'):
                add('all-byte-mode-budget-suffix', kind, mode, counter, limit,
                    bytes([byte]) + suffix)

for kind in ('u8', 'bool'):
    for mode in (0, 1, 2, 3, 0x7fffffff, 0x80000000, 0x80000001, 0xffffffff):
        for counter in (0, 1, 2, MAX - 2, MAX - 1, MAX):
            limits = sorted({0, 1, MAX, counter, max(counter - 1, 0),
                             min(counter + 1, MAX)})
            for limit in limits:
                for raw in (b'', b'\x00', b'\x01', b'\x02', b'\x80', b'\xff',
                            b'\x00\x00\xff', b'\xff\x01\x02\x03'):
                    add('counter-mode-and-limit-boundaries', kind, mode, counter, limit, raw)

for kind in ('u8', 'bool'):
    for size in (2, 3, 7, 8, 9, 15, 16, 17, 255, 256, 257, 4096):
        tail = bytes((i * 73 + 19) % 256 for i in range(size - 1))
        for byte in (0, 1, 2, 127, 128, 255):
            add('long-suffix-preservation', kind, 1, MAX - 1, MAX,
                bytes([byte]) + tail)

expected = [answer(case) for case in cases]
inputs = ''.join('\t'.join((case['id'], case['kind'], str(case['mode']),
                          str(case['counter']), str(case['limit']),
                          case['input_hex'])) + '\n' for case in cases).encode()
answers = ''.join(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n'
                  for row in expected).encode()
authority = (json.dumps({'schema': 'byte-decoder-independent-authority/1',
                        'cases': cases, 'expected': expected}, sort_keys=True,
                       indent=2) + '\n').encode()
for name, raw in [('inputs.tsv', inputs), ('expected.jsonl', answers),
                  ('authority.json', authority)]:
    (ROOT / name).write_bytes(raw)

sha = lambda raw: hashlib.sha256(raw).hexdigest()
freeze = {'schema': 'byte-decoders-independent-pre-source/1',
          'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'target_sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
          'native_receipt_sha256': sha((ROOT / 'NATIVE-INTAKE.json').read_bytes()),
          'proof_sha256': sha((ROOT / 'PROOF.md').read_bytes()),
          'cases': len(cases), 'distinct_complete_inputs_excluding_id': len(seen),
          'families': families,
          'tag_counts': {str(tag): sum(row['tag'] == tag for row in expected)
                         for tag in (0, 2, 8, 18)},
          'protocol': 'TSV id,kind(u8/bool),mode_decimal,counter_decimal,limit_decimal,input_hex. Canonical sorted-keys compact JSONL; absent byte1/word8 writes null, counter_written JSON boolean, other quantities decimal integers, tail lowercase hex.',
          'independence': {'new_Rust_read_or_authored': False,
                           'repository_imports': False,
                           'PC_register_opcode_evaluator': False,
                           'captured_execution': False,
                           'method': 'integer inequalities, unsigned byte values and slice suffixes'},
          'limits': ['normal separated nonwrapping immutable slices',
                     'chosen safe state/write projection, no original ABI/type/padding/pointer identity',
                     'no source or target machine-byte identity; full component gates false'],
          'files': {name: {'bytes': len(raw), 'sha256': sha(raw)}
                    for name, raw in [('freeze.py', Path(__file__).read_bytes()),
                                      ('inputs.tsv', inputs), ('expected.jsonl', answers),
                                      ('authority.json', authority)]}}
assert len(cases) == len(seen)
(ROOT / 'FREEZE.json').write_text(json.dumps(freeze, sort_keys=True, indent=2) + '\n')
print(json.dumps({'freeze_sha256': sha((ROOT / 'FREEZE.json').read_bytes()),
                  'cases': len(cases), 'families': families,
                  'proof_sha256': freeze['proof_sha256'],
                  'inputs_sha256': sha(inputs), 'expected_sha256': sha(answers)},
                 sort_keys=True))
