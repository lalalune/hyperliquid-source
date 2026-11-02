#!/usr/bin/env python3
"""Authenticate the independently frozen pre-Rust wire authority.

Protocol/active-field checks only, with actual static native closure. No Rust
feedback supplies expectations and no captured opcode/PC/register evaluator runs.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path
import re

import signed_varint_i64_contract as native

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-005-signed-varint-i64-94'
PREP = PACKET / 'preparation'
FREEZE_SHA256 = '28294f3fcd101cd27d2b4ef5954f5cabf4299dacd8f8585611bc64ce6130e63d'
PROOF_SHA256 = '8563eb88002a36a7c8f2cd8e5bf1143e04b84f02d83b9dce9ae7658d7d936d22'
NATIVE_REVIEW_SHA256 = '6b5952027c1bcb03750a2f1963e704008e80bedfc71e8cdbb51fc58e92b49fae'
GENERATOR_SHA256 = '6b05cf99765c170f9c5e52df8a27a10d134db5e55e814704086ef534efdb5b07'
UNIT_SHA256 = 'e35b797ca1f52f103504371ac18843bc90fdfc29d24627d79ebd2cebaf1716a7'
KEYS = ['additional', 'bits', 'call', 'consumed', 'cursor', 'expected', 'found',
        'id', 'remaining', 'tag', 'tail', 'value']


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(binary):
    freeze_raw = (PREP / 'independent-FREEZE.json').read_bytes()
    need(sha(freeze_raw) == FREEZE_SHA256, 'Independent pre-Rust freeze differs')
    freeze = json.loads(freeze_raw)
    need(freeze['stimuli'] == 27671 and freeze['observations'] == 89218
         and freeze['active_fields_only'] is True, 'Independent denominator/projection differs')
    for name, digest in [('PROOF.md', PROOF_SHA256), ('NATIVE-REVIEW.json', NATIVE_REVIEW_SHA256),
                         ('generate.py', GENERATOR_SHA256)]:
        need(sha((PREP / ('independent-' + name)).read_bytes()) == digest,
             'Original independent proof/review/generator differs: ' + name)
    origin = json.loads((PREP / 'independent-ORIGIN.json').read_text())
    need(origin['freeze_sha256'] == FREEZE_SHA256 and origin['proposed_signed_Rust_absent'] is True
         and origin['new_signed_Rust_read_or_authored_by_oracle_author'] is False
         and origin['author_head_before_new_Rust'] == 'c6d3102e3fde1ab60365f4f3848a3f8600c252a7',
         'Historical pre-source origin linkage differs')
    files = {}
    for name, record in freeze['files'].items():
        need(name in ('authority.json', 'inputs.tsv', 'expected.jsonl'), 'Unexpected authority member')
        packed = (PREP / ('independent-' + name + '.gz')).read_bytes()
        need(len(packed) < 8 << 20 and record['bytes'] < 32 << 20, 'Authority member too large')
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
            raw = stream.read(record['bytes'] + 1)
        need(len(raw) == record['bytes'] and sha(raw) == record['sha256'],
             'Original independent authority bytes differ: ' + name)
        files[name] = raw
    need(set(files) == {'authority.json', 'inputs.tsv', 'expected.jsonl'}, 'Authority incomplete')
    stimuli = []
    seen = set()
    for line in files['inputs.tsv'].splitlines():
        fields = line.split(b'|')
        need(len(fields) == 4 and re.fullmatch(rb'[A-Za-z0-9_-]{1,64}', fields[0]) is not None,
             'Raw stimulus identity/protocol differs')
        need(fields[0] not in seen and re.fullmatch(rb'[0-9]+', fields[1]) is not None
             and 0 <= int(fields[1]) <= 255 and re.fullmatch(rb'(?:[0-9a-f]{2})*', fields[2]) is not None
             and len(fields[2]) <= 8192 and fields[3] in (b'1', b'2', b'3', b'4'),
             'Raw stimulus fields differ')
        seen.add(fields[0]);stimuli.append((fields[0].decode(), int(fields[1]), bytes.fromhex(fields[2].decode()), int(fields[3])))
    need(len(stimuli) == 27671, 'Distinct stimulus denominator differs')
    answers = files['expected.jsonl'].splitlines()
    need(len(answers) == 89218 and files['expected.jsonl'].endswith(b'\n'), 'Observation denominator/framing differs')
    first = {};offset = 0
    for identifier, flag, wire, calls in stimuli:
        cursor = 0
        for call in range(1, calls + 1):
            row_raw = answers[offset];offset += 1;row = json.loads(row_raw)
            need(list(row) == KEYS and row_raw == json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode(),
                 'Expected JSON observation is not canonical')
            need(row['id'] == identifier and row['call'] == call and type(row['consumed']) is int
                 and 0 <= row['consumed'] <= len(wire) - cursor, 'Expected call identity/consumption differs')
            cursor += row['consumed']
            need(row['cursor'] == cursor and row['remaining'] == len(wire) - cursor
                 and row['tail'] == wire[cursor:].hex(), 'Expected residual state differs')
            tag = row['tag']
            if tag == 18:
                need(type(row['value']) is int and -(1 << 63) <= row['value'] < 1 << 63
                     and row['bits'] == format(row['value'] % (1 << 64), '016x')
                     and all(row[k] is None for k in ('additional', 'expected', 'found')),
                     'Success active projection differs')
            elif tag == 0:
                need(type(row['additional']) is int and 1 <= row['additional'] <= 8
                     and all(row[k] is None for k in ('value', 'bits', 'expected', 'found')),
                     'Shortfall active projection differs')
            elif tag == 3:
                need(row['expected'] in (8, 9) and row['found'] in (10, 12)
                     and all(row[k] is None for k in ('value', 'bits', 'additional')),
                     'Type-error active projection differs')
            else:
                raise ValueError('Unexpected normal tag in independent authority')
            if call == 1:
                first[identifier] = (flag, wire, row)
    need(offset == len(answers), 'Expected calls leave extra observations')
    fixture = (ROOT / 'src/node94-signed-varint-i64/unit-vectors.tsv').read_bytes()
    need(sha(fixture) == UNIT_SHA256, 'Twenty-case authority extraction changed')
    unit_receipt = json.loads((PREP / 'UNIT-FIXTURE-RECEIPT.json').read_text())
    need(unit_receipt['selection_after_implementation_authoring'] is True
         and unit_receipt['expectation_parent_precedes_Rust'] is True
         and unit_receipt['parent_freeze_sha256'] == FREEZE_SHA256, 'Unit extraction chronology differs')
    for line in fixture.decode().splitlines():
        fields = line.split('|');flag, wire, row = first[fields[0]]
        expected = [fields[0], str(flag), wire.hex(), str(row['tag'])]
        expected += ['~' if row[k] is None else str(row[k]) for k in ('value', 'bits', 'additional', 'expected', 'found')]
        expected += [str(row['consumed']), str(row['remaining']), row['tail']]
        need(fields == expected, 'Unit vector is not an unchanged independent first call')
    need(len(fixture.splitlines()) == 20, 'Unit vector denominator differs')
    actual_native = native.analyze(Path(binary).read_bytes())
    return {'inputs': files['inputs.tsv'], 'expected': files['expected.jsonl'], 'fixture': fixture,
            'stimuli': stimuli, 'native_record': actual_native,
            'metadata': {'stimuli': 27671, 'observations': 89218, 'pre_Rust_freeze_sha256': FREEZE_SHA256,
                         'independent_native_proof_sha256': PROOF_SHA256,
                         'native_review_sha256': NATIVE_REVIEW_SHA256,
                         'expected_sha256': sha(files['expected.jsonl']), 'input_sha256': sha(files['inputs.tsv']),
                         'logical_tag_counts': freeze['logical_tag_counts'],
                         'mathematical_dispatch_counts': freeze['mathematical_dispatch_counts'],
                         'ordinary_unit_methods': 1, 'unit_first_calls': 20,
                         'unit_extraction_after_source': True, 'active_fields_only': True,
                         'captured_execution': False, 'instruction_evaluator': False}}
