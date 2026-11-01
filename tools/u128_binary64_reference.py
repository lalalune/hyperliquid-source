#!/usr/bin/env python3
"""Authenticate the pre-Rust authority and recheck it by exact encoding search.

No target execution, opcode/PC evaluator or host floating conversion. The
binary64 ordering search is separate from the independently authored Rust.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path
import re

import u128_binary64_contract as native

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-u128-binary64-94'
PREP = PACKET / 'preparation'
FREEZE_SHA256 = '46fcb655e66a84595ac8786ab5c7a4ba67b4912ca7ce0a2329f51f34719b9230'
ROOT_PROOF_SHA256 = 'd4fbdabeb04e2ec746508acd123b347cd11d990d1689588c282d7f9ef33985d6'
UNIT_SHA256 = '1a03105a179ea780da85fa2e10ca160fb79d4a4d64ad2a8ed84883bd81fe0251'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ratio(bits):
    """Exact nonnegative finite binary64 numerator/denominator, no float."""
    exponent, fraction = bits >> 52, bits & ((1 << 52) - 1)
    significand = fraction | ((1 << 52) if exponent else 0)
    shift = exponent - 1075 if exponent else -1074
    return (significand << shift, 1) if shift >= 0 else (significand, 1 << -shift)


def encoding_search(n):
    """Find the two enclosing representable values, compare exact distances."""
    need(type(n) is int and 0 <= n < 1 << 128, 'Expected an unsigned128 integer')
    if not n:
        return 0
    lo, hi = 0, 0x47f0000000000000  # +0 and exactly2^128 enclose all u128.
    while lo + 1 < hi:
        mid = (lo + hi) >> 1
        a, b = ratio(mid)
        if a < n * b:
            lo = mid
        else:
            hi = mid
    a, b = ratio(lo)
    c, d = ratio(hi)
    below, above = (n * b - a) * d, (c - n * d) * b
    if below < above:
        return lo
    if above < below:
        return hi
    return lo if lo & 1 == 0 else hi


def fresh(binary):
    raw_freeze = (PREP / 'root-FREEZE.json').read_bytes()
    need(sha(raw_freeze) == FREEZE_SHA256, 'Independent pre-Rust freeze changed')
    freeze = json.loads(raw_freeze)
    need(freeze['rows'] == 16614 and freeze['unique_u128_values'] == 16610
         and freeze['new_Rust_seen'] is False, 'Independent freeze denominator differs')
    files = {}
    for name, record in freeze['files'].items():
        need(name in ('freeze.py', 'input.tsv', 'expected.tsv'), 'Unexpected authority file')
        compressed = (PREP / ('root-' + name + '.gz')).read_bytes()
        need(len(compressed) < 1 << 20, 'Authority archive too large')
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(record['bytes'] + 1)
        need(len(raw) == record['bytes'] and sha(raw) == record['sha256'],
             'Original independent authority bytes changed: ' + name)
        files[name] = raw
    need(set(files) == {'freeze.py', 'input.tsv', 'expected.tsv'}, 'Authority files incomplete')
    need(sha((PREP / 'root-NATIVE-PROOF.md').read_bytes()) == ROOT_PROOF_SHA256,
         'Independent complete native proof changed')
    receipts = json.loads((PREP / 'root-PROOF-RECEIPT.json').read_text())
    need(receipts['beforeNewRust'] is True and receipts['proofSha256'] == ROOT_PROOF_SHA256
         and receipts['frozenAuthoritySha256'] == FREEZE_SHA256
         and receipts['targetBodySha256'] == native.BODY_SHA256, 'Native authority linkage differs')
    inputs, answers = files['input.tsv'].splitlines(), files['expected.tsv'].splitlines()
    need(len(inputs) == len(answers) == 16614, 'Independent row denominator differs')
    cases, identifiers = [], set()
    for stimulus, answer in zip(inputs, answers):
        parts, expected = stimulus.split(b'|'), answer.split(b'|')
        need(len(parts) == len(expected) == 2 and parts[0] == expected[0]
             and re.fullmatch(rb'[A-Za-z0-9_-]{1,64}', parts[0]) is not None
             and re.fullmatch(rb'[0-9a-f]{32}', parts[1]) is not None
             and re.fullmatch(rb'[0-9a-f]{16}', expected[1]) is not None,
             'Authority protocol is not exact')
        need(parts[0] not in identifiers, 'Authority case identity duplicated')
        identifiers.add(parts[0])
        n, bits = int(parts[1], 16), int(expected[1], 16)
        need(encoding_search(n) == bits, 'Independent exact-encoding search disagreement')
        cases.append((parts[0].decode('ascii'), n, bits))
    need(len({n for _, n, _ in cases}) == 16610, 'Unique numerical denominator differs')
    fixture = (ROOT / 'src/node94-u128-binary64/unit-vectors.tsv').read_bytes()
    need(sha(fixture) == UNIT_SHA256, 'Pre-source twenty-case unit fixture differs')
    unit_freeze = json.loads((PREP / 'UNIT-FIXTURE-FREEZE.json').read_text())
    need(unit_freeze['before_new_Rust'] is True and unit_freeze['fixture_sha256'] == UNIT_SHA256
         and unit_freeze['parent_FREEZE_sha256'] == FREEZE_SHA256
         and unit_freeze['rows'] == 20 and unit_freeze['unit_method_count'] == 1,
         'Unit freeze linkage differs')
    whole = {f'{i}|{n:032x}|{b:016x}'.encode() for i, n, b in cases}
    need(len(fixture.splitlines()) == 20 and all(line in whole for line in fixture.splitlines()),
         'Unit fixture is not an unchanged authority subset')
    target = Path(binary).read_bytes()
    need(len(target) == 91774280 and sha(target) == native.TARGET_SHA256, 'Full target identity differs')
    native_record = native.inspect_target(target)
    return {'cases': cases, 'inputs': files['input.tsv'], 'expected': files['expected.tsv'],
            'fixture': fixture, 'native_proof': native_record,
            'metadata': {'rows': 16614, 'unique_u128': 16610,
                         'pre_Rust_freeze_sha256': FREEZE_SHA256,
                         'independent_native_proof_sha256': ROOT_PROOF_SHA256,
                         'fresh_recheck_method': 'Integer binary search of ordered finite IEEE encodings, exact rational distances and tie parity',
                         'original_authority_method': freeze['expected_method'],
                         'primary_expected_sha256': sha(files['expected.tsv']),
                         'primary_inputs_sha256': sha(files['input.tsv']),
                         'fixture_sha256': UNIT_SHA256, 'ordinary_unit_methods': 1,
                         'ordinary_unit_fixture_rows': 20,
                         'target_sha256': native.TARGET_SHA256, 'captured_execution': False,
                         'instruction_evaluator': False}}
