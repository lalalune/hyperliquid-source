"""Qualify the value reference against sealed literal expectations.

Draft only until root execution admission. Reads three specified JSON files;
writes a fresh output directory. No subprocess, network or native artifact.
Parent must authenticate all source files before this module is imported/run.
"""
import argparse
import hashlib
import json
from pathlib import Path

from reference_math import DomainError, Found, Ring, Row

PINS = {
    'handcases': '21b7bafc2a85c84879c32ef72dcb849f9e073dd06875cc636b0861aea8e843ad',
    'host_invalid': '5d45a4b2bc46db37c98b412f30df594c75d130d61f9564096bb8b874a95962cc',
    'manual_freeze': '8a935e4bf7f9d8e9e7d2c1415a9a61cf02b634d3bb3517c6fabd19fb001c91f7',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ring_from_case(case, keys):
    if case['capacity'] != len(case['physical_rows']):
        raise DomainError('declared physical allocation is incomplete')
    rows = tuple(Row(keys[name], int(value)) for name, value in case['physical_rows'])
    return Ring(rows, case['head'], case['live_len'])


def as_manual_search(result):
    if isinstance(result, Found):
        return {'tag': 0, 'logical_index': result.logical_index,
                'physical_index': result.physical_index, 'value_u64': str(result.value)}
    return {'tag': 1, 'insertion_index': result.insertion_index}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in PINS:
        parser.add_argument('--'+name.replace('_','-'), type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be fresh')
    inputs, identities = {}, {}
    for name, expected in PINS.items():
        content = getattr(args, name).read_bytes()
        if digest(content) != expected:
            parser.error(name+' identity mismatch')
        inputs[name] = json.loads(content)
        identities[name] = {'bytes': len(content), 'sha256': expected}
    hand = inputs['handcases']
    keys = {name: bytes.fromhex(value) for name, value in hand['key_catalogue'].items()}
    mismatches, observations = [], []
    search_count = 0
    for case in hand['cases']:
        ring = ring_from_case(case, keys)
        queries = tuple(keys[name] for name in case['queries'])
        actual_searches = [as_manual_search(ring.search(query)) for query in queries]
        actual_material = ring.materialize(queries)
        material = None if actual_material is None else [str(v) for v in actual_material]
        search_count += len(queries)
        ok = actual_searches == case['searches'] and material == case['materializer']['result']
        observations.append({'id': case['id'], 'searches': actual_searches,
                             'materializer_value': material, 'matches_literal': ok})
        if not ok:
            mismatches.append({'id': case['id'], 'expected_searches': case['searches'],
                               'actual_searches': actual_searches,
                               'expected_materializer': case['materializer']['result'],
                               'actual_materializer': material})
    refusals = []
    for case in inputs['host_invalid']['cases']:
        stage = ('record_loader' if case['capacity'] != len(case['physical_rows'])
                 else 'ring_constructor')
        try:
            ring_from_case(case, keys)
        except DomainError as exc:
            refusals.append({'id': case['id'], 'stage': stage, 'host_refused': True, 'reason': str(exc)})
        else:
            refusals.append({'id': case['id'], 'stage': stage, 'host_refused': False})
            mismatches.append({'id': case['id'], 'expected': 'host refusal', 'actual': 'admitted'})
    if len(hand['cases']) != 24 or search_count != 64 or len(refusals) != 7:
        raise ValueError('sealed fixture counts differ from admission')
    sources = {name: digest((Path(__file__).parent/name).read_bytes())
               for name in ['reference_math.py', 'qualify_handcases.py']}
    report = {'schema': 1, 'result': 'PASS' if not mismatches else 'FAIL',
              'inputs': identities, 'source_sha256': sources, 'cases': len(observations),
              'standalone_searches': search_count, 'materializer_values': len(observations),
              'host_refusal_examples': len(refusals), 'mismatches': mismatches,
              'host_refusal_stages': {'record_loader': 1, 'ring_constructor': 6},
              'observations': observations, 'host_refusals': refusals,
              'limits': ['Manual expectations were not rewritten to fit the reference.',
                         'No reached-query or temporary-prefix trace is qualified.',
                         'X05 is record-loader capacity/row-count mismatch, not a representable Ring state.',
                         'Host refusal is not native-error equivalence; no allocator-failure test.',
                         'No captured execution or native differential oracle.']}
    args.output.mkdir(parents=True, exist_ok=False)
    encoded = (json.dumps(report, indent=2)+'\n').encode('utf-8')
    (args.output/'result.json').write_bytes(encoded)
    print(json.dumps({'result': report['result'], 'cases': 24, 'searches': 64,
                      'host_refusals': 7, 'mismatches': len(mismatches),
                      'result_sha256': digest(encoded)}, sort_keys=True))
    return 1 if mismatches else 0


if __name__ == '__main__':
    raise SystemExit(main())
