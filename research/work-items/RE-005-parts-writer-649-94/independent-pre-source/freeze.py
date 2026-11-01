#!/usr/bin/env python3
"""Pre-source declarative request oracle and separate raw serialization."""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
MAX = (1 << 64) - 1


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def words(part, salt):
    """Observed field layout only; expected request plans never enter TSV."""
    if part['kind'] == 'inactive':
        return part['words']
    high = ((salt * 0x9e3779b9) & 0xffffffff) << 32
    if part['kind'] == 'number':
        return [high | (part['number'] << 16) | 1,
                (0xfedcba9876543210 ^ salt) & MAX, (MAX - salt) & MAX]
    if part['kind'] == 'zeros':
        return [high | ((salt & 0xffff) << 16), part['number'], (MAX - salt) & MAX]
    return [high | ((salt & 0xffff) << 16) | part['tag'], part['token'], len(bytes.fromhex(part['payload']))]


def serialize(case):
    records = [words(part, index + 1) for index, part in enumerate(case['parts'])]
    record_text = ','.join(':'.join(format(word, 'x') for word in row) for row in records) or '-'
    views = ';'.join(format(token, 'x') + ':' + raw for token, raw in case['views']) or '-'
    methods = ','.join(format(table, 'x') + ':' + format(method, 'x') for table, method in case['methods']) or '-'
    steps = []
    for ordinal, reply, actions in case['script']:
        rendered = []
        for action in actions:
            if action[0] == 'state':
                rendered.append('S' + format(action[1], 'x'))
            else:
                rendered.append('M' + format(action[1], 'x') + ',' + format(action[2], 'x'))
        steps.append(str(ordinal) + '~' + str(reply) + '~' + ('/'.join(rendered) or '-'))
    return '\t'.join([case['id'], format(case['data'], 'x'), format(case['table'], 'x'),
                      format(case['prefix_token'], 'x'), format(case['prefix_length'], 'x'),
                      format(case['active_count'], 'x'), record_text, views, methods,
                      format(case['state'], 'x'), ';'.join(steps) or '-']).encode() + b'\n'


def expected(case):
    """High-level byte/decimal plans, not a decoder or native state model."""
    methods = dict(case['methods'])
    state = case['state']
    script = {ordinal: (reply, actions) for ordinal, reply, actions in case['script']}
    ordinal = 0
    events = []

    def emit(payload, repeats, method):
        nonlocal ordinal, state
        while repeats:
            reply, actions = script.get(ordinal, (0, []))
            if ordinal in script:
                count = 1
            else:
                later = min((number for number in script if number > ordinal), default=ordinal + repeats)
                count = min(repeats, later - ordinal)
            event = {'argument': payload, 'data': case['data'], 'table': case['table'],
                     'method': method, 'state': state, 'reply': reply}
            if events and events[-1]['event'] == event:
                events[-1]['count'] += count
            else:
                events.append({'count': count, 'event': event})
            for action in actions:
                if action[0] == 'state':
                    state = action[1]
                else:
                    assert action[1] in methods
                    methods[action[1]] = action[2]
            ordinal += count
            repeats -= count
            if reply:
                return False
        return True

    status = 0
    if case['prefix_length']:
        assert len(bytes.fromhex(case['prefix_payload'])) == case['prefix_length']
        if not emit(case['prefix_payload'], 1, methods[case['table']]):
            status = 1
    if not status:
        for part in case['parts'][:case['active_count']]:
            kind = part['kind']
            if kind == 'zeros':
                n = part['number']
                if not n:
                    continue
                method = methods[case['table']]
                full, tail = divmod(n, 64)
                if full and not emit('30' * 64, full, method):
                    status = 1
                    break
                if tail and not emit('30' * tail, 1, method):
                    status = 1
                    break
            else:
                assert kind in ('number', 'bytes')
                payload = str(part['number']).encode('ascii').hex() if kind == 'number' else part['payload']
                if not emit(payload, 1, methods[case['table']]):
                    status = 1
                    break
    return {'id': case['id'], 'callback_count': ordinal, 'events': events,
            'final_state': state, 'final_methods': sorted([table, method] for table, method in methods.items()),
            'raw_status': status}


def main():
    cases, seen = [], set()

    def add(category, parts, *, prefix=b'', prefix_token=0x51, prefix_bound=True,
            active=None, methods=None, script=None, data=11, table=1, state=0,
            extra_views=None):
        views = dict(extra_views or [])
        if prefix_bound:
            views[prefix_token] = prefix + b'ignored-prefix-view-tail'
        for part in parts:
            if part['kind'] == 'bytes':
                view = bytes.fromhex(part['payload']) + b'ignored-part-view-tail'
                if part['token'] in views:
                    assert views[part['token']][:len(view)] == view
                views[part['token']] = view
        case = {'id': 'w' + str(len(cases)).zfill(6), 'category': category,
                'data': data, 'table': table, 'prefix_token': prefix_token,
                'prefix_length': len(prefix), 'prefix_payload': prefix.hex(),
                'active_count': len(parts) if active is None else active, 'parts': parts,
                'views': [[token, raw.hex()] for token, raw in sorted(views.items())],
                'methods': [[t, m] for t, m in ([(1, 101), (2, 202)] if methods is None else methods)],
                'state': state, 'script': [] if script is None else script}
        raw = serialize(case).split(b'\t', 1)[1]
        if raw in seen:
            return
        seen.add(raw)
        cases.append(case)

    number = lambda n: {'kind': 'number', 'number': n}
    zero = lambda n: {'kind': 'zeros', 'number': n}
    blob = lambda raw, tag=2, token=0x61: {'kind': 'bytes', 'tag': tag, 'token': token, 'payload': raw.hex()}
    inactive = {'kind': 'inactive', 'words': [MAX, MAX, MAX]}

    for n in range(65536):
        add('all-u16-numerals', [number(n)], prefix_bound=False, prefix_token=MAX)

    for n in list(range(258)) + [511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 65534, 65535, 65536]:
        add('zero-chunk-boundaries', [zero(n)], prefix_bound=False)
        add('zero-next-part-live-method', [zero(n), number(17), blob(b'')], prefix=b'P',
            script=[[0, 0, [['method', 1, 303], ['state', n]]],
                    [1, 0, [['method', 1, 404], ['state', n + 1]]],
                    [2, 0, [['method', 2, 505], ['state', n + 2]]]])

    huge = sorted({MAX, MAX - 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1} |
                  {n for bit in range(16, 64) for n in [(1 << bit) - 1, 1 << bit, (1 << bit) + 1]})
    for n in huge:
        for fail in [0, 1, 2, 7, 63]:
            add('large-u64-zero-early-failure', [zero(n), number(999)], prefix_bound=False,
                script=[[0, 0, [['method', 1, MAX], ['state', 0x1234]]],
                        [fail, 255, [['state', MAX]]]] if fail else [[0, 255, [['method', 1, MAX], ['state', MAX]]]])

    tags = [2, 3, 127, 128, 255, 256, 257, 258, 511, 512, 1024, 32767, 32768, 65534, 65535]
    for tag in tags:
        for payload in [b'', b'\x00', b'\xff', bytes(range(256)), b'\xc0\xaf\xed\xa0\x80\xf5\xff', b'0' * 64]:
            add('full-u16-raw-tags-arbitrary-bytes', [blob(payload, tag)], prefix_bound=False)
            add('raw-prefix-identities-and-method-reload', [blob(payload, tag), number(65535)], prefix=payload,
                script=[[0, 0, [['method', 1, 303], ['state', 11]]],
                        [1, 0, [['method', 1, 404], ['state', 22]]]])
    for b in range(256):
        add('all-byte-values-prefix-and-raw', [blob(bytes([b])), blob(b'', token=0x62)],
            prefix=bytes([b]), state=b)

    for reply in range(256):
        for prefix, parts, fail in [
            (b'P', [number(0)], 0), (b'', [number(65535)], 0),
            (b'', [blob(b'')], 0), (b'', [blob(b'raw')], 0),
            (b'', [zero(129), number(9)], 0), (b'', [zero(129), number(9)], 1),
            (b'', [zero(129), number(9)], 2), (b'', [zero(128), blob(b'')], 2),
        ]:
            add('all-raw-replies-normalize-and-effects', parts, prefix=prefix,
                script=[[fail, reply, [['state', MAX - reply], ['method', 1, MAX - reply]]]])

    for active in range(4):
        add('inactive-records-never-resolve', [zero(0), zero(0), zero(0), inactive],
            active=active, methods=[], prefix_token=MAX, prefix_bound=False,
            script=[[0, 255, [['method', MAX, 9], ['state', 19]]]])
    for zeros in [[], [zero(0)], [zero(0), zero(0)]]:
        add('zero-callback-no-method-or-prefix-view', zeros, methods=[], prefix_bound=False,
            prefix_token=MAX, data=MAX, table=MAX, state=MAX,
            script=[[MAX, 255, [['method', MAX, 1], ['state', 0]]]])
    for n in [0, 1, 63, 64, 65, 127, 128, 129, 192, 65535]:
        for ordinal in [0, 1, 2, 3, 7]:
            add('ordered-cell-actions-and-cache', [zero(n), blob(b''), number(10000), zero(65), blob(b'X', tag=65535, token=0x62)],
                prefix=b'P', state=MAX,
                script=[[ordinal, 0, [['method', 1, 301], ['state', 7], ['method', 1, 401],
                                     ['method', 2, 501], ['state', 8]]],
                        [ordinal + 1, 0, [['method', 1, 601], ['state', 9]]],
                        [ordinal + 2, 3, [['method', 1, 701], ['state', 10]]]])
    identities = [0, 1, 1 << 31, 1 << 32, 1 << 53, (1 << 63) - 1, 1 << 63, MAX]
    for i, identity in enumerate(identities):
        add('full-u64-identities', [number(i), zero(65), blob(b'\x00\xff')], prefix=b'P',
            data=identity, table=identity, state=identity,
            methods=[[identity, identities[-i-1]]],
            script=[[0, 0, [['method', identity, identity], ['state', MAX - identity]]]])

    for prefix, parts in [(b'P', [inactive]), (b'', [number(0), inactive]),
                          (b'', [zero(65), inactive]), (b'', [blob(b''), inactive])]:
        add('earlier-failure-never-resolves-later-active-view', parts, prefix=prefix,
            script=[[0, 255, [['state', MAX], ['method', 1, 909]]]])

    paths = {name: OUT / name for name in ['authority.jsonl', 'inputs.tsv', 'expected.jsonl']}
    assert not any(path.exists() for path in paths.values())
    category_counts, observation_count, rle_count, maximum = {}, 0, 0, 0
    with paths['authority.jsonl'].open('wb') as authority, paths['inputs.tsv'].open('wb') as inputs, paths['expected.jsonl'].open('wb') as answers:
        for case in cases:
            wanted = expected(case)
            assert wanted['callback_count'] <= 4096
            assert sum(row['count'] for row in wanted['events']) == wanted['callback_count']
            authority.write(canonical(case) + b'\n')
            inputs.write(serialize(case))
            answers.write(canonical(wanted) + b'\n')
            category_counts[case['category']] = category_counts.get(case['category'], 0) + 1
            observation_count += wanted['callback_count']
            rle_count += len(wanted['events'])
            maximum = max(maximum, wanted['callback_count'])
    files = {name: {'bytes': path.stat().st_size, 'sha256': digest(path.read_bytes())} for name, path in paths.items()}
    report = {'schema': 'writer649-independent-pre-source-freeze/2',
              'supersedes_v1_sha256': '86af1dff9b63dfc5891bef06a112c1c855033bd5caae2b5bddcc80ffc09cc540',
              'v2_change': 'Four appended earlier-failure/later-unmapped-active-view cases; all v1 lines unchanged and preserved under freeze-v1. Proof clarifies that view validity is required only for actually requested slices.',
              'before_new_Rust': True, 'new_Rust_seen_or_executed': False,
              'captured_execution_or_instruction_evaluator': False,
              'native_primary': ['0x1572b20', '0x1572da9', 649, 169],
              'native_sha256': '8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3',
              'independent_proof_sha256': digest((OUT / 'PROOF.md').read_bytes()),
              'native_challenge_sha256': digest((OUT / 'NATIVE-CHALLENGE.json').read_bytes()),
              'generator_sha256': digest(Path(__file__).read_bytes()), 'files': files,
              'case_count': len(cases), 'distinct_complete_raw_inputs': len(seen),
              'complete_u16_number_payloads': 65536, 'categories': category_counts,
              'callback_observations': observation_count, 'exact_RLE_records': rle_count,
              'maximum_callbacks_per_case': maximum,
              'limits': ['Finite supporting corpus does not exhaust all sequences or huge successful zero-run traces; complete structural normal-domain proof is separate.',
                         'Expected outputs use declarative byte/decimal plans; separate serializer sends only eleven raw fields, never plans/expected roles/output.',
                         'All actual callbacks must occur individually; oracle RLE is lossless observation compression.',
                         'No mutable descriptor/parts theorem, renderer/private ABI/fault/unwind/concurrency, captured execution, full suite or completed component gate.']}
    freeze = OUT / 'FREEZE.json'
    assert not freeze.exists()
    freeze.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'path': str(freeze), 'sha256': digest(freeze.read_bytes()),
                      'cases': len(cases), 'callback_observations': observation_count,
                      'exact_RLE_records': rle_count, 'files': files}, sort_keys=True))


if __name__ == '__main__':
    main()
