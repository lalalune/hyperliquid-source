#!/usr/bin/env python3
"""Separate sequential mathematical reference for the raw eleven-field corpus."""
import hashlib
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def audit(line):
    fields = line.rstrip(b'\n').decode().split('\t')
    assert len(fields) == 11
    identifier, data, table, prefix, length, count, raw_parts, raw_views, raw_methods, state, raw_script = fields
    data, table, prefix, length, count, state = [int(v, 16) for v in [data, table, prefix, length, count, state]]
    parts = [] if raw_parts == '-' else [[int(word, 16) for word in row.split(':')] for row in raw_parts.split(',')]
    assert all(len(part) == 3 and all(0 <= word < 1 << 64 for word in part) for part in parts)
    assert count <= len(parts)
    views = {}
    if raw_views != '-':
        for row in raw_views.split(';'):
            token, text = row.split(':')
            token = int(token, 16)
            assert token not in views
            views[token] = bytes.fromhex(text)
    methods = {}
    if raw_methods != '-':
        for row in raw_methods.split(','):
            token, method = [int(word, 16) for word in row.split(':')]
            assert token not in methods
            methods[token] = method
    script = {}
    if raw_script != '-':
        for row in raw_script.split(';'):
            ordinal, reply, raw_actions = row.split('~')
            ordinal, reply = int(ordinal), int(reply)
            assert ordinal not in script and 0 <= reply <= 255
            actions = []
            if raw_actions != '-':
                for text in raw_actions.split('/'):
                    if text[0] == 'S':
                        actions.append(('state', int(text[1:], 16)))
                    else:
                        assert text[0] == 'M'
                        target, method = [int(word, 16) for word in text[1:].split(',')]
                        actions.append(('method', target, method))
            script[ordinal] = (reply, actions)
    events, calls = [], 0

    def invoke(argument, method):
        nonlocal state, calls
        reply, actions = script.get(calls, (0, []))
        event = {'argument': argument.hex(), 'data': data, 'table': table,
                 'method': method, 'state': state, 'reply': reply}
        if events and events[-1]['event'] == event:
            events[-1]['count'] += 1
        else:
            events.append({'count': 1, 'event': event})
        for action in actions:
            if action[0] == 'state':
                state = action[1]
            else:
                assert action[1] in methods
                methods[action[1]] = action[2]
        calls += 1
        return reply == 0

    def request_view(token, size):
        assert token in views and size <= len(views[token])
        return invoke(views[token][:size], methods[table])

    okay = True
    if length:
        okay = request_view(prefix, length)
    if okay:
        for first, second, third in parts[:count]:
            tag = first & 65535
            if tag == 0:
                remaining = second
                if remaining:
                    cached_method = methods[table]
                    while remaining:
                        take = min(64, remaining)
                        if not invoke(b'0' * take, cached_method):
                            okay = False
                            break
                        remaining -= take
            elif tag == 1:
                value = (first // 65536) % 65536
                okay = invoke(str(value).encode('ascii'), methods[table])
            else:
                okay = request_view(second, third)
            if not okay:
                break
    result = {'callback_count': calls, 'events': events, 'id': identifier,
              'final_state': state, 'final_methods': sorted([key, value] for key, value in methods.items()),
              'raw_status': 0 if okay else 1}
    return json.dumps(result, sort_keys=True, separators=(',', ':')).encode() + b'\n', calls


def main():
    root = Path(__file__).resolve().parent
    freeze_raw = (root / 'FREEZE.json').read_bytes()
    freeze = json.loads(freeze_raw)
    assert freeze['schema'] == 'writer649-independent-pre-source-freeze/2'
    assert sha((root / 'freeze-v1/FREEZE.json').read_bytes()) == freeze['supersedes_v1_sha256']
    for name, record in freeze['files'].items():
        raw = (root / name).read_bytes()
        assert (len(raw), sha(raw)) == (record['bytes'], record['sha256'])
        original = (root / 'freeze-v1' / name).read_bytes()
        assert raw.startswith(original)
    total = rows = 0
    ids, complete_inputs, numeral_payloads = set(), set(), set()
    with (root / 'inputs.tsv').open('rb') as inputs, (root / 'expected.jsonl').open('rb') as expected, (root / 'authority.jsonl').open('rb') as plans:
        for stimulus, wanted, plan_raw in zip(inputs, expected, plans, strict=True):
            actual, calls = audit(stimulus)
            assert actual == wanted
            identifier, remainder = stimulus.rstrip(b'\n').split(b'\t', 1)
            assert identifier not in ids and remainder not in complete_inputs
            ids.add(identifier)
            complete_inputs.add(remainder)
            plan = json.loads(plan_raw)
            assert plan['id'].encode() == identifier
            if plan['category'] == 'all-u16-numerals':
                numeral_payloads.add(plan['parts'][0]['number'])
            rows += 1
            total += calls
    assert rows == freeze['case_count'] == len(ids) == len(complete_inputs) == 69359
    assert total == freeze['callback_observations'] == 90453
    assert numeral_payloads == set(range(65536))
    receipt = {'schema': 'writer649-independent-sequential-raw-protocol-audit/1', 'status': 'PASS',
               'freeze_sha256': sha(freeze_raw), 'cases': rows, 'callback_observations': total,
               'complete_u16_numeral_payloads': len(numeral_payloads),
               'v1_all_three_authority_stimulus_answer_files_exact_prefix_of_v2': True,
               'all_full_canonical_bytes_and_final_states_equal': True,
               'every_callback_processed_individually': True,
               'all_eleven_fields_decoded_from_raw_without_oracle_plans': True,
               'new_Rust_seen_or_executed': False,
               'captured_execution_or_instruction_evaluator': False,
               'audit_script_sha256': sha(Path(__file__).read_bytes()),
               'limits': ['Sequential high-level byte/decimal request mathematics, not a CPU/opcode evaluator.',
                          'Finite corpus checks the serializer and segment-oracle independently; complete qualified native theorem remains separate.']}
    path = root / 'PROTOCOL-AUDIT.json'
    assert not path.exists()
    path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'path': str(path), 'sha256': sha(path.read_bytes()), 'status': receipt['status'],
                      'cases': rows, 'callbacks': total}, sort_keys=True))


if __name__ == '__main__':
    main()
