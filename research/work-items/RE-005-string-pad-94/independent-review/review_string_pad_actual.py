#!/usr/bin/env python3
"""Review retained ordinary data only; no builds or target/client execution."""
import argparse
import ast
import hashlib
import json
from pathlib import Path


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def actual_file(path):
    h = hashlib.sha256()
    count = 0
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1 << 20), b''):
            count += len(part)
            h.update(part)
    return count, h.hexdigest()


def bound_file(path, record):
    count, found = actual_file(path)
    need((count, found) == (record['bytes'], record['sha256']), 'File drift: ' + str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run, root = args.run.resolve(), args.root.resolve()
    private = Path(__file__).resolve().parent
    need(not args.output.exists(), 'Preserve prior receipt')
    prebuild = read_json(private / 'STRING-PAD-PREBUILD-REVIEW.json')
    result = read_json(run / 'RESULT.json')
    before, after = read_json(run / 'BEFORE.json'), read_json(run / 'AFTER.json')
    calls = read_json(run / 'CALLS.json')
    need(before == after and result['same_inputs'] is True, 'Before/after drift')
    need(result['status'] == 'PASS' and result['calls'] == len(calls) == 56, 'Actual command/result denominator')
    need(len({row['label'] for row in calls}) == 56, 'Duplicate command label')
    need(len(before['repositories']) == 8, 'Seven child pins plus root required')
    need(before['repositories'][0]['head'] == args.head, 'Wrong measured source head')
    need(all(row['status'] == '' for row in before['repositories']), 'Measured dirty repository')
    pins = read_json(root / 'provenance/sources.json')['repositories']
    need({row['path']: row['head'] for row in before['repositories'][1:]} ==
         {row['path']: row['commit'] for row in pins}, 'Actual pin map differs')
    need(result['tracked_physical_input_count'] == len(before['tracked_physical_inputs']), 'Physical denominator differs')
    for name, record in prebuild['bound_sources'].items():
        if name.endswith('/README.md'):
            continue
        need(before['tracked_physical_inputs'][name]['sha256'] == record['sha256'], 'Prebuild execution source differs: ' + name)
        bound_file(root / name, record)

    provider_raw = Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json').read_bytes()
    need(digest(provider_raw) == '56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6', 'Provider audit differs')
    provider = json.loads(provider_raw)
    need(len(before['provider_payloads']) == 103, 'Actual provider denominator')
    for row in provider['payloads']:
        got = before['provider_payloads'][row['path']]
        need((got['bytes'], got['sha256']) == (row['bytes'], row['sha256']), 'Recorded provider payload differs')
    need({key: value['sha256'] for key, value in before['installed_component_manifests'].items()} ==
         provider['installed_manifest_sha256'], 'Installed manifest map differs')
    need(len(before['installed_component_manifests']) == 2, 'Installed manifest denominator')
    need(before['target']['sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f', 'Recorded node identity')
    need(before['core_archive']['sha256'] == 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256', 'Recorded core identity')

    labels = {}
    for row in calls:
        label = row['label']
        need(row['exit'] == 0 and row['cwd'] == str(root), 'Unexpected command exit/cwd: ' + label)
        need(set(row['streams']) == {'stdout', 'stderr'}, 'Incomplete raw command streams')
        for stream in row['streams'].values():
            name = Path(stream['file'])
            need(not name.is_absolute() and '..' not in name.parts, 'Unsafe stream path')
            bound_file(run / name, stream)
        labels[label] = row
    need(result['captured_execution_or_instruction_evaluator'] is False and result['component_gates_requested'] is False,
         'Wrong execution/gate scope')
    need(result['full_test_suite'].startswith('NOT_RUN'), 'Full-suite limitation absent')

    inputs = (private / 'string-pad-1081-input.tsv').read_bytes()
    expected_raw = (private / 'string-pad-1081-expected.jsonl').read_bytes()
    need(digest(inputs) == 'bf40d855ffc68481fa0e1acb37043d51f4207888160176060ce68b61b3c79300', 'Frozen input differs')
    need(digest(expected_raw) == '29d8d003b50f09978f0699f8d1a2d5d598070f35470e59fd5ec10fbbff8e46df', 'Frozen expected differs')
    need((run / 'inputs.tsv').read_bytes() == inputs, 'Actual client input differs')
    rows = expected_raw.splitlines()
    input_lines = inputs.splitlines()
    ids = [line.split(b'\t', 1)[0].decode() for line in input_lines]
    need(len(rows) == len(ids) == len(set(ids)) == 26054, 'Frozen case denominator/IDs')
    need(len({line.split(b'\t', 1)[1] for line in input_lines}) == 26054, 'Frozen complete raw inputs not unique')
    observations = rle = maximum = 0
    for identifier, row in zip(ids, rows):
        data = json.loads(row)
        need(data['id'] == identifier, 'Frozen ID ordering')
        need(type(data['raw_status']) is int and 0 <= data['raw_status'] <= 255, 'Frozen raw status domain')
        n = sum(event['count'] for event in data['events'])
        need(n == data['callback_count'], 'RLE event count differs')
        observations += n
        rle += len(data['events'])
        maximum = max(maximum, n)
    need((observations, rle, maximum) == (9915008, 49649, 65536), 'Full observation denominators')
    need((result['cases'], result['distinct_complete_inputs'], result['callback_observations'], result['exact_RLE_records']) ==
         (26054, 26054, observations, rle), 'Result denominators differ')

    profiles = []
    for label in ['debug', 'optimized', 'repro-optimized']:
        stdout = run / (label + '-client-run.stdout')
        need(stdout.read_bytes() == expected_raw and not (run / (label + '-client-run.stderr')).read_bytes(), 'Actual full canonical transcript differs: ' + label)
        argv = labels[label + '-client-run']['argv']
        need(argv == [str(run / label / 'input-client'), str(run / 'inputs.tsv')], 'Input-only client argv differs')
        record = result['profiles'][label]
        for kind, name in [('rlib', 'libnode94_string_pad.rlib'), ('client', 'input-client')]:
            bound_file(run / label / name, record[kind])
        need(record['different_rows'] == 0 and record['first_different_IDs'] == [], 'Profile mismatch claim')
        if label != 'repro-optimized':
            test_raw = (run / (label + '-unit-run.stdout')).read_bytes()
            need(b'2 passed; 0 failed' in test_raw and
                 b'independent_pre_source_complete_transcripts' in test_raw and
                 b'borrowed_writer_context_and_live_methods_remain_observable' in test_raw,
                 'Actual external unit methods absent')
        profiles.append({'profile': label, 'cases': len(rows), 'callback_observations': observations,
                         'stdout_sha256': digest(expected_raw)})
    for name in ['libnode94_string_pad.rlib', 'input-client']:
        need((run / 'optimized' / name).read_bytes() == (run / 'repro-optimized' / name).read_bytes(), 'Raw same-recipe artifact differs')

    mutants = []
    need(len(result['compiled_source_controls']) == 13, 'Source-control denominator')
    for name, record in result['compiled_source_controls'].items():
        mismatches = []
        path = run / ('mutant-' + name + '-client-run.stdout')
        with path.open('rb') as stream:
            for index, expected in enumerate(rows):
                actual = stream.readline()
                need(actual.endswith(b'\n') and json.loads(actual)['id'] == ids[index], 'Mutant incomplete/reordered ID')
                if actual[:-1] != expected:
                    mismatches.append(ids[index])
            need(stream.read() == b'', 'Extra mutant rows')
        need(not (run / ('mutant-' + name + '-client-run.stderr')).read_bytes(), 'Mutant client stderr')
        need(len(mismatches) == record['different_rows'] > 0, 'Source-control kill count differs')
        need(mismatches[:8] == record['first_different_IDs'], 'Source-control sample IDs differ')
        for kind, filename in [('rlib', 'libnode94_string_pad.rlib'), ('client', 'input-client')]:
            bound_file(run / ('mutant-' + name) / filename, record[kind])
        mutants.append({'name': name, 'mismatched_cases': len(mismatches),
                        'all_mismatch_IDs_sha256': digest(('\n'.join(mismatches) + '\n').encode())})

    native = read_json(run / 'native/REPORT.json')
    need(native['target_sha256'] == before['target']['sha256'] and native['archive_sha256'] == before['core_archive']['sha256'], 'Native whole-artifact identities')
    for role, size, count, wanted in [
        ('main', 1081, 300, 'f958a0383269ead1a2056ba42785c9050e46a57aa0f990a27976fe27cb5eee77'),
        ('count', 1483, 365, '13c5b0904bd66520b303cc5513d2cf7fed55c20298a5bef6a979f81be0083f35')]:
        function = native['functions'][role]
        body = (run / 'native' / ('captured-' + role + '.bin')).read_bytes()
        need((len(body), digest(body)) == (size, wanted), 'Actual native body identity differs')
        need((function['bytes'], function['rows'], len(function['native_rows'])) == (size, count, count), 'Complete native row denominator')
        need(function['FDE']['end'] - function['FDE']['start'] == size, 'Actual FDE extent')
        need(function['body_sha256'] == wanted, 'Recorded native body digest')
        need(bytes.fromhex(''.join(row['raw'] for row in function['native_rows'])) == body, 'Native row tiling differs')
        official = (run / 'native' / ('official-' + role + '.bin')).read_bytes()
        excluded = {i for field in function['relocations'] for i in range(field['offset'], field['offset'] + field['width'])}
        need(len(official) == size and all(a == b or i in excluded for i, (a, b) in enumerate(zip(body, official))), 'Complete published correspondence differs')
    loader = native['actual_loader_write_audit']
    need(loader['records'] == 80300 and loader['kind_counts'] == {'1': 924, '6': 263, '7': 278, '8': 78833, '18': 2}, 'Full actual RELA census differs')
    need(loader['all_observed_write_widths'] == 8 and loader['immutable_overlap_count'] == 0 and loader['no_nonempty_REL_or_RELR_sections'] is True, 'Loader write closure differs')
    selected, = loader['selected_slot_writers']
    need((selected['slot'], selected['end'], selected['kind'], selected['symbol'], selected['addend']) ==
         (0x5770628, 0x5770630, 8, 0, 0x15796c0), 'Count GOT unique whole writer differs')
    controls = read_json(run / 'native/CONTROLS.json')
    need(controls == result['below_digest_static_controls'] and len(controls) == len({row['label'] for row in controls}) == 11,
         'Static-control result/denominator differs')
    need(all(row['rejection'] for row in controls), 'Empty static rejection')
    need(len(result['comparator_controls']) == len(set(result['comparator_controls'])) == 7, 'Comparator controls differ')

    # Exercise only the two pure comparison functions in isolation; do not
    # import the runner or its subprocess/native/provider operations.
    tree = ast.parse((root / 'research/work-items/RE-005-string-pad-94/validate_string_pad.py').read_bytes())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in {'need', 'compare'}]
    need(len(functions) == 2, 'Pure comparator extraction differs')
    scope = {'json': json}
    exec(compile(ast.Module(body=functions, type_ignores=[]), '<comparison-functions-only>', 'exec'), scope)
    parsed = [{'id': identifier} for identifier in ids]
    need(scope['compare'](expected_raw, parsed, rows) == [], 'Actual comparator rejects full expected rows')
    changed = b'{"id":"' + ids[0].encode() + b'","raw_status":999}\n' + b'\n'.join(rows[1:]) + b'\n'
    need(scope['compare'](changed, parsed, rows) == [0], 'Actual comparator missed changed content')
    for damaged in [b'\n'.join(rows[:-1]) + b'\n', expected_raw + rows[0] + b'\n', rows[1] + b'\n' + b'\n'.join(rows[1:]) + b'\n']:
        try:
            scope['compare'](damaged, parsed, rows)
        except ValueError:
            pass
        else:
            raise ValueError('Actual comparator accepted denominator/ID corruption')

    receipt = {'schema': 'node94-string-pad-independent-actual-review/1', 'status': 'PASS',
               'reviewer': 'formatter_recovery', 'measured_head': args.head,
               'run_path': str(run), 'result_sha256': digest((run / 'RESULT.json').read_bytes()),
               'review_script_sha256': digest(Path(__file__).read_bytes()),
               'command_count': len(calls), 'raw_stream_count': 2 * len(calls),
               'profiles': profiles, 'mutants': mutants, 'static_controls': controls,
               'recorded_physical_input_count': len(before['tracked_physical_inputs']),
               'recorded_clean_child_pins': 7, 'recorded_provider_payloads': 103,
               'recorded_installed_manifests': 2, 'recorded_before_after_equal': True,
               'native_primary_bytes': 1081, 'native_primary_rows': 300,
               'credited_counter_bytes': 1483, 'credited_counter_rows': 365,
               'actual_loader_RELA_records': 80300,
               'limits': ['Retained raw artifacts and recorded maps were independently checked; no fresh full target/provider rehash or compiler/client execution in this review.',
                          'No captured target execution, instruction evaluator, ABI/renderer/fault/unwind/concurrency closure or component gates.',
                          'Full current test suite and hosted CI NOT_RUN.']}
    args.output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'receipt': str(args.output), 'sha256': digest(args.output.read_bytes()),
                      'status': receipt['status'], 'mutants': mutants}, sort_keys=True))


if __name__ == '__main__':
    main()
