#!/usr/bin/env python3
"""Independent retained-data artifact review; no program or target execution."""
import ast
import hashlib
import json
from pathlib import Path


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def bound(path, record):
    raw = path.read_bytes()
    need((len(raw), sha(raw)) == (record['bytes'], record['sha256']), 'Artifact drift: ' + str(path))


def main():
    private = Path(__file__).resolve().parent
    root = Path('/tmp/hl-resume-20261101/selector-56c')
    run = Path('/tmp/hl-resume-20261101/writer649-build-51c0ea7f')
    head = '51c0ea7fc4a035b4c0dd690f9310657b39ea9db4'
    result_raw = (run / 'RESULT.json').read_bytes()
    need(sha(result_raw) == 'd0c3162717f646cbf43da35cf13a6227dd2f1789717c911985202519179693d1', 'Fresh result identity')
    result = json.loads(result_raw)
    calls = load(run / 'CALLS.json')
    before, after = load(run / 'BEFORE.json'), load(run / 'AFTER.json')
    need(result['status'] == 'PASS' and result['same_inputs'] and before == after, 'Fresh qualification did not pass unchanged')
    need(result['calls'] == len(calls) == len({row['label'] for row in calls}) == 53, 'Command denominator')
    need(len(before['tracked_physical_inputs']) == result['tracked_physical_input_count'] == 10846, 'Physical source count')
    need(len(before['repositories']) == 8 and before['repositories'][0]['head'] == head and
         all(row['status'] == '' for row in before['repositories']), 'Clean source/pin checkpoint')
    pins = load(root / 'provenance/sources.json')['repositories']
    need({row['path']: row['head'] for row in before['repositories'][1:]} ==
         {row['path']: row['commit'] for row in pins}, 'Seven actual pin values differ')
    reviewed = load(private / 'PREBUILD-REVIEW.json')['bound_sources']
    reviewed['tools/validate_parts_writer649.py']['sha256'] = 'ac0f775a610e11eba088be0277973cb979cf0634b70fa6ba56bf52514779ea1b'
    for name, record in reviewed.items():
        if name.endswith('/README.md'):
            continue
        need(sha((root / name).read_bytes()) == before['tracked_physical_inputs'][name]['sha256'] == record['sha256'], 'Execution source differs: ' + name)
    provider_raw = Path('/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json').read_bytes()
    need(sha(provider_raw) == '56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6', 'Provider audit differs')
    provider = json.loads(provider_raw)
    need(len(before['provider_payloads']) == len(provider['payloads']) == 103, 'Provider count')
    for row in provider['payloads']:
        got = before['provider_payloads'][row['path']]
        need((got['bytes'], got['sha256']) == (row['bytes'], row['sha256']), 'Recorded official payload differs')
    need(len(before['installed_component_manifests']) == 2 and
         {name: row['sha256'] for name, row in before['installed_component_manifests'].items()} ==
         provider['installed_manifest_sha256'], 'Both installed manifests differ')
    need(before['target']['sha256'] == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f' and
         before['core_archive']['sha256'] == 'ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256', 'Recorded full input identities')
    labels = {}
    for row in calls:
        need(row['exit'] == 0 and row['cwd'] == str(root), 'Unexpected actual child exit/cwd')
        need(set(row['streams']) == {'stdout', 'stderr'}, 'Incomplete streams')
        for stream in row['streams'].values():
            name = Path(stream['file'])
            need(not name.is_absolute() and '..' not in name.parts, 'Unsafe stream path')
            bound(run / name, stream)
        labels[row['label']] = row

    inputs = (private / 'inputs.tsv').read_bytes()
    wanted = (private / 'expected.jsonl').read_bytes()
    need(sha(inputs) == '6d1ca83e5517b49cb284f4f7ac54233e1db1265f4b90f15ffc9fa623c07ea58a' and
         sha(wanted) == '5f734582c41dad1645c94f83ddc453cd3c723137c7d56fd9e35b4254048e1109', 'Frozen corpus identity')
    need((run / 'inputs.tsv').read_bytes() == inputs, 'Actual raw client input differs')
    rows = wanted.splitlines()
    identifiers = [row.split(b'\t', 1)[0].decode() for row in inputs.splitlines()]
    need(len(rows) == len(identifiers) == len(set(identifiers)) == 69359, 'Case/ID denominator')
    callbacks = records = 0
    for identifier, row in zip(identifiers, rows):
        value = json.loads(row)
        need(value['id'] == identifier and type(value['raw_status']) is int and value['raw_status'] in (0, 1), 'Authority status/ID type')
        need(sum(event['count'] for event in value['events']) == value['callback_count'], 'Lossless RLE count')
        callbacks += value['callback_count']
        records += len(value['events'])
    need((callbacks, records) == (90453, 73214), 'Observation denominator')
    need((result['cases'], result['distinct_complete_inputs'], result['callback_observations'], result['exact_RLE_records']) ==
         (69359, 69359, 90453, 73214), 'Result denominator')
    profiles = []
    for name in ['debug', 'optimized', 'repro-optimized']:
        need((run / (name + '-client-run.stdout')).read_bytes() == wanted and
             not (run / (name + '-client-run.stderr')).read_bytes(), 'Complete canonical profile differs')
        need(labels[name + '-client-run']['argv'] == [str(run / name / 'input-client'), str(run / 'inputs.tsv')], 'Client received additional inputs')
        info = result['profiles'][name]
        need(info['different_rows'] == 0 and not info['first_different_IDs'], 'Profile mismatch metadata')
        for kind, filename in [('rlib', 'libnode94_parts_writer.rlib'), ('client', 'input-client')]:
            bound(run / name / filename, info[kind])
        if name != 'repro-optimized':
            raw = (run / (name + '-unit-run.stdout')).read_bytes()
            need(b'3 passed; 0 failed' in raw and all(test.encode() in raw for test in
                 ['independent_pre_source_raw_transcripts', 'no_requests_resolve_no_method_or_view',
                  'zero_run_caches_method_then_numeral_reloads_and_error_stops_lazily']), 'Three actual unit methods missing')
        profiles.append({'profile': name, 'cases': 69359, 'callback_observations': callbacks, 'stdout_sha256': sha(wanted)})
    for filename in ['libnode94_parts_writer.rlib', 'input-client']:
        need((run / 'optimized' / filename).read_bytes() == (run / 'repro-optimized' / filename).read_bytes(), 'Raw deterministic rebuild differs')

    mutants = []
    need(len(result['compiled_source_controls']) == 12, 'Compiled semantic control count')
    for name, metadata in result['compiled_source_controls'].items():
        changed = []
        with (run / ('mutant-' + name + '-client-run.stdout')).open('rb') as stream:
            for index, wanted_row in enumerate(rows):
                got = stream.readline()
                need(got.endswith(b'\n') and json.loads(got)['id'] == identifiers[index], 'Mutant missing/reordered row')
                if got[:-1] != wanted_row:
                    changed.append(identifiers[index])
            need(not stream.read(), 'Extra mutant rows')
        need(not (run / ('mutant-' + name + '-client-run.stderr')).read_bytes(), 'Mutant client stderr')
        need(len(changed) == metadata['different_rows'] > 0 and changed[:8] == metadata['first_different_IDs'], 'Mutant kill count/IDs differ')
        for kind, filename in [('rlib', 'libnode94_parts_writer.rlib'), ('client', 'input-client')]:
            bound(run / ('mutant-' + name) / filename, metadata[kind])
        mutants.append({'name': name, 'mismatched_cases': len(changed),
                        'all_mismatched_IDs_sha256': sha(('\n'.join(changed) + '\n').encode())})

    native = load(run / 'native/REPORT.json')
    body = (run / 'native/captured-main.bin').read_bytes()
    need(len(body) == native['bytes'] == 649 and sha(body) == native['body_sha256'] ==
         '8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3', 'Full native649 body differs')
    need(native['rows'] == len(native['native_rows']) == 169 and
         b''.join(bytes.fromhex(row['raw']) for row in native['native_rows']) == body, 'Full native row tiling differs')
    admission = load(Path('/tmp/hl-resume-20261101/root-parts-next/ADMISSION.json'))
    need(native['FDE'] == admission['selected'][1]['FDE'] and native['CIE'] == admission['selected'][1]['CIE'], 'Complete FDE/CIE differs from pre-source intake')
    need([row['va'] for row in native['dynamic_calls']] == [0x1572b49, 0x1572b87, 0x1572c2f, 0x1572c5d, 0x1572c8a] and
         native['fixed_called_helpers'] == [], 'Native fixed/dynamic closure differs')
    need(native['frame_raw']['FDE'] and native['frame_raw']['CIE'], 'Raw frame record missing')
    literal = (run / 'native/ASCII-zero64.bin').read_bytes()
    need(literal == bytes.fromhex(native['literal']['raw']) == b'0' * 64 and
         native['literal']['mapping']['PT_LOAD']['flags'] == 4 and
         not native['literal']['mapping']['section']['flags'] & 1, 'Read-only literal differs')
    loader = native['loader_write_audit']
    need(loader['records'] == 80300 and loader['kind_counts'] == {'1': 924, '6': 263, '7': 278, '8': 78833, '18': 2} and
         loader['all_observed_write_widths'] == 8 and loader['overlaps'] == 0, 'Actual allRELA write closure differs')
    math = native['decimal_arithmetic']
    need((math['domain'], math['complete_numeral_mismatches'], math['maximum_width']) == (65536, 0, 5) and
         math['no_PC_register_memory_or_opcode_evaluator'] is True, 'Complete numeral math differs')
    provenance = native['published_candidate']
    need((provenance['source_bytes'], provenance['target_bytes'], provenance['result'], provenance['cropping_or_stitching'], provenance['byte_window_credit']) ==
         (581, 649, 'EXTENT_MISMATCH_NO_COMPARISON', False, False), 'Negative published provenance overclaimed')
    controls = load(run / 'native/CONTROLS.json')
    need(controls == result['below_digest_static_controls'] and len(controls) == len({row['label'] for row in controls}) == 14 and
         all(row['rejection'] for row in controls), 'Fourteen native corruption controls differ')
    need(len(set(result['comparator_controls'])) == len(result['comparator_controls']) == 7, 'Seven comparator controls')

    # Exercise only two pure comparison functions, without runner imports.
    nodes = [node for node in ast.parse((root / 'tools/validate_parts_writer649.py').read_bytes()).body
             if isinstance(node, ast.FunctionDef) and node.name in {'need', 'compare'}]
    need(len(nodes) == 2, 'Pure comparator extraction')
    scope = {'json': json}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<comparison-only>', 'exec'), scope)
    id_rows = [{'id': value} for value in identifiers]
    need(scope['compare'](wanted, id_rows, rows) == [], 'Comparator positive rejected')
    changed = b'{"id":"' + identifiers[0].encode() + b'","raw_status":255}\n' + b'\n'.join(rows[1:]) + b'\n'
    need(scope['compare'](changed, id_rows, rows) == [0], 'Comparator missed changed contents')
    for damaged in [b'\n'.join(rows[:-1]) + b'\n', wanted + rows[0] + b'\n', rows[1] + b'\n' + b'\n'.join(rows[1:]) + b'\n']:
        try:
            scope['compare'](damaged, id_rows, rows)
        except ValueError:
            pass
        else:
            raise ValueError('Comparator accepted denominator/ID corruption')
    receipt = {'schema': 'writer649-independent-actual-artifact-review/1', 'status': 'PASS',
               'source_checkpoint': head, 'result_sha256': sha(result_raw), 'actual_commands': 53, 'raw_streams': 106,
               'profiles': profiles, 'mutants': mutants, 'native_controls': controls,
               'native_bytes': 649, 'native_rows': 169, 'root_pre_source_FDE_CIE_unchanged': True,
               'complete_u16_numeral_math': 65536, 'actual_RELA_records': 80300,
               'physical_inputs_before_equal_after': 10846, 'actual_clean_pins': 7,
               'official_provider_payloads': 103, 'installed_manifests': 2,
               'same_recipe_optimized_rlib_and_client_raw_equal': True,
               'published581_vs_native649_is_negative_only_no_bytecredit': True,
               'original_f214_partialFAIL_preserved_separately': True,
               'review_script_sha256': sha(Path(__file__).read_bytes()),
               'limits': ['Retained actual raw streams/maps/artifacts checked independently; no compiler/client/static producer execution or target/provider full reread in this pass.',
                          'Fresh independent retained-client executions are sealed in separate INDEPENDENT-REPLAYS.json.',
                          'PrivateABI/renderer/mutableinput/fault/unwind/concurrency/fullnode identity, full suite, captured execution/instruction evaluators and hostedCI remain outside/NOT_RUN.']}
    output = private / 'ACTUAL-ARTIFACT-REVIEW.json'
    need(not output.exists(), 'Preserve prior actual receipt')
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'path': str(output), 'sha256': sha(output.read_bytes()), 'status': receipt['status'], 'mutants': mutants}, sort_keys=True))


if __name__ == '__main__':
    main()
