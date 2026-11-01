#!/usr/bin/env python3
"""Independently verify retained static records; no subprocess/target reads."""
import hashlib
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, message):
    if not ok:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_bytes())


def main():
    private = Path(__file__).resolve().parent
    root = Path('/tmp/hl-resume-20261101/selector-56c')
    packet = root / 'research/work-items/RE-005-string-pad-94'
    run = Path('/tmp/hl-resume-20261101/string-pad-static-70cc50b2')
    build = Path('/tmp/hl-resume-20261101/string-pad-build-70cc50b2')
    result_raw = (run / 'RESULT.json').read_bytes()
    result = json.loads(result_raw)
    before, after = load(run / 'BEFORE.json'), load(run / 'AFTER.json')
    original = load(build / 'BEFORE.json')
    need(before == after == original, 'Static maps drift from actual clean compiler experiment')
    need(result['status'] == 'PASS' and result['same_inputs'] is True, 'Static result not PASS')
    need(result['source_head'] == '70cc50b2e6d4ba75c6541328aed886712e7a959b', 'Wrong static checkpoint')
    need((result['tracked_physical_inputs'], result['provider_payloads'], result['installed_manifests'], result['pinned_repositories']) ==
         (10847, 103, 2, 7), 'Static denominators differ')
    calls = load(run / 'CALLS.json')
    need(calls == result['calls'] and len(calls) == 4, 'Static ledger differs')
    need([row['target'] for row in calls] == ['doctor', 'verify', 'catalogue-check', 'reproduce'], 'Unexpected static targets')
    for row in calls:
        need(row['exit'] == 0, 'Static nonzero exit')
        argv = row['argv']
        need(len(argv) == 4 and argv[:2] == ['make', '-j1'] and argv[2].startswith('PYTHON=') and
             argv[2].endswith(' -B') and argv[3] == row['target'], 'Unexpected static command')
        need(set(row['streams']) == {'stdout', 'stderr'}, 'Incomplete static raw streams')
        for record in row['streams'].values():
            name = Path(record['file'])
            need(not name.is_absolute() and '..' not in name.parts, 'Unsafe raw stream name')
            raw = (run / name).read_bytes()
            need((len(raw), sha(raw)) == (record['bytes'], record['sha256']), 'Static raw stream digest differs')
    wrapper = (packet / 'repository-checks/static_checks.py').read_bytes()
    need(sha(wrapper) == result['static_wrapper_sha256'] == 'd4d59319327bbd09d3a75e3cce9f607892a0997d85c7744d54601273afe518a3', 'Static wrapper differs')
    need(result['full_test_suite'].startswith('NOT_RUN') and result['captured_execution_or_instruction_evaluator'] is False, 'Wrong static scope')
    for path in run.iterdir():
        if path.is_file():
            retained = packet / 'repository-checks' / path.name
            need(retained.read_bytes() == path.read_bytes(), 'Retained static evidence changed: ' + path.name)

    admission_raw = (packet / 'native-intake/ADMISSION.json').read_bytes()
    need(sha(admission_raw) == '175919e0989e668267383b26edb20b438d1ca6a9f75275be8cb3c8f38280efce', 'Pre-source native admission differs')
    admission = json.loads(admission_raw)
    native = load(build / 'native/REPORT.json')
    primary = native['functions']['main']
    need(primary['FDE'] == admission['FDE'] and primary['CIE'] == admission['CIE'] and
         primary['native_rows'] == admission['native_rows'], 'Actual native rows/frame definitions drift from pre-source proof')
    need(primary['fde_raw'] == admission['frame_raw']['FDE'] and primary['cie_raw'] == admission['frame_raw']['CIE'], 'Actual raw FDE/CIE drift')
    helper, = admission['helpers']
    counter = native['functions']['count']
    need(counter['FDE'] == helper['FDE'] and counter['CIE'] == helper['CIE'] and
         counter['body_sha256'] == helper['body_sha256'] and counter['rows'] == helper['rows'], 'Credited counter binding drift')
    need(sha((packet / 'LICENSE-MIT').read_bytes()) == 'b71bd43a069ca0641a9ecfe585ca7b3c53b5cc1608f8b68321168698e28b5ea1', 'Full upstream MIT notice differs')

    receipt = {'schema': 'node94-string-pad-independent-static-review/1', 'status': 'PASS',
               'reviewer': 'formatter_recovery', 'source_head': result['source_head'],
               'result_sha256': sha(result_raw), 'review_script_sha256': sha(Path(__file__).read_bytes()),
               'actual_commands': 4, 'raw_streams': 8,
               'command_seconds': sum(row['seconds'] for row in calls),
               'tracked_physical_inputs': 10847, 'genuine_pinned_repositories': 7,
               'provider_payloads': 103, 'installed_component_manifests': 2,
               'before_equal_after_equal_clean_compiler_experiment_before': True,
               'pre_source_primary_native_rows_and_raw_FDE_CIE_match_actual': True,
               'credited_counter_frame_and_body_binding_match_actual': True,
               'full_upstream_MIT_option_notice_verified': True,
               'limits': ['Retained command streams/maps and pre-source native records were independently checked; no static target rerun, compiler or target/provider rehash in this pass.',
                          'Full expanded suite, captured instruction execution/evaluation and hosted CI NOT_RUN.']}
    output = private / 'STRING-PAD-STATIC-REVIEW.json'
    need(not output.exists(), 'Preserve prior static receipt')
    output.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'receipt': str(output), 'sha256': sha(output.read_bytes()), 'status': receipt['status']}))


if __name__ == '__main__':
    main()
