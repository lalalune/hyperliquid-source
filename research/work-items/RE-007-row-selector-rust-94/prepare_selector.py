#!/usr/bin/env python3
"""Freeze an ignored component overlay and conditional posthash comparison inputs."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = '56c0ec672bd8fdcfaa80f2db700a61e6240b3663'
PROOF = 'f9d8906d9334e5f9297c81d4c211bfcdcf50f050'
PRIOR_FREEZE = '515b7a3abcbb4dab494632d381d1a9377d3ea4120a7090702c96ccebf9269f77'
COMPONENT = ROOT / 'src/node94-margin-risk'
MAX = (1 << 64) - 1


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def render(value):
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


def manifest(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink(), 'snapshot symlink: ' + str(path))
        if path.is_file() and path != directory / 'FREEZE.json':
            raw = path.read_bytes()
            result[str(path.relative_to(directory))] = dict(bytes=len(raw), sha256=sha(raw))
    return result


def choice(case):
    """Independent dictionary answer; it does not walk probe groups."""
    index = None
    if case['count']:
        controls = bytes.fromhex(case['controls_hex'])
        query = bytes.fromhex(case['query_hex'])
        fingerprint = int(case['hash'], 16) >> 57
        matches = [int(i) for i, key in case['keys'].items()
                   if controls[int(i)] == fingerprint and bytes.fromhex(key) == query]
        need(len(matches) <= 1, 'unique matching key premise')
        index = next(iter(matches), None)
    return dict(choice='SharedDefault' if index is None else 'Bucket', index=index,
                initializer_needed=case['state'] != 0)


def walk(case, wrong=None):
    """Normal-domain audit / wrong-relation controls, never an acceptance oracle."""
    wrong = wrong or ''
    state_needed = (0 < case['state'] < 1 << 31) if wrong == 'signed-positive-state' else case['state'] != 0
    if not case['count'] and wrong != 'ignore-empty-count':
        return dict(choice='SharedDefault', index=None, initializer_needed=state_needed)
    controls = bytes.fromhex(case['controls_hex'])
    need(len(controls) >= 16, 'model has no table')
    mask = len(controls) - 1
    position = int(case['hash'], 16) & mask
    fp = (int(case['hash'], 16) >> (56 if wrong == 'fingerprint-shift-56' else 57)) & 255
    query = bytes.fromhex(case['query_hex'])
    step = 0
    for _ in range(len(controls) // 16):
        empty = False
        for lane in range(8 if wrong == 'eight-lane-group' else 16):
            index = min(position + lane, mask) if wrong == 'clamp-wrapped-lane' else (position + lane) & mask
            control = controls[index]
            if control == 255 and wrong == 'stop-at-first-empty':
                return dict(choice='SharedDefault', index=None, initializer_needed=case['state'] != 0)
            empty |= control == 255
            key = bytes.fromhex(case['keys'].get(str(index), '00' * 20))
            width = 16 if wrong == 'sixteen-byte-key' else 20
            if control == fp and key[:width] == query[:width]:
                state = case['state'] != 0
                if wrong == 'initialize-only-default':
                    state = False
                if wrong == 'signed-positive-state':
                    state = 0 < case['state'] < 1 << 31
                return dict(choice='Bucket', index=index, initializer_needed=state)
        if empty:
            state = case['state'] != 0
            if wrong == 'signed-positive-state':
                state = 0 < case['state'] < 1 << 31
            return dict(choice='SharedDefault', index=None, initializer_needed=state)
        step = 16 if wrong == 'linear-group-step' else step + (8 if wrong == 'eight-byte-step' else 16)
        position = (position + step) & mask
    raise ValueError('bounded audit did not terminate')


def add_case(rows, name, capacity, start, lane, *, fp=0x35, state=0, query=None,
             changed_query=None, decoy=None, target_group=0, count=None):
    query = bytes(range(20)) if query is None else query
    controls = bytearray([255] * capacity)
    keys = {}
    for group in range(target_group):
        pos = (start + 16 * (group * (group + 1) // 2)) & (capacity - 1)
        for offset in range(16):
            controls[(pos + offset) & (capacity - 1)] = 128
    pos = (start + 16 * (target_group * (target_group + 1) // 2)) & (capacity - 1)
    index = (pos + lane) & (capacity - 1)
    controls[index] = fp
    keys[str(index)] = query.hex()
    if decoy is not None:
        at = (pos + decoy) & (capacity - 1)
        changed = bytearray(query)
        changed[19] ^= 1
        controls[at] = fp
        keys[str(at)] = changed.hex()
    case = dict(name=name, count=len(keys) if count is None else count,
                hash=hex((fp << 57) | start), state=state, controls_hex=controls.hex(),
                keys=keys, query_hex=(changed_query if changed_query is not None else query).hex(),
                scope='conditional posthash native-derived value relation',
                provenance='post-source synthetic addition; external native hash admissibility unproved')
    case['expected'] = choice(case)
    rows.append(case)


def cases():
    prior = (HERE / 'PRE-RUST-FREEZE.json').read_bytes()
    need(sha(prior) == PRIOR_FREEZE, 'prior pre-source freeze identity')
    frozen = json.loads(prior)
    for name, digest in frozen['frozen_sha256'].items():
        need(sha((HERE / name).read_bytes()) == digest, 'prior frozen payload changed: ' + name)
    rows = copy.deepcopy(json.loads((HERE / 'vectors.json').read_text())['cases'])
    for case in rows:
        need(choice(case) == case['expected'], 'pre-source expectation differs from independent dictionary')
        case.update(scope='conditional posthash native-derived value relation',
                    provenance='pre-source frozen synthetic case; no captured run or hash admissibility proof')
    query = bytes(range(20))
    for byte in range(20):
        changed = bytearray(query)
        changed[byte] ^= 1
        add_case(rows, f'fixed-h-query-byte-{byte}', 32, 0, 5, changed_query=changed)
    for byte in range(20):
        for bit in range(8):
            changed = bytearray(query)
            changed[byte] ^= 1 << bit
            add_case(rows, f'fixed-h-query-bit-{byte}-{bit}', 32, 0, 5, changed_query=changed)
    for fp in range(128):
        add_case(rows, f'fingerprint-{fp}', 32, 0, fp % 16, fp=fp)
    for start in range(32):
        for lane in range(16):
            add_case(rows, f'lane-wrap-{start}-{lane}', 32, start, lane,
                     state=[0, 3, 0x80000000, 0xffffffff][(start + lane) % 4])
    for capacity in (32, 64, 128, 256):
        for group in range(1, min(capacity // 16, 7)):
            for lane in (0, 15):
                add_case(rows, f'probe-{capacity}-{group}-{lane}', capacity, 0, lane, target_group=group)
    for state in (0, 1, 2, 3, 4, 255, 0x80000000, 0xffffffff):
        add_case(rows, f'late-state-hit-{state}', 32, 0, 5, state=state)
        changed = bytes([1]) + query[1:]
        add_case(rows, f'late-state-miss-{state}', 32, 0, 5, state=state, changed_query=changed)
    for decoy in range(15):
        add_case(rows, f'decoy-lane-{decoy}', 32, 0, 15, decoy=decoy)
    add_case(rows, 'empty-count-unused-table-arguments', 16, 0, 5, state=3, count=0)
    for case_id, case in enumerate(rows):
        case['id'] = case_id
        need(walk(case) == case['expected'], 'constructed normal placement failed: ' + case['name'])
    need(len({case['name'] for case in rows}) == len(rows), 'duplicate case name')
    return rows


def input_bytes(rows):
    result = bytearray(b'R94SIN01' + struct.pack('<I', len(rows)))
    for case in rows:
        controls = bytes.fromhex(case['controls_hex'])
        keys = [bytes.fromhex(case['keys'].get(str(i), '00' * 20)) for i in range(case.get('key_count', len(controls)))]
        result.extend(struct.pack('<IQQIII', case['id'], case['count'], int(case['hash'], 16),
                                  case['state'], len(controls), len(keys)))
        result.extend(bytes.fromhex(case['query_hex']) + controls + b''.join(keys))
    return bytes(result)


def expected_bytes(rows):
    result = bytearray(b'R94SOUT1' + struct.pack('<I', len(rows)))
    for case in rows:
        e = case['expected']
        kind = 2 if e['choice'] == 'ApiError' else int(e['choice'] == 'Bucket')
        result.extend(struct.pack('<IBBQ', case['id'], kind,
                                  e['initializer_needed'], MAX if e['index'] is None else e['index']))
    return bytes(result)


def policy_cases(first_id):
    rows = []
    for name, capacity, key_count, code in [
        ('shape-zero', 0, 0, 0), ('shape-fifteen', 15, 15, 0),
        ('shape-seventeen', 17, 17, 0), ('key-coverage', 16, 15, 1),
        ('cycle-sixteen', 16, 16, 2), ('cycle-thirty-two', 32, 32, 2),
        ('shape-precedes-key-coverage', 15, 0, 0),
    ]:
        rows.append(dict(id=first_id+len(rows), name='policy-'+name, count=1, hash='0x6a00000000000000',
                         state=3, controls_hex=bytes([128]*capacity).hex(), keys={}, key_count=key_count,
                         query_hex=bytes(range(20)).hex(), scope='chosen safe-API policy only',
                         provenance='new wrapper refusal; native excluded behavior unspecified',
                         expected=dict(choice='ApiError', index=code, initializer_needed=False)))
    return rows


def mutants(source):
    changes = {
        'sixteen-byte-key': [('keys[index] == *query', 'keys[index][..16] == query[..16]')],
        'stop-at-first-empty': [('            if control == fingerprint',
            '            if control == u8::MAX { return Ok(QualifiedRowSelection { choice: RowChoice::SharedDefault, initializer_needed }); }\n            if control == fingerprint')],
        'fingerprint-shift-56': [('supplied_hash >> 57', 'supplied_hash >> 56')],
        'clamp-wrapped-lane': [('position.wrapping_add(lane) & mask', 'position.wrapping_add(lane).min(mask)')],
        'linear-group-step': [('step = step.wrapping_add(16);', 'step = 16;')],
        'eight-byte-step': [('step = step.wrapping_add(16);', 'step = step.wrapping_add(8);')],
        'initialize-only-default': [('choice: RowChoice::Bucket(index),\n                    initializer_needed,',
                                    'choice: RowChoice::Bucket(index),\n                    initializer_needed: false,')],
        'ignore-empty-count': [('if entry_count == 0 {', 'if entry_count == u64::MAX {')],
        'signed-positive-state': [('let initializer_needed = observed_state != 0;',
                                  'let initializer_needed = (observed_state as i32) > 0;')],
        'eight-lane-group': [('for lane in 0..16usize {', 'for lane in 0..8usize {')],
    }
    result = {}
    for name, replacements in changes.items():
        changed = source
        for before, after in replacements:
            need(changed.count(before) == 1, 'source mutation anchor: ' + name)
            changed = changed.replace(before, after)
        result[name] = changed
    return result


def policy_mutants(source):
    result = {}
    for name, before, after in [
        ('shape-error-label', 'return Err(SelectorInputError::ControlShape);', 'return Err(SelectorInputError::KeyCoverage);'),
        ('coverage-error-label', 'return Err(SelectorInputError::KeyCoverage);', 'return Err(SelectorInputError::ControlShape);'),
        ('cycle-error-label', 'Err(SelectorInputError::NoNormalExit)', 'Err(SelectorInputError::KeyCoverage)'),
    ]:
        need(source.count(before) == 1, 'policy mutation source anchor')
        result[name] = source.replace(before, after)
    return result


def prepare(out):
    need(not out.exists(), 'choose a fresh snapshot directory')
    out.mkdir(parents=True)
    native_rows = cases()
    api_rows = policy_cases(len(native_rows))
    rows = native_rows + api_rows
    original_sources = {}
    paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', BASE, '--', 'src/node94-margin-risk'], cwd=ROOT).decode().splitlines()
    for relative in filter(None, paths):
        source = ROOT / relative
        need(source.is_file() and not source.is_symlink(), 'component file/symlink')
        raw = source.read_bytes()
        baseline = subprocess.check_output(['git', 'show', BASE + ':' + relative], cwd=ROOT)
        if relative.endswith('/src/lib.rs'):
            baseline = baseline.replace(b'mod types;', b'mod types;\npub mod row_selector;')
        if not relative.endswith('/README.md'):
            need(raw == baseline, 'component input differs beyond declared selector integration: ' + relative)
        original_sources[relative] = sha(raw)
        target = out / 'repo' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    literal = 'research/work-items/RE-007-margin-path-94/boundaries.tsv'
    literal_raw = (ROOT / literal).read_bytes()
    need(literal_raw == subprocess.check_output(['git', 'show', BASE + ':' + literal], cwd=ROOT), 'external include fixture changed')
    original_sources[literal] = sha(literal_raw)
    literal_target = out / 'repo' / literal
    literal_target.parent.mkdir(parents=True, exist_ok=True)
    literal_target.write_bytes(literal_raw)
    selector_path = COMPONENT / 'src/row_selector.rs'
    selector = selector_path.read_bytes()
    (out / 'repo/src/node94-margin-risk/src/row_selector.rs').write_bytes(selector)
    (out / 'driver').mkdir()
    (out / 'driver/input_only.rs').write_bytes((HERE / 'input_only.rs').read_bytes())
    (out / 'context').mkdir()
    for name in ('PRE-RUST-FREEZE.json', 'vectors.json', 'native-anchors.json', 'lookup.gnu.txt', 'lookup.llvm.txt', 'STATIC-CONTROLS.json', 'check_freeze.py', 'README.md'):
        (out / 'context' / name).write_bytes((HERE / name).read_bytes())
    (out / 'cases.json').write_text(render(rows))
    (out / 'input.bin').write_bytes(input_bytes(rows))
    (out / 'expected.bin').write_bytes(expected_bytes(rows))
    plans = []
    (out / 'mutants').mkdir()
    for name, source in mutants(selector.decode()).items():
        witnesses = []
        for case in native_rows:
            try:
                if walk(case, name) != case['expected']:
                    witnesses.append(case)
            except (ValueError, IndexError):
                pass  # An error/hang is not admitted as a value counterexample here.
        need(witnesses, 'no normal value witness for source mutant: ' + name)
        witness = witnesses[0]
        directory = out / 'mutants' / name
        directory.mkdir()
        (directory / 'row_selector.rs').write_text(source)
        (directory / 'input.bin').write_bytes(input_bytes([witness]))
        (directory / 'expected.bin').write_bytes(expected_bytes([witness]))
        plans.append(dict(name=name, scope='qualified conditional posthash native value relation',
                          witness_id=witness['id'], witness_name=witness['name'],
                          predicted_value_counterexamples=len(witnesses), compiled_result='not run'))
    for name, source in policy_mutants(selector.decode()).items():
        code = {'shape-error-label': 0, 'coverage-error-label': 1, 'cycle-error-label': 2}[name]
        witness = next(case for case in api_rows if case['expected']['index'] == code)
        directory = out / 'mutants' / name
        directory.mkdir()
        (directory / 'row_selector.rs').write_text(source)
        (directory / 'input.bin').write_bytes(input_bytes([witness]))
        (directory / 'expected.bin').write_bytes(expected_bytes([witness]))
        plans.append(dict(name=name, scope='chosen safe-API policy only', witness_id=witness['id'],
                          witness_name=witness['name'], distinction='API error label only; no native result',
                          compiled_result='not run'))
    (out / 'mutants.json').write_text(render(plans))
    # All review/build scripts are frozen before the first compilation.
    (out / 'review-tools').mkdir()
    for name in ('prepare_selector.py', 'compare_selector.py', 'run_selector.py'):
        (out / 'review-tools' / name).write_bytes((HERE / name).read_bytes())
    for relative, digest in original_sources.items():
        need(sha((ROOT / relative).read_bytes()) == digest, 'live component changed during snapshot')
    need(selector_path.read_bytes() == selector, 'live selector changed during snapshot')
    record = dict(status='frozen preparation; compiled result not yet observed', base=BASE,
                  native_proof_commit=PROOF, prior_pre_source_freeze_sha256=PRIOR_FREEZE,
                  target_sha256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
                  pre_source_cases=10, later_conditional_posthash_cases=len(native_rows)-10,
                  qualified_posthash_cases=len(native_rows), chosen_safe_api_cases=len(api_rows),
                  total_comparison_cases=len(rows), whole_lookup_native_hash_admissible_cases=0,
                  native_relation_mutants=10, chosen_selector_safe_api_mutants=3,
                  original_component_sources=original_sources,
                  component_overlay='Tracked existing component: only pub mod row_selector after mod types plus authored selector module; README documentation is not compiler input.',
                  scope='Owned bucket/default marker and late-state nonzero predicate only; externally supplied H, stable logical controls plus native mirror, unique keys and normal termination.',
                  limits=['Native hash admissibility, Once/callback effects, native returned row pointer/lifetime/aliasing and physical read/store order are not implemented.',
                          'Count-zero ignores table arguments; nonzero tables have power-of-two N>=16, mask N-1, native C+j=controls[j&(N-1)] for 0<=j<N+15.',
                          'State argument is the late native load at 0x36f58df/0x36f5901; an entry snapshot requires stability until then.',
                          'Checked entry has new refusal policy for shape/key coverage/unresolved cycle. Its cases and error-label mutants are separate from native-domain mutations.'],
                  manifest=manifest(out), captured_execution=False)
    (out / 'FREEZE.json').write_text(render(record))
    print(render(dict(snapshot=str(out), freeze_sha256=sha((out/'FREEZE.json').read_bytes()),
                      cases=len(rows), mutants=len(plans), input_sha256=sha((out/'input.bin').read_bytes()),
                      expected_sha256=sha((out/'expected.bin').read_bytes()))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    prepare(parser.parse_args().out)
