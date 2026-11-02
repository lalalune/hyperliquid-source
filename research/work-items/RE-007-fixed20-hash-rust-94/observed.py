#!/usr/bin/env python3
"""Replay retained authored-Rust output against pre-source mathematical fixtures."""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unpack_archive(path):
    return gzip.decompress(base64.b64decode(b''.join(path.read_bytes().split()), validate=True))


def retain(path, raw):
    path.write_bytes(base64.encodebytes(gzip.compress(raw, mtime=0)))


def recorded_snapshot(report):
    records = json.loads(unpack_archive(HERE/'observed/source-snapshot.json.gz.b64'))
    manifest = report['frozen']['manifest']
    need(set(records) == set(manifest) | {'SOURCE-FREEZE.json'}, 'recorded source/input file set changed')
    result = {}
    for name, encoded in records.items():
        path = Path(name)
        need(not path.is_absolute() and '..' not in path.parts, 'recorded snapshot path escaped')
        raw = base64.b64decode(encoded, validate=True)
        if name == 'SOURCE-FREEZE.json':
            need(sha(raw) == report['source_freeze_sha256'], 'source freeze digest changed')
            need(json.loads(raw) == report['frozen'], 'source freeze object changed')
        else:
            need(dict(bytes=len(raw), sha256=sha(raw)) == manifest[name], 'recorded compiler/input payload changed')
        result[name] = raw
    return result


def extract_snapshot(destination, report):
    need(not destination.exists(), 'fresh extraction directory required')
    for name, raw in recorded_snapshot(report).items():
        path = destination/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return destination


def expectations(snapshot):
    """Independent tuple/residue oracle and a single-entry membership relation."""
    oracle = module(snapshot/'context/hash-preparation/oracle.py', 'pre_source_fixed20_oracle')
    rows = oracle.cases()
    data = snapshot/'data'
    need(rows == json.loads((data/'cases.json').read_bytes()), 'frozen hash recipes differ from mathematical oracle')
    stimulus, expected = oracle.inputs(rows), oracle.outputs(rows)
    need(stimulus == (data/'input.bin').read_bytes(), 'hash input recipe changed')
    need(expected == (data/'expected.bin').read_bytes(), 'hash expected values changed')
    controls = oracle.controls(rows)
    need(controls == json.loads((data/'controls.json').read_bytes()), 'pre-source wrong-math controls changed')
    comp_rows = json.loads((data/'composition-cases.json').read_bytes())
    need(len(comp_rows) == 1980, 'composition denominator changed')
    comp_input = bytearray(b'K20CMP01'+struct.pack('<I', len(comp_rows)))
    comp_expected = bytearray(b'K20CMO01'+struct.pack('<I', len(comp_rows)))
    for index, record in enumerate(comp_rows):
        query = rows[record['hash_case']]
        stored = rows[record['stored_hash_case']]
        need(record['id'] == index and record['hash_case'] == index//2, 'composition recipe ID changed')
        need(query['seed'] == stored['seed'], 'stored key used another seed pair')
        need(record['hit'] == (index % 2 == 0), 'hit/default alternation changed')
        need(record['late_state'] == [0, 3, 0x80000000, 0xffffffff][query['id'] % 4], 'late-state fixture changed')
        query_bytes, stored_bytes = bytes.fromhex(query['query_hex']), bytes.fromhex(stored['query_hex'])
        stored_hash = oracle.hash_math(stored['seed'], stored_bytes)
        bucket = stored_hash & 31
        controls_bytes = bytearray([255])*32
        controls_bytes[bucket] = stored_hash >> 57
        keys = bytearray(32*20)
        keys[bucket*20:(bucket+1)*20] = stored_bytes
        comp_input.extend(struct.pack('<IQQII', index, *query['seed'], record['late_state'], 32))
        comp_input.extend(query_bytes+controls_bytes+keys)
        # A single occupied bucket is visible in the first 16 lanes iff its
        # circular distance from the start is <16. The first group always has
        # an empty lane, so only that candidate can beat the default branch.
        matches = query_bytes == stored_bytes and (query['expected'] >> 57) == (stored_hash >> 57)
        selected = bucket if matches and ((bucket-(query['expected'] & 31)) & 31) < 16 else None
        need((selected is not None) == record['hit'] and record['bucket'] == selected, 'independent membership relation differs')
        comp_expected.extend(struct.pack('<IQBBQ', index, query['expected'], int(selected is not None),
                                         int(record['late_state'] != 0), (1 << 64)-1 if selected is None else selected))
    need(bytes(comp_input) == (data/'composition-input.bin').read_bytes(), 'composition input recipe changed')
    need(bytes(comp_expected) == (data/'composition-expected.bin').read_bytes(), 'composition expected values changed')
    return rows, controls, stimulus, expected, bytes(comp_input), bytes(comp_expected)


def audit(report, streams, snapshot):
    recipe = module(HERE/'verify.py', 'fixed20_recipe')
    recipe.authentic(snapshot, report['source_freeze_sha256'])
    need(report['whole_lookup_admitted_vectors'] == 0 and report['captured_execution'] is False, 'runtime scope changed')
    rows, controls, stimulus, expected, comp_input, comp_expected = expectations(snapshot)
    commands = {record['label']: record for record in report['commands']}
    need(len(commands) == len(report['commands']) == 66 and set(commands) == set(streams), 'command/channel set changed')
    decoded = {}
    for label, record in commands.items():
        need(set(streams[label]) == {'stdout', 'stderr'}, 'missing/extra output channel')
        need(record['exit_code'] == (2 if label.startswith('hash-') else 0), 'observed command exit changed')
        decoded[label] = {}
        for channel in ['stdout', 'stderr']:
            raw = base64.b64decode(streams[label][channel], validate=True)
            need(sha(raw) == record[channel+'_sha256'], 'retained actual stream identity changed')
            decoded[label][channel] = raw
    need(report['compiler_version'].startswith('rustc 1.94.1 '), 'compiler version changed')
    need(len(report['tool_hashes']) == 3 and 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d' in report['tool_hashes'].values(), 'pinned rustc missing')
    need([p['profile'] for p in report['profiles']] == ['o0-r0', 'o0-r1', 'o3-r0', 'o3-r1'], 'build profiles changed')
    for profile in report['profiles']:
        prefix = profile['profile']
        for kind, payload, wanted, count in [('hash', stimulus, expected, 990), ('composition', comp_input, comp_expected, 1980)]:
            command = commands[prefix+'-'+kind+'-run']
            actual = decoded[prefix+'-'+kind+'-run']['stdout']
            need(command['stdin_sha256'] == sha(payload), 'compiled baseline stimulus changed')
            need(actual == wanted, 'compiled '+kind+' normal value mismatch')
            need(profile[kind]['cases'] == count and profile[kind]['mismatches'] == 0, 'profile denominator changed')
            need(profile[kind]['output_sha256'] == sha(actual), 'profile output identity changed')
    need(len(report['source_mutants']) == len(controls) == 13, 'math mutant denominator changed')
    source = (snapshot/'repo/src/node94-margin-risk/src/hash20.rs').read_text()
    variants = recipe.variants(source)
    for record, control in zip(report['source_mutants'], controls):
        name = control['name']
        need(all(record[key] == control[key] for key in ['name', 'witness', 'witness_name', 'wrong_hash']), 'math mutant attribution changed')
        need(record['normal_value_distinction'] is True, 'math mutant class changed')
        prefix = 'repo/src/node94-margin-risk/'
        wanted_manifest = {key[len(prefix):]: value for key, value in report['frozen']['manifest'].items() if key.startswith(prefix)}
        changed = variants[name].encode()
        wanted_manifest['src/hash20.rs'] = dict(bytes=len(changed), sha256=sha(changed))
        need(record['source_manifest'] == wanted_manifest, 'operative compiler mutant tree changed')
        witness = rows[control['witness']]
        need(commands[name+'-driver-run']['stdin_sha256'] == sha(b'K20IN001'+struct.pack('<I', 1)+stimulus[12+40*witness['id']:52+40*witness['id']]), 'mutant stimulus changed')
        actual = decoded[name+'-driver-run']['stdout']
        wrong = b'K20OUT01'+struct.pack('<IIQ', 1, witness['id'], control['wrong_hash'])
        need(actual == wrong and control['wrong_hash'] != witness['expected'], 'math mutant lacks pre-source normal wrong-u64 witness')
        need(sha(actual) == record['actual_sha256'], 'mutant output receipt changed')
    label = 'composition-wiring-run'
    need(commands[label]['stdin_sha256'] == sha(b'K20CMP01'+struct.pack('<I', 1)+comp_input[12+4*720:12+5*720]), 'join witness stimulus changed')
    actual = decoded[label]['stdout']
    witness = comp_expected[12+4*22:12+5*22]
    wrong = b'K20CMO01'+struct.pack('<I', 1)+witness[:12]+bytes([0, witness[13]])+bytes([255])*8
    need(actual == wrong and witness[12] == 1, 'join control lacks unchanged-H normal selection distinction')
    need(report['composition_wiring_control'] == dict(normal_result_changed=True, actual_sha256=sha(actual)), 'join receipt changed')
    component_counts = {}
    for opt in [0, 3]:
        raw = decoded[f'o{opt}-component-tests']['stdout'].decode()
        counts = list(map(int, re.findall(r'test result: ok\. (\d+) passed; 0 failed;', raw)))
        need(sum(counts) == 41, 'current component test count changed')
        component_counts[str(opt)] = sum(counts)
    malformed = {'hash-bad-magic': b'BADIN001'+stimulus[8:], 'hash-truncated': stimulus[:-1], 'hash-trailing': stimulus+b'\0'}
    need(report['driver_framing_controls'] == list(malformed), 'framing policy controls changed')
    for label, payload in malformed.items():
        need(commands[label]['stdin_sha256'] == sha(payload) and not decoded[label]['stdout'], 'framing policy output/stimulus changed')
    return dict(hash_cases=990, synthetic_composition_cases=1980, profiles=4, hash_observations=3960,
                composition_observations=7920, normal_wrong_hash_mutants=13, normal_join_controls=1,
                driver_framing_policy_controls=3, component_tests_by_opt=component_counts,
                commands=66, channels=132, source_freeze_sha256=report['source_freeze_sha256'],
                whole_lookup_admitted_vectors=0, captured_execution=False)


def check_selected_sources(snapshot):
    for relative in ['src/hash20.rs', 'src/row_selector.rs', 'tests/hash20_vectors.rs']:
        need((ROOT/'src/node94-margin-risk'/relative).read_bytes() ==
             (snapshot/'repo/src/node94-margin-risk'/relative).read_bytes(), 'selected current Rust source differs from compiled receipt')
    for name in ['hash_driver.rs', 'composition_driver.rs']:
        need((HERE/name).read_bytes() == (snapshot/'drivers'/name).read_bytes(), 'input-only driver differs from compiled receipt')
    need('pub mod hash20;' in (ROOT/'src/node94-margin-risk/src/lib.rs').read_text(), 'public module export missing')
    return True


def check_current_component(snapshot, report):
    """Optional active-integration check; historical replay uses selected sources."""
    root = ROOT/'src/node94-margin-risk'
    paths = [p for p in root.rglob('*') if p.is_file() and p.relative_to(root).parts[0] != 'target']
    prefix = 'repo/src/node94-margin-risk/'
    wanted = {key[len(prefix):]: value for key, value in report['frozen']['manifest'].items() if key.startswith(prefix)}
    actual = {}
    for path in paths:
        need(not path.is_symlink(), 'current component source symlink')
        raw = path.read_bytes()
        actual[str(path.relative_to(root))] = dict(bytes=len(raw), sha256=sha(raw))
    need(actual == wanted, 'current component differs from recorded compiler tree')
    return len(actual)


def archive(directory, snapshot):
    report_raw = (directory/'REPORT.json').read_bytes()
    report = json.loads(report_raw)
    streams = {}
    for command in report['commands']:
        label = command['label']
        need(label not in streams, 'duplicate command label')
        streams[label] = {}
        for channel in ['stdout', 'stderr']:
            raw = (directory/(label+'.'+channel)).read_bytes()
            need(sha(raw) == command[channel+'_sha256'], 'raw stream changed before retention')
            streams[label][channel] = base64.b64encode(raw).decode()
    result = audit(report, streams, snapshot)
    check_selected_sources(snapshot)
    target = HERE/'observed'
    target.mkdir(exist_ok=True)
    records = {str(p.relative_to(snapshot)): base64.b64encode(p.read_bytes()).decode()
               for p in sorted(snapshot.rglob('*')) if p.is_file()}
    source_raw = json.dumps(records, sort_keys=True, separators=(',', ':')).encode()
    stream_raw = json.dumps(streams, sort_keys=True, separators=(',', ':')).encode()
    for name, raw in [('report', report_raw), ('streams', stream_raw), ('source-snapshot', source_raw)]:
        retain(target/(name+'.json.gz.b64'), raw)
        result[name+'_payload_sha256'] = sha(raw)
    (target/'FREEZE.sha256').write_text(report['source_freeze_sha256']+'\n')
    result['raw_stream_bytes'] = sum(len(base64.b64decode(raw)) for pair in streams.values() for raw in pair.values())
    (target/'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    return result


def load():
    summary = json.loads((HERE/'observed/summary.json').read_bytes())
    payloads = {}
    for name in ['report', 'streams', 'source-snapshot']:
        raw = unpack_archive(HERE/'observed'/(name+'.json.gz.b64'))
        need(sha(raw) == summary[name+'_payload_sha256'], 'retained '+name+' payload identity changed')
        payloads[name] = json.loads(raw)
    need((HERE/'observed/FREEZE.sha256').read_text().strip() == payloads['report']['source_freeze_sha256'], 'source freeze marker changed')
    return payloads['report'], payloads['streams']


def replay(current_component=False):
    report, streams = load()
    with tempfile.TemporaryDirectory(prefix='fixed20-recorded-') as directory:
        snapshot = extract_snapshot(Path(directory)/'fixed', report)
        result = audit(report, streams, snapshot)
        result['selected_current_sources_match'] = check_selected_sources(snapshot)
        if current_component:
            result['current_component_files_match'] = check_current_component(snapshot, report)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-from', type=Path)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--current-component', action='store_true')
    args = parser.parse_args()
    if args.archive_from:
        need(args.snapshot is not None, 'archive needs exact compiler/input snapshot')
        result = archive(args.archive_from, args.snapshot)
    else:
        result = replay(args.current_component)
    print(json.dumps(result, indent=2, sort_keys=True))
