#!/usr/bin/env python3
"""Retain/replay actual authored-Rust streams; never execute captured code."""
import argparse
import base64
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('selector_'+name, HERE/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(directory):
    report_raw = (directory/'REPORT.json').read_bytes()
    report = json.loads(report_raw)
    streams = {}
    for command in report['commands']:
        label = command['label']
        need(label not in streams, 'duplicate command label')
        streams[label] = {}
        for channel in ('stdout', 'stderr'):
            raw = (directory/(label+'.'+channel)).read_bytes()
            need(sha(raw) == command[channel+'_sha256'], 'raw stream changed before retention')
            streams[label][channel] = base64.b64encode(raw).decode()
    target = HERE/'observed'
    target.mkdir(exist_ok=True)
    (target/'report.json.gz.b64').write_bytes(base64.encodebytes(gzip.compress(report_raw, mtime=0)))
    stream_raw = json.dumps(streams, sort_keys=True, separators=(',', ':')).encode()
    (target/'streams.json.gz.b64').write_bytes(base64.encodebytes(gzip.compress(stream_raw, mtime=0)))
    (target/'FREEZE.sha256').write_text(report['freeze_sha256']+'\n')
    result = audit(report, streams)
    result.update(report_sha256=sha(report_raw), stream_payload_sha256=sha(stream_raw),
                  retained_channels=2*len(streams), raw_stream_bytes=sum(
                      len(base64.b64decode(payload)) for stream in streams.values() for payload in stream.values()))
    (target/'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    return result


def load():
    report_raw = gzip.decompress(base64.b64decode(b''.join((HERE/'observed/report.json.gz.b64').read_bytes().split()), validate=True))
    stream_raw = gzip.decompress(base64.b64decode(b''.join((HERE/'observed/streams.json.gz.b64').read_bytes().split()), validate=True))
    summary = json.loads((HERE/'observed/summary.json').read_text())
    need(sha(report_raw) == summary['report_sha256'], 'retained report identity')
    need(sha(stream_raw) == summary['stream_payload_sha256'], 'retained stream payload identity')
    return json.loads(report_raw), json.loads(stream_raw)


def audit(report, streams):
    recipe = module('prepare_selector')
    comparator = module('compare_selector')
    native = recipe.cases()
    policies = recipe.policy_cases(len(native))
    rows = native + policies
    need((len(native), len(policies)) == (894, 7), 'corpus denominators changed')
    expected = recipe.expected_bytes(rows)
    stimulus = recipe.input_bytes(rows)
    commands = {command['label']: command for command in report['commands']}
    need(len(commands) == len(report['commands']) and set(commands) == set(streams), 'stream labels incomplete')
    decoded = {}
    for label, command in commands.items():
        decoded[label] = {}
        need(command['exit_code'] == (2 if label.startswith('framing-') else 0), 'command exit changed')
        for channel in ('stdout', 'stderr'):
            raw = base64.b64decode(streams[label][channel], validate=True)
            need(sha(raw) == command[channel+'_sha256'], 'retained stream hash changed')
            decoded[label][channel] = raw
    for build in report['builds']:
        label = build['profile']+'-driver-run'
        raw = decoded[label]['stdout']
        need(commands[label]['stdin_sha256'] == sha(stimulus), 'compiled baseline stimulus changed')
        need(not comparator.mismatches(raw, expected), 'compiled baseline value mismatch')
        need(sha(raw) == build['output_sha256'], 'build output identity mismatch')
    need(len(report['builds']) == 4, 'build-profile denominator changed')
    source = (HERE.parents[2]/'src/node94-margin-risk/src/row_selector.rs').read_text()
    sources = recipe.mutants(source) | recipe.policy_mutants(source)
    groups = [report['native_relation_source_mutants'], report['chosen_selector_safe_api_mutants']]
    need(list(map(len, groups)) == [10, 3], 'mutant denominators changed')
    for group, native_domain in zip(groups, (True, False)):
        for control in group:
            name = control['name']
            need(control['source_manifest']['src/row_selector.rs']['sha256'] == sha(sources[name].encode()),
                 'mutant compiler source is not the frozen operative change')
            row = rows[control['witness_id']]
            need(row['name'] == control['witness_name'], 'mutant witness attribution changed')
            label = name+'-driver-run'
            need(commands[label]['stdin_sha256'] == sha(recipe.input_bytes([row])), 'mutant witness stimulus changed')
            raw = decoded[label]['stdout']
            need(sha(raw) == control['output_sha256'], 'mutant output receipt identity')
            wanted = recipe.expected_bytes([row])
            need(comparator.mismatches(raw, wanted) == [0], 'mutant value distinction missing')
            need((raw[16] < 2 and wanted[16] < 2) if native_domain else (raw[16] == wanted[16] == 2),
                 'native/policy mutant distinction crossed domains')
    component_tests = {}
    for opt in (0, 3):
        stdout = decoded[f'o{opt}-component-tests']['stdout'].decode()
        counts = list(map(int, re.findall(r'test result: ok\. (\d+) passed; 0 failed;', stdout)))
        need(sum(counts) == 40, 'component tests missing or changed')
        component_tests[str(opt)] = sum(counts)
    for name in report['driver_framing_controls']:
        need(not decoded['framing-'+name]['stdout'], 'malformed framing emitted partial output')
    need(len(report['driver_framing_controls']) == 5, 'framing-control denominator')
    return dict(status='retained actual Rust streams replay against independent expectations',
                qualified_posthash_cases=894, chosen_policy_cases=7, profiles=4,
                posthash_observations=3576, policy_observations=28,
                native_normal_value_mutants=10, chosen_api_label_mutants=3,
                component_tests_by_opt=component_tests, driver_framing_controls=5,
                input_sha256=sha(stimulus), expected_sha256=sha(expected),
                freeze_sha256=report['freeze_sha256'], target_executed=False)


def recorded_snapshot(report):
    """Preserve the original compiler inputs while this component gains modules."""
    archive = HERE/'observed/source-snapshot.json.gz.b64'
    raw = gzip.decompress(base64.b64decode(b''.join(archive.read_bytes().split()), validate=True))
    records = json.loads(raw)
    expected = report['frozen']['manifest']
    need(set(records) == set(expected) | {'FREEZE.json'}, 'historical snapshot file set changed')
    result = {}
    for name, encoded in records.items():
        path = Path(name)
        need(not path.is_absolute() and '..' not in path.parts, 'historical snapshot path escaped')
        payload = base64.b64decode(encoded, validate=True)
        if name == 'FREEZE.json':
            need(sha(payload) == report['freeze_sha256'], 'historical freeze identity changed')
            need(json.loads(payload) == report['frozen'], 'historical freeze metadata changed')
        else:
            need(dict(bytes=len(payload), sha256=sha(payload)) == expected[name], 'historical compiler/input payload changed')
        result[name] = payload
    return result


def extract_recorded_snapshot(destination, report):
    need(not destination.exists(), 'choose a fresh historical snapshot directory')
    records = recorded_snapshot(report)
    for name, raw in records.items():
        path = destination/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return destination


def check_recorded_snapshot(report):
    comparator = module('compare_selector')
    with tempfile.TemporaryDirectory(prefix='selector-historical-inputs-') as temporary:
        snapshot = Path(temporary)/'fixed'
        extract_recorded_snapshot(snapshot, report)
        comparator.authenticate(snapshot, report['freeze_sha256'])
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-from', type=Path)
    parser.add_argument('--extract-snapshot', type=Path)
    args = parser.parse_args()
    if args.archive_from is not None:
        result = archive(args.archive_from)
    elif args.extract_snapshot is not None:
        report, _ = load()
        extract_recorded_snapshot(args.extract_snapshot, report)
        result = dict(extracted_original_snapshot=str(args.extract_snapshot), freeze_sha256=report['freeze_sha256'])
    else:
        report, streams = load()
        result = audit(report, streams)
        result['recorded_compiler_input_snapshot_matches'] = check_recorded_snapshot(report)
    print(json.dumps(result, indent=2, sort_keys=True))
