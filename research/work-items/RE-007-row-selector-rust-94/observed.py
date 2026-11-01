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


def check_current_tree(report):
    recipe = module('prepare_selector')
    comparator = module('compare_selector')
    root = HERE.parents[2]
    component = root/'src/node94-margin-risk'
    current = {str(path.relative_to(root)) for path in component.rglob('*')
               if path.is_file() and path.relative_to(component).parts[0] != 'target'}
    bound = {name[len('repo/'):] for name in report['frozen']['manifest']
             if name.startswith('repo/src/node94-margin-risk/')}
    need(current == bound, 'live component has missing/additional source inputs')
    with tempfile.TemporaryDirectory(prefix='selector-current-tree-') as temporary:
        snapshot = Path(temporary)/'fixed'
        with contextlib.redirect_stdout(io.StringIO()):
            recipe.prepare(snapshot)
        need(sha((snapshot/'FREEZE.json').read_bytes()) == report['freeze_sha256'], 'current tree differs from compiled freeze')
        comparator.authenticate(snapshot, report['freeze_sha256'])
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-from', type=Path)
    args = parser.parse_args()
    if args.archive_from is not None:
        result = archive(args.archive_from)
    else:
        report, streams = load()
        result = audit(report, streams)
        result['current_compiler_input_tree_matches'] = check_current_tree(report)
    print(json.dumps(result, indent=2, sort_keys=True))
