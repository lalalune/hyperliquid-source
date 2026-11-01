#!/usr/bin/env python3
"""Four already-cleared static repository targets at the exact padding C1.

No test discovery, instruction evaluator, compiler or captured execution.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

ROOT = Path('/tmp/hl-resume-20261101/selector-56c')
OUT = Path('/tmp/hl-resume-20261101/padding-static-255eea2c')
HEAD = '255eea2cc3ae6f75b807b4f000af455c710f4b6f'
OLD = Path('/tmp/hl-resume-20261101/padding-build-56c-c1/BEFORE.json')
assert hashlib.sha256(OLD.read_bytes()).hexdigest() == 'b88583f1cced26ac710050f80b5633a66b281e2a37dbd19e3560489d946f9bb4'
known = json.loads(OLD.read_text())
spec = importlib.util.spec_from_file_location('padding_guards', ROOT / 'research/work-items/RE-005-integral-padding-94/validate_padding.py')
guards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guards)
assert not OUT.exists()
OUT.mkdir()
prefix = Path('/tmp/hl-resume-20261101/toolchain/prefix')
env = dict(guards.CLEAN_ENV, PATH=str(prefix / 'bin') + ':/usr/local/bin:/usr/bin:/bin')


def audit():
    value = {'repositories': [], 'tracked_physical_inputs': {}, 'provider_payloads': {}}
    for row in known['repositories']:
        base = ROOT / row['path']
        assert Path(guards.git(base, 'rev-parse', '--show-toplevel')).resolve() == base.resolve()
        got = {'path': row['path'], 'head': guards.git(base, 'rev-parse', 'HEAD'),
               'tree': guards.git(base, 'rev-parse', 'HEAD^{tree}'),
               'status': guards.git(base, 'status', '--porcelain', '--untracked-files=all')}
        assert got == row
        value['repositories'].append(got)
    assert value['repositories'][0]['head'] == HEAD
    for name, expected in known['tracked_physical_inputs'].items():
        actual = guards.physical(ROOT / name)
        assert actual == expected, name
        value['tracked_physical_inputs'][name] = actual
    for name, expected in known['provider_payloads'].items():
        actual = guards.physical(prefix / name)
        assert actual == expected, name
        value['provider_payloads'][name] = actual
    for name, path in [('provider_audit', '/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json'),
                       ('linker', '/usr/bin/gcc'), ('ld_bfd', '/usr/bin/ld.bfd'),
                       ('target', ROOT / 'artifacts/node/94/hl-node'),
                       ('core_archive', prefix / 'lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'),
                       ('runner', ROOT / 'research/work-items/RE-005-integral-padding-94/validate_padding.py')]:
        actual = guards.physical(Path(path).resolve())
        assert actual == known[name], name
        value[name] = actual
    return value


before = audit()
(OUT / 'BEFORE.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
calls = []
for target in ['doctor', 'verify', 'catalogue-check', 'reproduce']:
    argv = ['make', '-j1', 'PYTHON=' + sys.executable + ' -B', target]
    start = time.monotonic()
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True)
    row = {'target': target, 'argv': argv, 'exit': result.returncode,
           'seconds': time.monotonic() - start, 'streams': {}}
    for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
        path = OUT / (target + '.' + suffix)
        path.write_bytes(raw)
        row['streams'][suffix] = {'file': path.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    calls.append(row)
    print(json.dumps(row), flush=True)
    if result.returncode:
        break
after = audit()
(OUT / 'AFTER.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
(OUT / 'CALLS.json').write_text(json.dumps(calls, sort_keys=True, indent=2) + '\n')
result = {'status': 'PASS' if before == after and len(calls) == 4 and all(c['exit'] == 0 for c in calls) else 'FAIL',
          'source_head': HEAD, 'same_inputs': before == after, 'tracked_physical_inputs': len(before['tracked_physical_inputs']),
          'provider_payloads': len(before['provider_payloads']), 'pinned_repositories': len(before['repositories']) - 1,
          'calls': calls, 'full_test_suite': 'NOT_RUN: expanded instruction-evaluator scope is not authorized',
          'captured_execution_or_instruction_evaluator': False,
          'static_wrapper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(OUT / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps(result), flush=True)
raise SystemExit(0 if result['status'] == 'PASS' else 1)
