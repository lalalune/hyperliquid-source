#!/usr/bin/env python3
"""Four already-cleared static repository targets at the exact writer649 corrected checkpoint.

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
OUT = Path('/tmp/hl-resume-20261101/writer649-static-51c0ea7f')
HEAD = '51c0ea7fc4a035b4c0dd690f9310657b39ea9db4'
OLD = Path('/tmp/hl-resume-20261101/writer649-build-51c0ea7f/BEFORE.json')
assert hashlib.sha256(OLD.read_bytes()).hexdigest() == 'ec99960ec712a312d714a169b5c8c390f3687d68f32247af9c86a0a1466836ad'
known = json.loads(OLD.read_text())
spec = importlib.util.spec_from_file_location('padding_guards', ROOT / 'tools/validate_parts_writer649.py')
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
    value['installed_component_manifests'] = {}
    for name, expected in known['installed_component_manifests'].items():
        actual = guards.physical(prefix / 'lib/rustlib' / name)
        assert actual == expected, name
        value['installed_component_manifests'][name] = actual
    for name, path in [('provider_audit', '/tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json'),
                       ('linker', '/usr/bin/gcc'), ('ld_bfd', '/usr/bin/ld.bfd'),
                       ('target', ROOT / 'artifacts/node/94/hl-node'),
                       ('core_archive', prefix / 'lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'),
                       ('runner', ROOT / 'tools/validate_parts_writer649.py')]:
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
          'provider_payloads': len(before['provider_payloads']), 'installed_manifests': len(before['installed_component_manifests']), 'pinned_repositories': len(before['repositories']) - 1,
          'calls': calls, 'full_test_suite': 'NOT_RUN: expanded instruction-evaluator scope is not authorized',
          'captured_execution_or_instruction_evaluator': False,
          'static_wrapper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(OUT / 'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps(result), flush=True)
raise SystemExit(0 if result['status'] == 'PASS' else 1)
