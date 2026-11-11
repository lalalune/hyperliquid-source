#!/usr/bin/env python3
"""Reproduce ten release-only controls using installed tools and source copies.

Requires Python3.11+, installed Rust1.95.0 binaries, and a fresh output outside
Cargo workspace/config ancestry. No downloads, captured code or expected values
enter the built driver's input. Original both-profile qualification is separate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import tomllib

PLAN_SHA = '91b5a4eb9dcb98a8b3050cedb099a607d9f06abccda7b9dd828d2502276284e3'
CLEAN = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw)}


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(name, argv, cwd, environment, output, timeout=60):
    started = time.monotonic()
    code, error, stdout, stderr = None, None, b'', b''
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True, timeout=timeout)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as caught:
        error, stdout, stderr = 'timeout', caught.stdout or b'', caught.stderr or b''
    except OSError as caught:
        error = type(caught).__name__ + ': ' + str(caught)
    (output / (name + '.stdout')).write_bytes(stdout)
    (output / (name + '.stderr')).write_bytes(stderr)
    receipt = {'argv': argv, 'cwd': str(cwd), 'env': environment, 'exit_code': code,
               'error': error, 'duration_seconds': time.monotonic() - started,
               'stdout': {'bytes': len(stdout), 'sha256': digest(stdout)},
               'stderr': {'bytes': len(stderr), 'sha256': digest(stderr)}}
    save(output / (name + '.receipt.json'), receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'cargo', 'rustc', 'comparator', 'corpus', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    require(args.cargo.is_absolute() and args.rustc.is_absolute(), 'absolute installed tool paths required')
    source, cargo, rustc, comparator, corpus = [getattr(args, n).resolve(strict=True) for n in
                                               ('source', 'cargo', 'rustc', 'comparator', 'corpus')]
    output = args.output.resolve()
    require(cargo.name == 'cargo' and rustc.name == 'rustc', 'installed binaries required, not rustup shims')
    require(not output.exists() and output.parent.is_dir(), 'fresh output with existing parent required')
    for ancestor in (output, *output.parents):
        require(not any((ancestor / p).exists() for p in ('Cargo.toml', '.cargo/config', '.cargo/config.toml')),
                'output must be outside Cargo workspace/config ancestry')
    plan_path = Path(__file__).resolve().with_name('MUTATIONS.json')
    require(digest(plan_path.read_bytes()) == PLAN_SHA, 'portable mutation-plan identity differs')
    plan = json.loads(plan_path.read_bytes())
    pins = {source / name: sha for name, sha in plan['source_sha256'].items()}
    pins.update({comparator: plan['comparator_sha256'], corpus / 'MANIFEST.sha256': plan['corpus_manifest_sha256'], plan_path: PLAN_SHA})
    for path, wanted in pins.items():
        require(digest(path.read_bytes()) == wanted, 'pinned input differs: ' + str(path))
    for line in (corpus / 'MANIFEST.sha256').read_text().splitlines():
        wanted, name = line.split('  ', 1)
        require(Path(name).name == name and name not in ('', '.', '..'), 'simple corpus filename required')
        path = corpus / name
        require(digest(path.read_bytes()) == wanted, 'corpus entry differs: ' + name)
        pins[path] = wanted
    manifest = tomllib.loads((source / 'Cargo.toml').read_text())
    require(manifest['package']['build'] is False and not any('dependencies' in k for k in manifest), 'dependency-free build=false package required')
    require(len(plan['mutations']) == 10, 'exactly ten fixed mutations required')
    baseline = (source / 'lib.rs').read_text()
    output.mkdir()
    tool_environment = dict(CLEAN, CARGO_HOME=str(output / 'tool-cargo-home'), RUSTC=str(rustc), CARGO_NET_OFFLINE='true')
    (output / 'tool-cargo-home').mkdir()
    summary = {'profile': 'release', 'case_count': plan['case_count'], 'inputs': [identity(p) for p in pins],
               'tools': [identity(p) for p in (cargo, rustc, Path(sys.executable).resolve())],
               'reproducer': identity(Path(__file__).resolve()), 'variants': [], 'passed': False}
    try:
        for name, command in [('cargo-version', [str(cargo), '--version']), ('rustc-version', [str(rustc), '-vV'])]:
            receipt = run(name, command, output, tool_environment, output)
            require(receipt['exit_code'] == 0 and receipt['error'] is None, 'tool identity command failed')
        require(('cargo ' + plan['rust_release'] + ' ') in (output / 'cargo-version.stdout').read_text(), 'cargo release differs')
        require(('release: ' + plan['rust_release'] + '\n') in (output / 'rustc-version.stdout').read_text(), 'rustc release differs')
        for mutation in plan['mutations']:
            directory = output / mutation['id']
            directory.mkdir()
            crate, target, home = [directory / name for name in ('source', 'target', 'cargo-home')]
            for path in (crate, target, home):
                path.mkdir()
            record = {'id': mutation['id'], 'detected': False}
            try:
                changed = baseline
                for edit in mutation['edits']:
                    require(changed.count(edit['find']) == edit['expected_occurrences'] == 1, 'mutation needle not unique')
                    changed = changed.replace(edit['find'], edit['replace'], 1)
                require(digest(changed.encode()) == mutation['mutated_lib_sha256'], 'mutated source hash differs')
                for name in plan['source_sha256']:
                    (crate / name).write_bytes(changed.encode() if name == 'lib.rs' else (source / name).read_bytes())
                record['source_before_build'] = {name: identity(crate / name) for name in plan['source_sha256']}
                for name, wanted in plan['source_sha256'].items():
                    require(record['source_before_build'][name]['sha256'] == (mutation['mutated_lib_sha256'] if name == 'lib.rs' else wanted),
                            'copied source identity differs before Cargo invocation')
                environment = dict(CLEAN, CARGO_HOME=str(home), CARGO_TARGET_DIR=str(target), RUSTC=str(rustc),
                                   CARGO_NET_OFFLINE='true', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', RUSTFLAGS='-C target-cpu=generic')
                metadata = run('metadata', [str(cargo), 'metadata', '--offline', '--locked', '--no-deps', '--format-version', '1'], crate, environment, directory)
                require(metadata['exit_code'] == 0 and metadata['error'] is None, 'offline metadata failed')
                graph = json.loads((directory / 'metadata.stdout').read_bytes())
                require(len(graph['packages']) == 1 and not graph['packages'][0]['dependencies'], 'dependency graph differs')
                require(all('custom-build' not in t['kind'] for t in graph['packages'][0]['targets']), 'build hook forbidden')
                build = run('build', [str(cargo), 'build', '--offline', '--locked', '--release', '--bin', plan['driver_name']], crate, environment, directory)
                require(build['exit_code'] == 0 and build['error'] is None, 'offline locked release build failed')
                executable = target / 'release' / plan['driver_name']
                record['executable'] = identity(executable)
                record['source'] = {name: identity(crate / name) for name in plan['source_sha256']}
                for name, wanted in plan['source_sha256'].items():
                    require(record['source'][name]['sha256'] == (mutation['mutated_lib_sha256'] if name == 'lib.rs' else wanted), 'copied source changed during build')
                comparison = directory / 'comparison'
                command = [sys.executable, '-B', '-S', str(comparator), '--executable', str(executable), '--sha256', record['executable']['sha256'],
                           '--corpus', str(corpus), '--manifest-sha256', plan['corpus_manifest_sha256'], '--output', str(comparison)]
                check = run('compare', command, directory, CLEAN, directory, timeout=45)
                require(check['exit_code'] == 1 and check['error'] is None and not check['stderr']['bytes'], 'comparator did not report an ordinary mismatch')
                result = json.loads((comparison / 'comparison.json').read_bytes())
                require(result['exit_code'] == 0 and result['launch_failure'] is None and result['format_error'] is None,
                        'child/process/format error is not semantic detection')
                require(result['executable_unchanged'] and result['stderr']['bytes'] == 0 and result['case_count'] == plan['case_count'], 'child identity/count/stderr differs')
                actual = (comparison / 'actual.stdout').read_bytes()
                require(digest(actual) == result['stdout']['sha256'] and actual.endswith(b'\n') and len(actual.split(b'\n')) - 1 == plan['case_count'], 'complete output stream required')
                differences = {x['id']: x for x in result['mismatches']}
                require(len(differences) == result['mismatch_count'] > 0 and not result['passed'], 'nonempty unique semantic differences required')
                for witness in mutation['witnesses']:
                    found = differences.get(witness['case_id'], {})
                    require(found.get('expected') == witness['baseline_class'] and found.get('actual') == witness['mutant_class'], 'named witness did not distinguish mutation')
                record.update(detected=True, mismatch_count=result['mismatch_count'], witnesses=mutation['witnesses'], comparison=identity(comparison / 'comparison.json'))
            except (OSError, ValueError, KeyError, TypeError) as error:
                record['failure'] = type(error).__name__ + ': ' + str(error)
            summary['variants'].append(record)
            save(output / 'RESULTS.json', summary)
    except (OSError, ValueError, KeyError, TypeError) as error:
        summary['failure'] = type(error).__name__ + ': ' + str(error)
    try:
        summary['originals_unchanged'] = all(digest(p.read_bytes()) == wanted for p, wanted in pins.items())
        summary['tools_unchanged'] = all(digest(Path(x['path']).read_bytes()) == x['sha256'] for x in summary['tools'])
    except OSError as error:
        summary.update(originals_unchanged=False, tools_unchanged=False, integrity_failure=str(error))
    summary['passed'] = 'failure' not in summary and len(summary['variants']) == 10 and all(x['detected'] for x in summary['variants']) and summary['originals_unchanged'] and summary['tools_unchanged']
    save(output / 'RESULTS.json', summary)
    print(json.dumps({'passed': summary['passed'], 'detected': sum(x['detected'] for x in summary['variants']), 'variants': len(summary['variants'])}))
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
