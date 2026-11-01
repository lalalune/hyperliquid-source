#!/usr/bin/env python3
"""Build only the authored standalone Rust value component, offline and locked."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-funding-record-storage'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/returned_records.rs']
STATIC_FREEZE = '22d5f0aa101dfb81b80429a6ef9064e6085e11f08ff69b3777216e9ce2004bcb'
STATIC_MANIFEST = '00eb571882d4d606e38a559b95e1bb06ef3f706f9b588ffb525c57771c5f058c'
PRE_FREEZE = 'd11b02025f9a64c66a1a61816dce62d8ba6b4d7f14eeede89f97250eb8732a9c'
PRE_MANIFEST = '9c6ce7334aa16d07ad9d461877090e3fca6c7d82a7f6b1a3a369dd5afc64f73c'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw)}


def inventory(path):
    return {p.relative_to(path).as_posix(): identity(p)
            for p in sorted(path.rglob('*')) if p.is_file()}


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


def check_manifest(base):
    count = 0
    for line in (base / 'MANIFEST.sha256').read_text().splitlines():
        digest, name = line.split('  ', 1)
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'manifest path')
        require(identity(base / relative)['sha256'] == digest, 'changed frozen file: ' + name)
        count += 1
    return count


def admit_sources(expected_source_freeze):
    for path, expected in [(PACKET / 'FINAL-FREEZE.json', STATIC_FREEZE),
                           (PACKET / 'MANIFEST.sha256', STATIC_MANIFEST),
                           (PACKET / 'pre-rust/PRE-RUST-FREEZE.json', PRE_FREEZE),
                           (PACKET / 'pre-rust/MANIFEST.sha256', PRE_MANIFEST),
                           (HERE / 'SOURCE-FREEZE.json', expected_source_freeze)]:
        require(identity(path)['sha256'] == expected, 'phase freeze identity: ' + path.name)
    require(check_manifest(PACKET) == 53 and check_manifest(PACKET / 'pre-rust') == 10,
            'original chronological manifests')
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'node94-funding-record-storage', 'version': '0.1.0'}],
            'actual dependency-free Cargo lock')
    return freeze, manifest, lock


def compare(actual, expected):
    left, right = actual.splitlines(keepends=True), expected.splitlines(keepends=True)
    differences = [i for i in range(max(len(left), len(right)))
                   if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    return {'equal': actual == expected, 'actual_rows': len(left), 'expected_rows': len(right),
            'different_rows': len(differences), 'first_different_rows': differences[:12],
            'actual_sha256': sha(actual), 'expected_sha256': sha(expected)}


def comparator_controls(expected):
    rows = expected.splitlines(keepends=True)
    changed = bytearray(expected)
    position = expected.index(b'000000000000000b')
    changed[position + 15] = ord('c')
    values = {'omit-final': b''.join(rows[:-1]), 'extra-row': expected + rows[0],
              'reorder': b''.join([rows[1], rows[0], *rows[2:]]),
              'duplicate-ID': b''.join([rows[0], rows[0], *rows[2:]]),
              'change-payload': bytes(changed), 'missing-final-LF': expected[:-1],
              'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b''}
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    stop = '        if record.tag == 2 {\n            break;\n        }\n'
    append = 'samples.entry(record.key).or_default().push(record.payload);'
    fallback = 'fallbacks.insert(record.key, record.payload);'
    end = '        }\n    }\n}\n'
    definitions = [
        ('never-stop', [('if record.tag == 2 {', 'if false {')]),
        ('low-byte-stop', [('if record.tag == 2 {', 'if record.tag as u8 == 2 {')]),
        ('stop-after-parity', [(stop, ''), (end, '        }\n        if record.tag == 2 {\n            break;\n        }\n    }\n}\n')]),
        ('only-tag-one-fallback', [('} else if dex_byte == 3 {', '} else if dex_byte == 3 && record.tag == 1 {')]),
        ('nonzero-dex-guard', [('} else if dex_byte == 3 {', '} else if dex_byte != 0 {')]),
        ('first-fallback-wins', [(fallback, 'fallbacks.entry(record.key).or_insert(record.payload);')]),
        ('replace-sample', [(append, 'samples.insert(record.key, vec![record.payload]);')]),
        ('drop-absent-sample', [(append, 'if let Some(values) = samples.get_mut(&record.key) {\n                values.push(record.payload);\n            }')]),
        ('clear-initial-state', [('    for record in records {', '    samples.clear();\n    fallbacks.clear();\n    for record in records {')]),
        ('clear-payload-low-bit', [(append, 'samples.entry(record.key).or_default().push(record.payload & !1);'),
                                   (fallback, 'fallbacks.insert(record.key, record.payload & !1);')]),
    ]
    result = []
    for name, edits in definitions:
        changed = original
        for before, after in edits:
            require(changed.count(before) == 1, 'mutation coordinate: ' + name)
            changed = changed.replace(before, after, 1)
        require(changed != original, 'unchanged mutation')
        result.append((name, changed, {'name': name, 'edits': edits, 'source_sha256': sha(changed.encode())}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh direct child of canonical /tmp')
    parser.add_argument('--private-map', type=Path, required=True, help='fresh path outside public packet')
    parser.add_argument('--source-freeze-sha', required=True)
    args = parser.parse_args()
    toolchain = args.toolchain.resolve()
    out = args.out.resolve()
    private_map = args.private_map.resolve()
    require(out.parent == Path('/tmp').resolve() and not out.exists(), 'fresh canonical /tmp output required')
    require(not private_map.exists() and not private_map.is_relative_to(PACKET), 'private mapping path')
    freeze, manifest, lock = admit_sources(args.source_freeze_sha)
    original_source = (SOURCE / 'src/lib.rs').read_text()
    variations = mutants(original_source)
    pins = json.loads((HERE / 'TOOLCHAIN-PINS.json').read_text())
    tools_before = {directory + '/' + name: value for directory in ['bin', 'lib']
                    for name, value in inventory(toolchain / directory).items()}
    require(tools_before == pins['payload_files'], 'toolchain payload differs from pre-build pins')
    out.mkdir(mode=0o700)
    receipts = out / 'receipts'
    (receipts / 'raw').mkdir(parents=True)
    cargo_home = out / 'cargo-home'
    cargo_home.mkdir()
    mapping = {'<BUILD>': str(out), '<TOOLCHAIN>': str(toolchain), '<SOURCE>': str(SOURCE), '<PACKET>': str(PACKET)}
    write_json(private_map, {'logical_to_private': mapping, 'canonical_build': str(out)})

    def logical(value):
        text = str(value)
        for name, physical in sorted(mapping.items(), key=lambda item: -len(item[1])):
            text = text.replace(physical, name)
        return text

    env_base = {'PATH': str(toolchain / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
                'CARGO_HOME': str(cargo_home), 'RUSTC': str(toolchain / 'bin/rustc'),
                'RUSTDOC': str(toolchain / 'bin/rustdoc'), 'CARGO_NET_OFFLINE': 'true',
                'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never', 'LANG': 'C',
                'LC_ALL': 'C', 'TZ': 'UTC', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env_base['HOME'] = os.environ['HOME']  # Preserve; never repurpose or inspect user credentials/config.
    config_checks = set()

    def audit_ancestors(directory):
        directory = directory.resolve()
        for ancestor in [directory, *directory.parents]:
            for name in ('config', 'config.toml'):
                candidate = ancestor / '.cargo' / name
                require(not candidate.exists(), 'unexpected canonical ancestor Cargo configuration')
                config_checks.add(logical(candidate))

    audit_ancestors(out)
    commands = []

    def retain(raw):
        digest = sha(raw)
        relative = 'raw/' + digest + '.gz'
        path = receipts / relative
        if not path.exists():
            path.write_bytes(gzip.compress(raw, mtime=0))
        return {'bytes': len(raw), 'sha256': digest, 'gzip_ref': relative}

    def run(label, argv, cwd=None, env=None, stdin=None, allowed=(0,)):
        used_env = env or env_base
        started = time.monotonic()
        process = subprocess.run([str(x) for x in argv], cwd=cwd or out, env=used_env,
                                 input=stdin, capture_output=True, timeout=180)
        # Preserve raw streams; reject rather than silently redact private home paths.
        for raw in (process.stdout, process.stderr):
            if 'HOME' in used_env:
                require(used_env['HOME'].encode() not in raw, 'private home path in raw stream: ' + label)
        commands.append({'label': label, 'argv': [logical(x) for x in argv], 'cwd': logical(cwd or out),
                         'exit_code': process.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
                         'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                         'stdout': retain(process.stdout), 'stderr': retain(process.stderr)})
        write_json(receipts / 'commands.json', commands)
        require(process.returncode in allowed, 'command failed: ' + label)
        return process.stdout

    for tool, flag in [('cargo', '--version'), ('rustc', '-vV'), ('rustdoc', '--version'),
                       ('rustfmt', '--version'), ('clippy-driver', '--version')]:
        run(tool + '-version', [toolchain / 'bin' / tool, flag])
    run('clang-version', ['/usr/bin/clang', '--version'])
    sdk = run('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    env_base['SDKROOT'] = sdk
    run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])
    external_tools = {}
    for tool in ('clang', 'ld'):
        path = Path(run('resolved-' + tool, ['/usr/bin/xcrun', '--find', tool]).decode().strip())
        external_tools[str(path)] = identity(path)
    for path in ['/usr/bin/clang', '/usr/bin/xcrun', '/usr/bin/ld', '/usr/bin/ar', sys.executable]:
        external_tools[logical(path)] = identity(Path(path))
    sdk_pins = {name: identity(Path(sdk) / name) for name in ('SDKSettings.json', 'usr/lib/libSystem.tbd')}
    corpus = json.loads((PACKET / 'pre-rust/corpus/corpus.json').read_text())
    input_bytes = gzip.decompress((PACKET / 'pre-rust/corpus/cases.tsv.gz').read_bytes())
    expected_bytes = gzip.decompress((PACKET / 'pre-rust/corpus/expected.tsv.gz').read_bytes())
    for name, raw in [('cases.tsv.gz', input_bytes), ('expected.tsv.gz', expected_bytes)]:
        require(sha(raw) == corpus['identities'][name]['raw_sha256'], 'corpus raw identity')
    controls = comparator_controls(expected_bytes)
    compile_environments = {}
    snapshots = {}

    def build(label, profiles, test=False, altered=None):
        phase = (out / label).resolve()
        phase.mkdir()
        component = phase / 'component'
        shutil.copytree(SOURCE, component)
        if altered is not None:
            (component / 'src/lib.rs').write_text(altered)
        client_source = phase / 'driver.rs'
        shutil.copyfile(HERE / 'driver.rs', client_source)
        before = inventory(component)
        expected_copy = dict(freeze['source'])
        if altered is not None:
            expected_copy['src/lib.rs'] = {'bytes': len(altered.encode()), 'sha256': sha(altered.encode())}
        require(before == expected_copy, 'copied source differs from admitted freeze/mutation')
        require(identity(client_source) == freeze['harness']['driver.rs'], 'copied input driver differs')
        audit_ancestors(component)
        # Both clean roots have identical relative layout. Only canonical paths
        # reach remapping/config audits, including macOS /tmp -> /private/tmp.
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix=' + str(phase) + '=/funding-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/funding-toolchain']
        env = dict(env_base, CARGO_TARGET_DIR=str(phase / 'target'), CARGO_ENCODED_RUSTFLAGS='\x1f'.join(flags))
        compile_environments[label] = {k: ('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if k == 'HOME' else logical(v))
                                       for k, v in env.items()}
        write_json(receipts / 'compile-environments.json', compile_environments)
        if altered is None:
            metadata = json.loads(run(label + '-metadata', [toolchain / 'bin/cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], component, env))
            require(len(metadata['packages']) == len(metadata['workspace_members']) == 1, 'one-package graph')
            package = metadata['packages'][0]
            require(package['dependencies'] == [] and package['source'] is None and
                    sorted((target['name'], target['kind']) for target in package['targets']) ==
                    [('node94_funding_record_storage', ['lib']), ('returned_records', ['test'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/returned_records.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libnode94_funding_record_storage.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'funding_input_client', client_source, '--extern',
                'node94_funding_record_storage=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            result = compare(output, expected_bytes)
            require(result['actual_rows'] == corpus['cases'], 'driver output count')
            results[profile] = {'comparison': result, 'rlib': identity(rlib), 'driver': identity(client),
                                'canonical_build_prefix_absent_in_rlib': str(phase).encode() not in rlib.read_bytes(),
                                'canonical_build_prefix_absent_in_driver': str(phase).encode() not in client.read_bytes()}
        if test:
            run(label + '-clippy', [toolchain / 'bin/cargo', 'clippy', '--offline', '--locked', '--all-targets', '--', '-D', 'warnings'], component, env)
        require(inventory(component) == before, 'copied component changed during build')
        snapshots[label] = before
        return results

    baseline = build('clean-one', ('debug', 'release'), test=True)
    require(all(row['comparison']['equal'] for row in baseline.values()), 'production corpus mismatch')
    rebuild = build('clean-two', ('debug', 'release'))
    require(all(row['comparison']['equal'] for row in rebuild.values()), 'clean rebuild corpus mismatch')
    own_byte_comparisons = {profile: {
        'rlib_raw_equal': baseline[profile]['rlib'] == rebuild[profile]['rlib'],
        'driver_raw_equal': baseline[profile]['driver'] == rebuild[profile]['driver'],
        'normalization': None, 'masks': []} for profile in ('debug', 'release')}
    mutation_results = []
    for name, changed, details in variations:
        observation = build('mutant-' + name, ('release',), altered=changed)['release']
        require(not observation['comparison']['equal'] and observation['comparison']['different_rows'] > 0,
                'compiled mutant not distinguished: ' + name)
        mutation_results.append({'definition': details, 'observation': observation})
    tools_after = {directory + '/' + name: value for directory in ['bin', 'lib']
                   for name, value in inventory(toolchain / directory).items()}
    require(tools_after == tools_before, 'toolchain changed during build')
    for path, expected in external_tools.items():
        actual = path.replace('<TOOLCHAIN>', str(toolchain)).replace('<BUILD>', str(out))
        require(identity(Path(actual)) == expected, 'external tool changed')
    for name, expected in sdk_pins.items():
        require(identity(Path(sdk) / name) == expected, 'selected SDK input changed')
    admit_sources(args.source_freeze_sha)
    write_json(receipts / 'source-copies.json', snapshots)
    write_json(receipts / 'build-audit.json', {
        'source_freeze_sha256': args.source_freeze_sha, 'source': freeze['source'],
        'manifest': manifest, 'lock': lock, 'canonical_ancestor_config_absent': sorted(config_checks),
        'fresh_CARGO_HOME': True, 'inherited_environment_except_HOME': False,
        'toolchain_payload_pins_sha256': identity(HERE / 'TOOLCHAIN-PINS.json')['sha256'],
        'toolchain_payload_unchanged': True, 'external_tools': external_tools, 'SDKROOT': sdk,
        'sdk_inputs': sdk_pins, 'python_version': sys.version,
        'limit': 'Toolchain bin/lib and selected linker/SDK bytes are pinned; host OS/dyld and all SDK files are not a hermetic or captured-target toolchain claim.'})
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['cases'],
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_release_mutants': mutation_results, 'comparator_controls': controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_static_and_pre_source_phases_unchanged': True,
              'scope': 'Host-compiled abstract value reconstruction only; no captured execution, native ABI/layout/byte equivalence, allocation/refusal/rollback or scheduler completeness claim.'}
    write_json(receipts / 'results.json', result)
    print(json.dumps({'receipt_directory': logical(receipts), 'baseline_rows_per_profile': corpus['cases'],
                      'baseline_mismatches': {p: r['comparison']['different_rows'] for p, r in baseline.items()},
                      'clean_rebuild_byte_comparisons': own_byte_comparisons,
                      'compiled_mutants': len(mutation_results), 'commands': len(commands)}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
