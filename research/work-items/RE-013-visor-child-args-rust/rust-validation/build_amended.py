#!/usr/bin/env python3
"""Build only the authored child-argument value component, offline and locked.

MIT orchestration adapted from RE-007-funding-sample-storage-94/rust-validation/
build.py (SHA256 a5fa4c29cc917397b23da9921362687fac5c1067caf1240781fad33fca02c7a0).
No funding semantics, expectations or runtime dependency are reused.
"""
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
SOURCE = ROOT / 'src/visor-child-args'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/value_contract.rs']
PRE_FREEZE = '5878f3e3eb4577bf9bd4fc017456c2a1c15a6dea8b2a6c9620b88e47064f4091'
PRE_MANIFEST = '975c52b80cbdd8e685d595634044054f5519d5ddf719f3b7cca2b39151aac46c'


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
    require(identity(PACKET / 'PRE-RUST-FREEZE.json')['sha256'] == PRE_FREEZE, 'pre-code freeze identity')
    require(identity(PACKET / 'MANIFEST.sha256')['sha256'] == PRE_MANIFEST, 'pre-code manifest identity')
    require(check_manifest(PACKET) == 23, 'original pre-code entries')
    require(identity(HERE / 'SOURCE-FREEZE-2.json')['sha256'] == expected_source_freeze, 'source freeze identity')
    freeze = json.loads((HERE / 'SOURCE-FREEZE-2.json').read_text())
    require(not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source symlink')
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        require(not (HERE / name).is_symlink(), 'harness symlink')
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'visor-child-args', 'version': '0.1.0'}], 'actual dependency-free lock')
    return freeze, manifest, lock


def compare(actual, expected):
    left, right = actual.splitlines(keepends=True), expected.splitlines(keepends=True)
    differences = [i for i in range(max(len(left), len(right)))
                   if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    return {'equal': actual == expected, 'actual_rows': len(left), 'expected_rows': len(right),
            'different_rows': len(differences), 'first_different_rows': differences[:12],
            'actual_sha256': sha(actual), 'expected_sha256': sha(expected)}


def comparator_controls(expected, lengths):
    rows = expected.splitlines(keepends=True)
    def replace(index, value):
        changed = rows.copy()
        changed[index] = value
        return b''.join(changed)
    invalid = next(i for i, row in enumerate(rows) if b'\tINVALID\t' in row)
    nonempty = next(i for i, row in enumerate(rows) if row.endswith(b'\tOK\t00\n'))
    values = {
        'missing-row': b''.join(rows[:-1]), 'extra-row': expected + rows[0],
        'reordered': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]),
        'changed-status': replace(invalid, rows[invalid].replace(b'INVALID', b'OK')),
        'changed-byte': replace(nonempty, rows[nonempty].replace(b'\t00\n', b'\t01\n')),
        'changed-index': replace(invalid, rows[invalid].replace(b'\t0\n', b'\t1\n')),
        'missing-LF': expected[:-1], 'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b'',
    }
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    result['length-domain'] = compare(lengths.replace(b'DOMAIN', b'OK', 1), lengths)
    result['length-value'] = compare(lengths.replace(b'\t24\n', b'\t25\n', 1), lengths)
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    validator = """        let value = std::str::from_utf8(bytes).map_err(|_| CollectError::InvalidUtf8 {
            argument_index: index,
        })?;"""
    definitions = [
        ('continue-past-none', [('            break;', '            continue;')]),
        ('none-becomes-empty', [('            break;', '            output.push(String::new());\n            continue;')]),
        ('empty-stops', [(validator, '        if bytes.is_empty() { break; }\n' + validator)]),
        ('drop-empty', [(validator, '        if bytes.is_empty() { continue; }\n' + validator)]),
        ('reject-nul', [(validator, '        if bytes.contains(&0) { return Err(CollectError::InvalidUtf8 { argument_index: index }); }\n' + validator)]),
        ('lossy-invalid', [(validator, '        let _ = index;\n        let repaired = String::from_utf8_lossy(bytes);\n        let value = repaired.as_ref();')]),
        ('trim-values', [('owned.push_str(value);', 'owned.push_str(value.trim());')]),
        ('reverse-values', [('    Ok(output)', '    output.reverse();\n    Ok(output)')]),
        ('drop-duplicates', [('output.push(owned);', 'if !output.contains(&owned) { output.push(owned); }')]),
        ('previous-error-index', [('argument_index: index,', 'argument_index: index.saturating_sub(1),')]),
        ('truncate-at-nul', [('owned.push_str(value);', "owned.push_str(value.split('\\0').next().unwrap());")]),
        ('reject-domain-endpoint', [('bytes <= i64::MAX as u64', 'bytes < (i64::MAX as u64 - 7)')]),
        ('wrap-descriptor-product', [('count.checked_mul(24)', 'Some(count.wrapping_mul(24))')]),
        ('wrong-descriptor-stride', [('count.checked_mul(24)', 'count.checked_mul(16)')]),
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
    lexical_out = args.out.absolute()
    require(not lexical_out.is_symlink(), "build output symlink")
    out = lexical_out.resolve()
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
    tool_links = {str(p.relative_to(toolchain)): os.readlink(p) for d in ['bin', 'lib'] for p in (toolchain / d).rglob('*') if p.is_symlink()}
    require(tool_links == pins['symlinks'], 'toolchain symlinks differ')
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
                'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env_base['HOME'] = os.environ['HOME']  # Preserve; never repurpose or inspect user credentials/config.
    config_checks = set()

    def audit_ancestors(directory):
        for start in {directory.absolute(), directory.resolve()}:
            for ancestor in [start, *start.parents]:
                for name in ('config', 'config.toml'):
                    candidate = ancestor / '.cargo' / name
                    require(not candidate.exists() and not candidate.is_symlink(),
                            'unexpected lexical/canonical ancestor Cargo configuration')
                    config_checks.add(logical(candidate))

    audit_ancestors(lexical_out)
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
    run('post-source-static-replay', [sys.executable, HERE / 'verify_amended.py', '--out', out / 'static-replay',
        '--source-freeze-sha', args.source_freeze_sha])
    corpus = json.loads((PACKET / 'frozen/corpus.json').read_text())
    streams = {}
    for entry in corpus['streams']:
        stored = (PACKET / 'frozen' / entry['path']).read_bytes()
        raw = gzip.decompress(stored)
        require(sha(stored) == entry['sha256'] and sha(raw) == entry['raw_sha256'], 'corpus identity')
        streams[entry['path']] = raw
    input_bytes, expected_bytes = streams['inputs.tsv.gz'], streams['expected.tsv.gz']
    length_inputs, length_expected = streams['length-inputs.tsv.gz'], streams['length-expected.tsv.gz']
    controls = comparator_controls(expected_bytes, length_expected)
    compile_environments = {}
    snapshots = {}

    def build(label, profiles, test=False, altered=None):
        phase = (out / label).resolve()
        phase.mkdir()
        component = phase / 'component'
        shutil.copytree(SOURCE, component)
        if altered is not None:
            (component / 'src/lib.rs').write_text(altered)
        client_source = phase / 'input_client.rs'
        shutil.copyfile(HERE / 'input_client.rs', client_source)
        require(not any(p.is_symlink() for p in component.rglob('*')), 'copied source symlink')
        before = inventory(component)
        expected_copy = dict(freeze['source'])
        if altered is not None:
            expected_copy['src/lib.rs'] = {'bytes': len(altered.encode()), 'sha256': sha(altered.encode())}
        require(before == expected_copy, 'copied source differs from admitted freeze/mutation')
        require(identity(client_source) == freeze['harness']['input_client.rs'], 'copied input driver differs')
        audit_ancestors(component)
        # Both clean roots have identical relative layout. Only canonical paths
        # reach remapping/config audits, including macOS /tmp -> /private/tmp.
        flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                 '--remap-path-prefix=' + str(phase) + '=/child-args-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/child-args-toolchain']
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
                    [('value_contract', ['test']), ('visor_child_args', ['lib'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/value_contract.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libvisor_child_args.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'child_args_input_client', client_source, '--extern',
                'visor_child_args=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            length_output = run(label + '-' + profile + '-lengths', [client, 'lengths'], component, env, length_inputs)
            length_result = compare(length_output, length_expected)
            require(length_result['actual_rows'] == corpus['length_cases'], 'length output count')
            result = compare(output, expected_bytes)
            require(result['actual_rows'] == corpus['cases'], 'driver output count')
            results[profile] = {'comparison': result, 'length_comparison': length_result, 'rlib': identity(rlib), 'driver': identity(client),
                                'canonical_build_prefix_absent_in_rlib': str(phase).encode() not in rlib.read_bytes(),
                                'canonical_build_prefix_absent_in_driver': str(phase).encode() not in client.read_bytes()}
        if test:
            run(label + '-clippy', [toolchain / 'bin/cargo', 'clippy', '--offline', '--locked', '--all-targets', '--', '-D', 'warnings'], component, env)
        require(inventory(component) == before, 'copied component changed during build')
        snapshots[label] = before
        return results

    baseline = build('clean-one', ('debug', 'release'), test=True)
    require(all(row['comparison']['equal'] and row['length_comparison']['equal'] for row in baseline.values()), 'production corpus mismatch')
    rebuild = build('clean-two', ('debug', 'release'))
    require(all(row['comparison']['equal'] and row['length_comparison']['equal'] for row in rebuild.values()), 'clean rebuild corpus mismatch')
    own_byte_comparisons = {profile: {
        'rlib_raw_equal': baseline[profile]['rlib'] == rebuild[profile]['rlib'],
        'driver_raw_equal': baseline[profile]['driver'] == rebuild[profile]['driver'],
        'normalization': None, 'masks': []} for profile in ('debug', 'release')}
    mutation_results = []
    for name, changed, details in variations:
        observation = build('mutant-' + name, ('debug', 'release'), altered=changed)
        require(all(not (p['comparison']['equal'] and p['length_comparison']['equal'])
                    for p in observation.values()), 'compiled mutant not distinguished: ' + name)
        mutation_results.append({'definition': details, 'profiles': observation})
        print('compiled mutant detected: ' + name, flush=True)
    tools_after = {directory + '/' + name: value for directory in ['bin', 'lib']
                   for name, value in inventory(toolchain / directory).items()}
    require(tools_after == tools_before, 'toolchain changed during build')
    require(tool_links == {str(p.relative_to(toolchain)): os.readlink(p) for d in ['bin', 'lib'] for p in (toolchain / d).rglob('*') if p.is_symlink()}, 'toolchain symlinks changed')
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
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['cases'], 'length_cases': corpus['length_cases'], 'handwritten_tests_per_profile': 8,
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_two_profile_mutants': mutation_results, 'comparator_controls': controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_pre_code_phase_unchanged': True,
              'scope': 'Host-compiled owned argument values only; no captured execution, native ABI/layout/byte equivalence, native allocation/error behavior, CLI policy or post-cleanup/spawn claim.'}
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
