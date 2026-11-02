#!/usr/bin/env python3
"""Build only the authored seeded key-value component, offline and locked.

MIT orchestration adapted from RE-013-visor-child-args-rust/rust-validation/
build_amended.py (SHA256 506d32bf277451a45a5e8157ca6b4331476b056960702b7aa0831ae1a0c1c567).
No child-argument semantics, oracle or runtime dependency is reused.
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
SOURCE = ROOT / 'src/visor-key-hash'
SOURCE_FILES = ['Cargo.lock', 'Cargo.toml', 'README.md', 'src/lib.rs', 'tests/value_contract.rs']
PRE_FREEZE = '7983ed45803670b073a8a1c821d0eb4f8f9b96805aa24f8c9303f2e2f0893c8a'
PRE_MANIFEST = '043511976da9acc2846e01a924b761db83a9af716776070ff8251e727b8701ff'


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
    require(check_manifest(PACKET) == 24, 'original pre-code entries')
    require(identity(HERE / 'SOURCE-FREEZE.json')['sha256'] == expected_source_freeze, 'source freeze identity')
    freeze = json.loads((HERE / 'SOURCE-FREEZE.json').read_text())
    require(not SOURCE.is_symlink() and not any(p.is_symlink() for p in SOURCE.rglob('*')), 'source symlink')
    require(sorted(inventory(SOURCE)) == SOURCE_FILES, 'unexpected source file/hook')
    require(inventory(SOURCE) == freeze['source'], 'actual source differs from freeze')
    for name, expected in freeze['harness'].items():
        require(not (HERE / name).is_symlink(), 'harness symlink')
        require(identity(HERE / name) == expected, 'harness differs from freeze: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(manifest['dependencies'] == {} and 'workspace' not in manifest and
            'build' not in manifest['package'] and not (SOURCE / 'build.rs').exists(), 'dependency/hook admission')
    require(lock['package'] == [{'name': 'visor-key-hash', 'version': '0.1.0'}], 'actual dependency-free lock')
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
    def replace(index, value):
        changed = rows.copy()
        changed[index] = value
        return b''.join(changed)
    values = {
        'missing-row': b''.join(rows[:-1]), 'extra-row': expected + rows[0],
        'reordered': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]),
        'changed-id': replace(0, rows[0].replace(b'c000000', b'c999999')),
        'changed-value': replace(0, rows[0][:8] + b'ffffffffffffffff\n'),
        'truncated-u32': replace(0, rows[0][:8] + rows[0][-9:]),
        'missing-LF': expected[:-1], 'CRLF': expected.replace(b'\n', b'\r\n'), 'empty': b'',
    }
    require(compare(expected, expected)['equal'], 'positive comparator')
    result = {name: compare(value, expected) for name, value in values.items()}
    require(all(not row['equal'] for row in result.values()), 'missed comparator corruption')
    return result


def mutants(original):
    seeds = '    let seeds = [seed[0], seed[1]];'
    length = '    let length_byte = (input.len().wrapping_add(1) as u64) & 0xff;'
    tail = """    tail |= 0xff_u64 << (8 * remainder.len());
    if remainder.len() == 7 {
        compress(&mut v, tail);
        tail = 0;
    }
"""
    double = """    tail |= 0xff_u64 << (8 * remainder.len());
    if remainder.len() < 7 {
        tail |= 0xff_u64 << (8 * (remainder.len() + 1));
    }
    if remainder.len() >= 6 {
        compress(&mut v, tail);
        tail = if remainder.len() == 7 { 0xff } else { 0 };
    }
"""
    middle = original[original.index('    let mut chunks'):original.index(length)]
    prefix = """    let mut tail = 0;
    let mut count = 0;
    for byte in core::iter::once(0xff).chain(input.iter().copied()) {
        tail |= u64::from(byte) << (8 * count);
        count += 1;
        if count == 8 {
            compress(&mut v, tail);
            count = 0;
            tail = 0;
        }
    }
"""
    definitions = [
        ('zero-seeds', [(seeds, '    let seeds = [seed[0] & 0, seed[1] & 0];')]),
        ('swap-seeds', [(seeds, '    let seeds = [seed[1], seed[0]];')]),
        ('duplicate-first-seed', [(seeds, '    let seeds = [seed[0], seed[0]];')]),
        ('wrong-seed-constant', [('0x736f_6d65_7073_6575', '0x736f_6d65_7073_6574')]),
        ('omit-ff', [('tail |= 0xff_u64 <<', 'tail |= 0_u64 <<')]),
        ('double-ff', [(tail, double), ('.wrapping_add(1)', '.wrapping_add(2)')]),
        ('prefix-ff', [(middle, prefix)]),
        ('nul-terminates', [(seeds, '    let input = &input[..input.iter().position(|b| *b == 0).unwrap_or(input.len())];\n' + seeds)]),
        ('big-endian-words', [('u64::from_le_bytes(bytes)', 'u64::from_be_bytes(bytes)')]),
        ('omit-length', [(length, '    let length_byte = (input.len().wrapping_add(1) as u64) & 0;')]),
        ('exclude-ff-length', [('.wrapping_add(1)', '.wrapping_add(0)')]),
        ('wrong-length-byte', [(length, '    let length_byte = ((input.len().wrapping_add(1) as u64) >> 8) & 0xff;')]),
        ('no-q7-compression', [('if remainder.len() == 7 {', 'if remainder.len() == 8 {')]),
        ('two-final-rounds', [('for _ in 0..3 {', 'for _ in 0..2 {')]),
        ('four-final-rounds', [('for _ in 0..3 {', 'for _ in 0..4 {')]),
        ('wrong-rotation', [('rotate_left(13)', 'rotate_left(12)')]),
        ('omit-pre-message-xor', [('    v[3] ^= word;', '    v[3] ^= word & 0;')]),
        ('omit-post-message-xor', [('    v[0] ^= word;', '    v[0] ^= word & 0;')]),
        ('truncate-result-u32', [('    v[0] ^ v[1] ^ v[2] ^ v[3]', '    (v[0] ^ v[1] ^ v[2] ^ v[3]) & 0xffff_ffff')]),
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
    run('post-source-static-replay', [sys.executable, PACKET / 'verify.py', '--out', out / 'static-replay'])
    corpus = json.loads((PACKET / 'frozen/corpus.json').read_text())
    streams = {}
    for entry in corpus['streams']:
        stored = (PACKET / 'frozen' / entry['path']).read_bytes()
        raw = gzip.decompress(stored)
        require(sha(stored) == entry['sha256'] and sha(raw) == entry['raw_sha256'], 'corpus identity')
        streams[entry['path']] = raw
    input_bytes, expected_bytes = streams['inputs.tsv.gz'], streams['expected.tsv.gz']
    controls = comparator_controls(expected_bytes)
    driver_controls = []
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
                 '--remap-path-prefix=' + str(phase) + '=/key-hash-build',
                 '--remap-path-prefix=' + str(toolchain) + '=/key-hash-toolchain']
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
                    [('value_contract', ['test']), ('visor_key_hash', ['lib'])], 'exact dependency-free targets')
            run(label + '-rustfmt-check', [toolchain / 'bin/rustfmt', '--edition', '2024', '--check',
                component / 'src/lib.rs', component / 'tests/value_contract.rs', client_source], component, env)
        results = {}
        for profile in profiles:
            release = ['--release'] if profile == 'release' else []
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *release], component, env)
            if test:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *release], component, env)
            rlib = phase / 'target' / profile / 'libvisor_key_hash.rlib'
            client = phase / ('client-' + profile)
            run(label + '-' + profile + '-link-driver', [toolchain / 'bin/rustc', '--edition=2024',
                '--crate-name', 'key_hash_input_client', client_source, '--extern',
                'visor_key_hash=' + str(rlib), '-L', 'dependency=' + str(phase / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + ('3' if profile == 'release' else '0'), '-C',
                'debuginfo=' + ('0' if profile == 'release' else '2'), *flags, '-o', client], component, env)
            output = run(label + '-' + profile + '-values', [client], component, env, input_bytes)
            if label == 'clean-one' and profile == 'debug':
                first = input_bytes.splitlines(keepends=True)[0]
                malformed = {
                    'empty-stream': b'', 'missing-LF': first[:-1],
                    'wrong-ID': first.replace(b'c000000', b'c000001'),
                    'short-seed': first.replace(b'0000000000000000', b'0', 1),
                    'uppercase-seed': first.replace(b'0000000000000000', b'AAAAAAAAAAAAAAAA', 1),
                    'nonhex-seed': first.replace(b'0000000000000000', b'gggggggggggggggg', 1),
                    'odd-byte-hex': first.replace(b'\t-\n', b'\t0\n'),
                    'empty-byte-field': first.replace(b'\t-\n', b'\t\n'),
                    'uppercase-byte-hex': first.replace(b'\t-\n', b'\tFF\n'),
                    'extra-field': first[:-1] + b'\textra\n',
                    'CRLF': first.replace(b'\n', b'\r\n'),
                }
                for control, bad_input in malformed.items():
                    raw = run('input-control-' + control, [client], component, env, bad_input, allowed=(2,))
                    require(not raw, 'malformed first row produced value output')
                    driver_controls.append({'name': control, 'exit_code': 2, 'input_sha256': sha(bad_input),
                                            'output_bytes': len(raw)})
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
        observation = build('mutant-' + name, ('debug', 'release'), altered=changed)
        require(all(not p['comparison']['equal']
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
    result = {'source_freeze_sha256': args.source_freeze_sha, 'corpus_cases': corpus['cases'], 'seed_pairs': corpus['distinct_seeds'], 'handwritten_tests_per_profile': 8,
              'baseline': baseline, 'independent_clean_directory_rebuild': rebuild,
              'own_build_byte_comparisons': own_byte_comparisons,
              'compiled_two_profile_mutants': mutation_results, 'comparator_controls': controls, 'input_driver_controls': driver_controls,
              'commands': len(commands), 'raw_stream_policy': 'Every stdout/stderr byte retained, content-addressed gzip; no output normalization or expected-file substitution.',
              'actual_source_unchanged': True, 'copied_source_unchanged': True,
              'original_pre_code_phase_unchanged': True,
              'scope': 'Host-compiled seeded key+FF values only; no captured execution, native ABI/layout/byte equivalence, generic streaming, table membership, cryptographic or component completion claim.'}
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
