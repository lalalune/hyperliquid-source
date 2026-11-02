#!/usr/bin/env python3
"""Build only the authored component/client, offline; never load captured code.

The parent Python comparator alone reads pre-Rust expectations. The linked client
receives input TSV on stdin only. Raw streams are content-addressed and deduped;
identical baseline output references the already retained frozen expected stream.
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

PACKET = Path(__file__).resolve().parent.parent
SOURCE = PACKET.parents[2] / 'src/visor-move-request'
TOOL_PINS = {
    'cargo': '532141271ce821135f63822c21fcd76c7972cbf69c19bc35e6ca8b00fcd5c40e',
    'rustc': 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6',
    'rustdoc': '63f095b26810d1f78a683edd1e10d8bbaea00f044e27cc189416f10f8080f13a',
}
SOURCE_FILES = ['Cargo.toml', 'Cargo.lock', 'README.md', 'src/lib.rs', 'tests/value_contract.rs']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': sha(data)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')


def inventory(root):
    return {str(p.relative_to(root)): identity(p) for p in sorted(root.rglob('*')) if p.is_file()}


def load_bound_inputs():
    freeze = json.loads((PACKET / 'pre-rust/PRE-RUST-FREEZE.json').read_text())
    require(sha((PACKET / 'pre-rust/PRE-RUST-FREEZE.json').read_bytes()) ==
            'b665594b3cd4a0fafef3e13dc854fe32e110291aa9431c039623034e07391c3d', 'pre-Rust freeze identity')
    for name, item in freeze['files'].items():
        require(identity(PACKET / 'pre-rust' / name) == item, 'changed pre-Rust file: ' + name)
    for name, key in [('AUTHOR-FREEZE.json', 'original_author_freeze_sha256'),
                      ('MANIFEST.json', 'original_manifest_sha256')]:
        require(sha((PACKET / name).read_bytes()) == freeze[key], 'changed original static freeze')
    source_freeze = json.loads((PACKET / 'rust-validation/SOURCE-FREEZE.json').read_text())
    for name, item in source_freeze['source'].items():
        require(identity(SOURCE / name) == item, 'changed component source: ' + name)
    for name, item in source_freeze['harness'].items():
        require(identity(PACKET / 'rust-validation' / name) == item, 'changed harness: ' + name)
    require(sorted(inventory(SOURCE)) == sorted(SOURCE_FILES), 'unexpected component file/hook')
    return source_freeze


def compare(actual, expected):
    # Exact bytes, no filtering, sorting, whitespace or status normalization.
    left, right = actual.splitlines(keepends=True), expected.splitlines(keepends=True)
    positions = [i for i in range(max(len(left), len(right)))
                 if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)]
    return {'equal': actual == expected, 'actual_rows': len(left), 'expected_rows': len(right),
            'different_rows': len(positions), 'first_different_rows': positions[:8],
            'actual_sha256': sha(actual), 'expected_sha256': sha(expected)}


def comparator_controls(expected):
    rows = expected.splitlines(keepends=True)
    good = next(i for i, row in enumerate(rows) if b'\tok\t1\t' in row)
    nul = next(i for i, row in enumerate(rows) if row.endswith(b'\tnul\n'))
    def replace(index, row):
        copy = rows.copy()
        copy[index] = row
        return b''.join(copy)
    changes = {
        'missing-final-row': b''.join(rows[:-1]),
        'extra-row': expected + rows[0],
        'swap-first-two': b''.join([rows[1], rows[0], *rows[2:]]),
        'duplicate-id': replace(1, rows[0]),
        'option-zero': replace(good, rows[good].replace(b'\tok\t1\t', b'\tok\t0\t')),
        'wrong-status': replace(nul, rows[nul].replace(b'\tnul\n', b'\tdomain\n')),
        'wrong-command-byte': replace(good, rows[good].replace(b'6d76', b'6d77', 1)),
        'missing-final-newline': expected[:-1],
        'empty-output': b'',
        'crlf': expected.replace(b'\n', b'\r\n'),
    }
    require(compare(expected, expected)['equal'], 'positive comparator control')
    result = {name: compare(value, expected) for name, value in changes.items()}
    require(all(not item['equal'] for item in result.values()), 'missed comparator corruption')
    return result


def mutants(source):
    definitions = [
        ('trim-retained-input', '[source, destination]', '[source.trim(), destination.trim()]'),
        ('retain-blank', 'if input.chars().all(is_target_whitespace)', 'if false && input.chars().all(is_target_whitespace)'),
        ('accept-nul', 'if source.as_bytes().contains(&0) || destination.as_bytes().contains(&0)',
         'if false && (source.as_bytes().contains(&0) || destination.as_bytes().contains(&0))'),
        ('leading-caret-mode', 'if leading_caret { 2 } else { 7 }', 'if leading_caret { 7 } else { 7 }'),
        ('swap-quote-priority', '} else if mask & 2 != 0 {', '} else if mask & 4 != 0 {'),
        ('consume-conflict', 'if candidate == 0 {\n                break;',
         'if candidate == 0 {\n                length += 1;\n                break;'),
        ('omit-double-escape', 'if matches!(byte, b\'"\' | b\'$\' | b\'\\\\\' | b\'`\')',
         'if false && matches!(byte, b\'"\' | b\'$\' | b\'\\\\\' | b\'`\')'),
        ('reverse-operands', '[source, destination]', '[destination, source]'),
        ('separator-colon', "command.push(b' ');", "command.push(b':');"),
        ('option-zero', 'pub fn option_byte(&self) -> u8 {\n        1', 'pub fn option_byte(&self) -> u8 {\n        0'),
        ('whitespace-85-to-86', '0x0d | 0x20 | 0x85 |', '0x0d | 0x20 | 0x86 |'),
        ('raw-plus-to-percent', "b'+' | b'-'", "b'%' | b'-'"),
        ('reject-equal-length-bound', 'if sum > MAX_COMBINED_INPUT_BYTES', 'if sum >= MAX_COMBINED_INPUT_BYTES'),
        ('wrap-length-addition', 'source_len\n        .checked_add(destination_len)\n        .ok_or(LengthOutsideProofDomain)?',
         'source_len.wrapping_add(destination_len)'),
    ]
    result = []
    for name, old, new in definitions:
        require(source.count(old) == 1, 'mutation coordinate: ' + name)
        changed = source.replace(old, new, 1)
        result.append((name, changed, {'name': name, 'old': old, 'new': new, 'source_sha256': sha(changed.encode())}))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='fresh owned private build directory under /tmp')
    parser.add_argument('--private-map', type=Path, required=True, help='mapping outside the public packet')
    args = parser.parse_args()
    toolchain = args.toolchain.resolve()
    out = args.out.absolute()
    require(not out.exists(), 'fresh output required')
    require(str(out).startswith('/tmp/'), 'build output must be a fresh /tmp directory')
    require(not args.private_map.exists(), 'fresh private mapping required')
    source_freeze = load_bound_inputs()
    original_source = (SOURCE / 'src/lib.rs').read_text()
    variations = mutants(original_source)  # Validate all mutation coordinates before any build.
    for name, pin in TOOL_PINS.items():
        require(identity(toolchain / 'bin' / name)['sha256'] == pin, 'tool identity: ' + name)
    manifest = tomllib.loads((SOURCE / 'Cargo.toml').read_text())
    lock = tomllib.loads((SOURCE / 'Cargo.lock').read_text())
    require(manifest['dependencies'] == {} and 'build' not in manifest['package'] and
            'workspace' not in manifest and not (SOURCE / 'build.rs').exists(), 'source dependency/hook audit')
    require(lock['package'] == [{'name': 'visor-move-request', 'version': '0.1.0'}], 'actual dependency-free lock')
    out.mkdir()
    receipts = out / 'receipts'
    receipts.mkdir()
    (receipts / 'raw').mkdir()
    cargo_home = out / 'cargo-home'
    cargo_home.mkdir()
    mappings = {'<BUILD>': str(out), '<TOOLCHAIN>': str(toolchain), '<SOURCE>': str(SOURCE), '<PACKET>': str(PACKET)}
    write_json(args.private_map, {'logical_to_private': mappings, 'public_path_policy': 'commands and inventories use logical prefixes; unmodified raw streams may name only the disposable /tmp build or public system paths'})
    def logical(value):
        value = str(value)
        for key, physical in sorted(mappings.items(), key=lambda p: -len(p[1])):
            value = value.replace(physical, key)
        return value
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'CARGO_HOME': str(cargo_home),
           'RUSTC': str(toolchain / 'bin/rustc'), 'RUSTDOC': str(toolchain / 'bin/rustdoc'),
           'CARGO_NET_OFFLINE': 'true', 'CARGO_INCREMENTAL': '0', 'CARGO_TERM_COLOR': 'never',
           'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1', 'DEVELOPER_DIR': '/Library/Developer/CommandLineTools'}
    if 'HOME' in os.environ:
        env['HOME'] = os.environ['HOME']  # Preserve; never repurpose or inspect home/config credentials.
    config_checks = []
    for ancestor in [Path('/'), Path('/tmp'), out]:
        for name in ['config', 'config.toml']:
            candidate = ancestor / '.cargo' / name
            require(not candidate.exists(), 'unexpected ancestor Cargo configuration')
            config_checks.append(logical(candidate))
    tools_before = {}
    for dirname in ['bin', 'lib']:
        tools_before.update({dirname + '/' + name: value for name, value in inventory(toolchain / dirname).items()})
    write_json(receipts / 'toolchain-files.json', tools_before)
    expected_refs = {}
    streams = {}
    for name in ['inputs.tsv', 'expected.tsv', 'length-inputs.tsv', 'length-expected.tsv']:
        data = gzip.decompress((PACKET / 'pre-rust/frozen' / (name + '.gz')).read_bytes())
        streams[name] = data
        expected_refs[sha(data)] = '../../pre-rust/frozen/' + name + '.gz'
    def retain(data):
        digest = sha(data)
        if digest in expected_refs:
            ref = expected_refs[digest]
        else:
            ref = 'raw/' + digest + '.gz'
            destination = receipts / ref
            if not destination.exists():
                destination.write_bytes(gzip.compress(data, mtime=0))
        return {'bytes': len(data), 'sha256': digest, 'gzip_ref': ref}
    commands = []
    def run(label, command, cwd=None, stdin=None, allowed=(0,)):
        started = time.monotonic()
        result = subprocess.run([str(x) for x in command], cwd=cwd or out, env=env, input=stdin,
                                capture_output=True, timeout=180)
        # Do not silently redact raw receipts. Reject accidental private home paths.
        for raw in [result.stdout, result.stderr]:
            if 'HOME' in env:
                require(env['HOME'].encode() not in raw, 'private home path in raw output: ' + label)
        entry = {'label': label, 'argv': [logical(x) for x in command], 'cwd': logical(cwd or out),
                 'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic() - started, 3),
                 'stdin': None if stdin is None else {'bytes': len(stdin), 'sha256': sha(stdin)},
                 'stdout': retain(result.stdout), 'stderr': retain(result.stderr)}
        commands.append(entry)
        write_json(receipts / 'commands.json', commands)
        require(result.returncode in allowed, 'command failed: ' + label)
        return result.stdout
    for tool, flag in [('cargo', '--version'), ('rustc', '-vV'), ('rustdoc', '--version')]:
        run(tool + '-version', [toolchain / 'bin' / tool, flag])
    run('clang-version', ['/usr/bin/clang', '--version'])
    sdk = run('sdk-path', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
    env['SDKROOT'] = sdk
    run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])
    external_tools = {}
    for tool in ['clang', 'ld']:
        found = Path(run('resolved-' + tool, ['/usr/bin/xcrun', '--find', tool]).decode().strip())
        external_tools[str(found)] = identity(found)
    for name in ['/usr/bin/clang', '/usr/bin/xcrun', '/usr/bin/ld', '/usr/bin/ar', sys.executable]:
        external_tools[logical(name)] = identity(Path(name))
    sdk_pins = {name: identity(Path(sdk) / name) for name in ['SDKSettings.json', 'usr/lib/libSystem.tbd']}
    env_receipt = {key: ('<ORIGINAL_HOME_UNCHANGED_NOT_RECORDED>' if key == 'HOME' else logical(value))
                   for key, value in env.items()}
    write_json(receipts / 'build-audit.json', {'source_freeze_sha256': identity(PACKET / 'rust-validation/SOURCE-FREEZE.json')['sha256'],
        'source': source_freeze, 'cargo_manifest': manifest, 'cargo_lock': lock,
        'exact_source_files': SOURCE_FILES, 'ancestor_config_absent': config_checks,
        'fresh_cargo_home': True, 'inherited_env_except_HOME': False, 'environment': env_receipt,
        'tool_pins': TOOL_PINS, 'external_tool_files': external_tools, 'SDKROOT': sdk, 'sdk_pins': sdk_pins,
        'python_version': sys.version, 'toolchain_payload_inventory': 'toolchain-files.json',
        'limits': 'Toolchain bin/lib payloads and selected linker/SDK inputs are hashed before/after. Host OS, dyld and all SDK files are not a hermetic toolchain or target compiler claim.'})
    component = out / 'component'
    shutil.copytree(SOURCE, component)
    client_source = out / 'input_client.rs'
    shutil.copyfile(PACKET / 'rust-validation/input_client.rs', client_source)
    metadata = json.loads(run('cargo-metadata', [toolchain / 'bin/cargo', 'metadata', '--offline', '--locked', '--format-version', '1'], component))
    require(len(metadata['packages']) == 1 and len(metadata['workspace_members']) == 1, 'metadata package graph')
    package = metadata['packages'][0]
    require(package['dependencies'] == [] and package['source'] is None and
            all('custom-build' not in target['kind'] and not target.get('proc_macro', False) for target in package['targets']), 'metadata hooks/deps')
    require(sorted((t['name'], t['kind']) for t in package['targets']) ==
            [('value_contract', ['test']), ('visor_move_request', ['lib'])], 'metadata exact targets')
    comparison_controls = comparator_controls(streams['expected.tsv'])
    fixed_flags = ['-Dwarnings', '-C', 'overflow-checks=on', '-C', 'linker=/usr/bin/clang',
                   '--remap-path-prefix=' + str(component) + '=/vmr-component',
                   '--remap-path-prefix=' + str(out) + '=/vmr-build',
                   '--remap-path-prefix=' + str(toolchain) + '=/vmr-toolchain']
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(fixed_flags)
    env['CARGO_TARGET_DIR'] = str(out / 'target')
    # Every actual environment difference from the initial audit is explicit.
    write_json(receipts / 'compile-environment.json', {key: logical(value) for key, value in env.items() if key != 'HOME'})
    def build_and_compare(label, tests=False):
        observations = {}
        for profile, optimization in [('debug', '0'), ('release', '3')]:
            profile_args = [] if profile == 'debug' else ['--release']
            run(label + '-' + profile + '-cargo-build', [toolchain / 'bin/cargo', 'build', '--offline', '--locked', '--lib', *profile_args], component)
            if tests:
                run(label + '-' + profile + '-cargo-test', [toolchain / 'bin/cargo', 'test', '--offline', '--locked', '--lib', '--tests', *profile_args], component)
            rlib = out / 'target' / profile / 'libvisor_move_request.rlib'
            client = out / ('client-' + profile)
            run(label + '-' + profile + '-link-input-client', [toolchain / 'bin/rustc', '--edition=2021', '--crate-name', 'vmr_input_client',
                str(client_source), '--extern', 'visor_move_request=' + str(rlib), '-L', 'dependency=' + str(out / 'target' / profile / 'deps'),
                '-C', 'opt-level=' + optimization, *fixed_flags, '-o', str(client)], component)
            values = run(label + '-' + profile + '-values', [client], stdin=streams['inputs.tsv'])
            lengths = run(label + '-' + profile + '-lengths', [client, 'lengths'], stdin=streams['length-inputs.tsv'])
            observations[profile] = {'rlib': identity(rlib), 'input_client': identity(client),
                'value_comparison': compare(values, streams['expected.tsv']),
                'length_comparison': compare(lengths, streams['length-expected.tsv'])}
        return observations
    baseline = build_and_compare('baseline', tests=True)
    require(all(x['value_comparison']['equal'] and x['length_comparison']['equal'] for x in baseline.values()), 'production finite comparison')
    first = out / 'first-target'
    (out / 'target').rename(first)
    for profile in ['debug', 'release']:
        (out / ('client-' + profile)).rename(out / ('first-client-' + profile))
    rebuild = build_and_compare('fresh-rebuild')
    byte_comparisons = {}
    for profile in ['debug', 'release']:
        pairs = [(first / profile / 'libvisor_move_request.rlib', out / 'target' / profile / 'libvisor_move_request.rlib'),
                 (out / ('first-client-' + profile), out / ('client-' + profile))]
        byte_comparisons[profile] = []
        for left, right in pairs:
            a, b = left.read_bytes(), right.read_bytes()
            raw = {'left': logical(left), 'right': logical(right), 'left_identity': identity(left), 'right_identity': identity(right),
                   'raw_equal': a == b, 'masks': [], 'normalization': None}
            byte_comparisons[profile].append(raw)
            require(a == b, 'own-build raw bytes differ')
    mutation_results = []
    for name, changed, details in variations:
        # Same isolated package, clean target, fresh process; only one explicit source edit.
        shutil.rmtree(out / 'target')
        (component / 'src/lib.rs').write_text(changed)
        observations = build_and_compare('mutant-' + name)
        require(all(not (o['value_comparison']['equal'] and o['length_comparison']['equal'])
                    for o in observations.values()), 'surviving compiled mutant: ' + name)
        mutation_results.append({**details, 'profiles': observations})
        print('compiled semantic mutant detected:', name, flush=True)
    (component / 'src/lib.rs').write_text(original_source)
    tools_after = {}
    for dirname in ['bin', 'lib']:
        tools_after.update({dirname + '/' + name: value for name, value in inventory(toolchain / dirname).items()})
    require(tools_before == tools_after, 'toolchain payload changed during run')
    for name, expected in external_tools.items():
        actual = Path(name.replace('<TOOLCHAIN>', str(toolchain)))
        require(identity(actual) == expected, 'external tool changed')
    require(sdk_pins == {name: identity(Path(sdk) / name) for name in sdk_pins}, 'SDK pins changed')
    load_bound_inputs()
    require(inventory(component) == inventory(SOURCE), 'isolated source not restored exactly')
    result = {'status': 'PASS', 'target_execution': False, 'instruction_evaluation': False,
              'profiles': ['debug', 'release'], 'value_cases_per_profile': 44679, 'integer_length_cases_per_profile': 211,
              'handwritten_tests_per_profile': 6, 'baseline': baseline, 'fresh_rebuild': rebuild,
              'own_build_raw_byte_comparisons': byte_comparisons, 'comparator_controls': comparison_controls,
              'compiled_mutant_count': len(mutation_results), 'compiled_mutants': mutation_results,
              'source_freeze_sha256': identity(PACKET / 'rust-validation/SOURCE-FREEZE.json')['sha256'],
              'pre_rust_freeze_sha256': identity(PACKET / 'pre-rust/PRE-RUST-FREEZE.json')['sha256'],
              'toolchain_unchanged_after': True, 'source_unchanged_after': True, 'commands': 'commands.json',
              'limits': 'Finite oracle comparison and own-build equality only; no target execution, target compiled-byte match, original ABI, allocator parity, shell/preflight/filesystem effect or whole component completion.'}
    write_json(receipts / 'results.json', result)
    print(json.dumps({'status': 'PASS', 'compiled_mutants': len(mutation_results), 'commands': len(commands), 'receipts': str(receipts)}), flush=True)


if __name__ == '__main__':
    main()
