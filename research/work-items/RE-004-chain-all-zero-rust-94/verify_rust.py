"""Qualify new native Rust against the independently frozen image relation."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import platform
import struct
import subprocess

from verify_static import PACKET, ROOT, TARGET, encoded, require, sha, validate
from oracle import fixtures

SOURCE = ROOT / 'src/node94-chain-all-zero'
CRATE = 'node94_chain_all_zero'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
HEAD = """    let mut node = u64::from_le_bytes(
        bytes(image, image_base, object.wrapping_add(72)).ok_or(AccessError::Head)?,
    );
"""
FOLLOW = """        let following =
            u64::from_le_bytes(bytes(image, image_base, node).ok_or(AccessError::Link)?);
"""
MUTATIONS = {
    'inverted_flag': [('if flag != 0', 'if flag == 0')],
    'flag_low_bit_only': [('if flag != 0', 'if flag & 1 != 0')],
    'head_before_flag': [(HEAD, ''), ('    if flag != 0 {', HEAD + '    if flag != 0 {')],
    'null_returns_false': [('\n    Ok(true)\n', '\n    Ok(false)\n')],
    'field_low32_only': [('if field != 0', 'if field as u32 != 0')],
    'inverted_field': [('if field != 0', 'if field == 0')],
    'link_before_field': [(FOLLOW, ''), ('    while node != 0 {\n', '    while node != 0 {\n' + FOLLOW)],
    'wrong_field_offset': [('node.wrapping_add(16)', 'node.wrapping_add(8)')],
    'wrong_head_offset': [('object.wrapping_add(72)', 'object.wrapping_add(80)')],
    'wrong_flag_offset': [('object.wrapping_add(112)', 'object.wrapping_add(111)')],
    'skip_first_node': [(HEAD, HEAD + '    if node != 0 { node = u64::from_le_bytes(bytes(image, image_base, node).ok_or(AccessError::Link)?); }\n')],
    'stop_after_first_zero': [('        node = following;', '        node = following; if node != 0 { return Ok(true); }')],
    'arbitrary_two_node_cap': [('let mut remaining = image.len().saturating_sub(7);', 'let mut remaining = 2_usize;')],
    'cycle_returns_true': [('return Err(AccessError::Cycle);', 'return Ok(true);')],
    'saturating_field_address': [('node.wrapping_add(16)', 'node.saturating_add(16)')],
    'strict_endpoint': [('    let end = start.checked_add(N)?;\n', '    let end = start.checked_add(N)?;\n    if end >= image.len() { return None; }\n')],
}


def mutate(original, patches):
    value = original
    for before, after in patches:
        require(value.count(before) == 1, 'mutation selector is not unique')
        value = value.replace(before, after)
    return value


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native output framing differs')
    count = memory = returns = admitted_values = admission = atomicity = 0
    first = None
    for i, (got, want) in enumerate(zip(struct.iter_unpack('<BQ512s', actual), struct.iter_unpack('<BQ512s', expected))):
        if got != want:
            count += 1; memory += got[2] != want[2]; returns += got[1] != want[1]
            admission += got[0] != want[0]
            admitted_values += got[0] == want[0] == 0 and got[1:] != want[1:]
            atomicity += want[0] != 0 and got[2] != want[2]
            if first is None:
                changed = [j for j, (a, b) in enumerate(zip(got[2], want[2])) if a != b]
                first = {'index': i, 'descriptor': list(struct.unpack_from('<QQH', inputs, 530 * i)),
                         'actual_tag_value': list(got[:2]), 'expected_tag_value': list(want[:2]),
                         'memory_bytes_differ': len(changed), 'first_byte': None if not changed else
                             {'offset': changed[0], 'actual': got[2][changed[0]], 'expected': want[2][changed[0]]}}
    return {'mismatches': count, 'memory_cases': memory, 'return_cases': returns,
            'admission_cases': admission, 'admitted_value_cases': admitted_values,
            'refusal_atomicity_cases': atomicity, 'first_witness': first, 'stdout_sha256': sha(actual)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--rustc', required=True, type=Path)
    args = parser.parse_args(); out, rustc = args.out.absolute(), args.rustc.resolve()
    require(not out.exists(), 'use a fresh output directory')
    original = (SOURCE / 'lib.rs').read_text()
    mutated = {name: mutate(original, patches) for name, patches in MUTATIONS.items()}
    static = validate(); require(encoded(static) == (PACKET / 'static.json').read_bytes(), 'static drift')
    inputs, expected, coverage = fixtures(); frozen = json.loads((PACKET / 'frozen.json').read_bytes())
    require(all(frozen[k] == v for k, v in coverage.items()), 'frozen metadata drift')
    require(frozen['oracle_sha256_at_freeze'] == sha((PACKET / 'oracle.py').read_bytes()), 'oracle drift')
    require(frozen['static_sha256_at_freeze'] == sha(encoded(static)), 'pre-Rust static binding drift')
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        require(gzip.decompress((PACKET / (name + '.bin.gz')).read_bytes()) == raw, 'frozen stream drift')
    require(sha(rustc.read_bytes()) == RUSTC_SHA, 'actual compiler pin')
    paths = [SOURCE / 'lib.rs', SOURCE / 'input_only_driver.rs', PACKET / 'oracle.py',
             PACKET / 'verify_static.py', PACKET / 'verify_rust.py']
    before = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}
    linker = Path('/usr/bin/cc'); linker_sha = sha(linker.read_bytes())
    out.mkdir(parents=True); calls, streams = [], {}

    def run(label, argv, data=None, success=True):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, input=data, capture_output=True)
        logs = {}
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            name = label + '.' + suffix; (out / name).write_bytes(raw); streams[name] = raw
            logs[suffix] = {'file': name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [str(v).replace(str(ROOT), '<repo>').replace(str(rustc), '<rustc>') for v in argv],
                      'exit_code': result.returncode, 'stdin_sha256': None if data is None else sha(data), 'logs': logs})
        (out / 'calls.json').write_bytes(encoded(calls))
        require((result.returncode == 0) == success, label + ' failed; raw streams retained')
        return result

    version = run('compiler', [rustc, '-vV']).stdout.decode()
    require('release: 1.94.1\n' in version and f'commit-hash: {COMMIT}\n' in version
            and 'host: aarch64-apple-darwin\n' in version, 'compiler version/host')
    linker_version = run('linker', [linker, '--version']).stdout.decode()
    profiles, repeats, controls = [], [], []

    def build(name, source, opt):
        folder = out / name; folder.mkdir()
        library, client = folder / f'lib{CRATE}.rlib', folder / 'client'
        flags = ['--edition=2021', '--target=aarch64-apple-darwin', '-Dwarnings', '-Ccodegen-units=1',
                 '-Coverflow-checks=on', f'-Copt-level={opt}', '-Clinker=/usr/bin/cc',
                 '--remap-path-prefix', f'{ROOT}=/reconstruction']
        run(name + '-library', [rustc, '--crate-name', CRATE, '--crate-type=rlib', source,
                               '-Cmetadata=chain_all_zero94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'chain_all_zero_client', SOURCE / 'input_only_driver.rs',
                              '--extern', f'{CRATE}={library}', *flags, '-o', client])
        raw = run(name + '-run', [client], inputs).stdout
        return library, client, raw, flags

    for opt in [0, 3]:
        label = f'opt{opt}'; library, client, raw, flags = build(label, SOURCE / 'lib.rs', opt)
        comparison = compare(raw, expected, inputs); require(comparison['mismatches'] == 0, 'native mismatch')
        unit = out / label / 'unit-tests'
        run(label + '-unit-build', [rustc, '--test', '--crate-name', CRATE, SOURCE / 'lib.rs', *flags, '-o', unit])
        tests = run(label + '-unit-run', [unit, '--test-threads=1']).stdout
        require(b'3 passed; 0 failed' in tests, 'unit tests did not run')
        library2, client2, raw2, _ = build(label + '-repeat', SOURCE / 'lib.rs', opt)
        require(raw2 == expected, 'repeat output differs')
        for kind, a, b in [('rlib', library, library2), ('client', client, client2)]:
            require(a.read_bytes() == b.read_bytes(), 'repeated host artifact differs')
            repeats.append({'profile': label, 'artifact': kind, 'bytes': a.stat().st_size,
                            'sha256': sha(a.read_bytes()), 'raw_equal': True, 'normalization': 'none'})
        for length in [1, 531]:
            bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
            require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
        oversized = struct.pack('<QQH', 0, 0, 513) + b'\0' * 512
        bad = run(label + '-oversized', [client], oversized, success=False)
        require(not bad.stdout and b'exceeds backing storage' in bad.stderr, 'oversized fixture accepted')
        profiles.append({'profile': label, 'cases': coverage['cases'], 'unit_tests_passed': 3, **comparison})
        for name, value in mutated.items():
            mutant = out / (name + '.rs'); mutant.write_text(value)
            _, _, wrong, _ = build(label + '-' + name, mutant, opt)
            mismatch = compare(wrong, expected, inputs)
            require(mismatch['mismatches'] > 0, 'surviving mutant: ' + name)
            if name in ['flag_low_bit_only', 'null_returns_false', 'field_low32_only', 'stop_after_first_zero']:
                require(mismatch['admitted_value_cases'] > 0, 'no admitted value witness: ' + name)
            controls.append({'profile': label, 'mutation': name, 'source_sha256': sha(mutant.read_bytes()), **mismatch})
    require(compare(bytes([expected[0] ^ 1]) + expected[1:], expected, inputs)['mismatches'] == 1,
            'changed-output comparator control')
    try:
        compare(expected[:-521], expected, inputs)
    except ValueError:
        pass
    else:
        raise ValueError('missing row comparator control')
    require(before == {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}, 'source drift during run')
    require(sha(rustc.read_bytes()) == RUSTC_SHA and sha(linker.read_bytes()) == linker_sha, 'tool drift during run')
    archive = {'encoding': 'base64', 'streams': {name: sha(raw) for name, raw in streams.items()},
               'payloads': {sha(raw): base64.b64encode(raw).decode() for raw in streams.values()}}
    archive_file = out / 'raw-streams.json.gz'; archive_file.write_bytes(gzip.compress(encoded(archive), mtime=0))
    decoded = json.loads(gzip.decompress(archive_file.read_bytes()))
    require(all(base64.b64decode(decoded['payloads'][decoded['streams'][name]], validate=True) == raw
                for name, raw in streams.items()), 'lossless archive mismatch')
    result = {'target_sha256': TARGET, 'source_sha256': before, 'compiler_sha256': RUSTC_SHA,
              'compiler_version': version, 'linker_sha256': linker_sha, 'linker_version': linker_version,
              'python': platform.python_version(), 'platform': platform.platform(), 'frozen': frozen,
              'profiles': profiles, 'repeated_builds': repeats, 'native_wrong_controls': controls,
              'comparator_controls': ['changed row detected', 'missing row rejected'],
              'raw_archive_sha256': sha(archive_file.read_bytes()), 'captured_execution': False,
              'instruction_emulation': False, 'target_compiled_byte_identity': 'not measured; new host value component'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': coverage['cases'], 'profiles': profiles, 'wrong_controls_detected': len(controls),
                      'repeated_artifacts_equal': len(repeats)}))


if __name__ == '__main__':
    main()
