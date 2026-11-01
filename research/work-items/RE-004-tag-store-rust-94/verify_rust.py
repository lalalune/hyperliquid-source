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

SOURCE = ROOT / 'src/node94-tag-store'
CRATE = 'node94_tag_store'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
COPY = """            let from = span(image, image_base, source, 16).ok_or(AccessError::Source)?;
            let value: [u8; 16] = image[from].try_into().unwrap();
            let to = span(image, image_base, destination, 16).ok_or(AccessError::Destination)?;
            image[to].copy_from_slice(&value);"""
LOOP = """            let from = span(image, image_base, source, 16).ok_or(AccessError::Source)?;
            let to = span(image, image_base, destination, 16).ok_or(AccessError::Destination)?;
            for i in ITER { image[to.start+i] = image[from.start+i]; }"""
PARTIAL = """            if let Some(start) = destination.checked_sub(image_base).and_then(|v| usize::try_from(v).ok()) {
                for (i, byte) in value.iter().enumerate() {
                    if let Some(slot) = image.get_mut(start.saturating_add(i)) { *slot = *byte; }
                }
            }
"""
MUTATIONS = {
 'full64_tag': [('match tag as u32 {','match tag {')],
 'low8_tag': [('match tag as u32 {','match tag as u8 {')],
 'unknown_store': [('_ => {}','_ => { let to = span(image, image_base, destination, 8).ok_or(AccessError::Destination)?; image[to].copy_from_slice(&source.to_le_bytes()); }')],
 'ignore_bias': [('let value = load_bias.wrapping_add(LINKED_ADDRESS);','let value = LINKED_ADDRESS; let _ = load_bias;')],
 'image_base_as_bias': [('let value = load_bias.wrapping_add(LINKED_ADDRESS);','let value = image_base.wrapping_add(LINKED_ADDRESS); let _ = load_bias;')],
 'saturating_bias': [('load_bias.wrapping_add(LINKED_ADDRESS)','load_bias.saturating_add(LINKED_ADDRESS)')],
 'wrong_linked_address': [('0x57592a0','0x57592a1')],
 'read_unread_global': [('let value = load_bias.wrapping_add(LINKED_ADDRESS);','let value = load_bias.wrapping_add(LINKED_ADDRESS); let from = span(image, image_base, value, 8).ok_or(AccessError::Source)?; let value = u64::from_le_bytes(image[from].try_into().unwrap());')],
 'read_scalar_pointer': [('image[to].copy_from_slice(&source.to_le_bytes());','let from = span(image, image_base, source, 8).ok_or(AccessError::Source)?; let value: [u8; 8] = image[from].try_into().unwrap(); image[to].copy_from_slice(&value);')],
 'scalar_big_endian': [('source.to_le_bytes()','source.to_be_bytes()')],
 'global_big_endian': [('value.to_le_bytes()','value.to_be_bytes()')],
 'scalar_low32': [('source.to_le_bytes()','u64::from(source as u32).to_le_bytes()')],
 'copy_eight': [(COPY,COPY.replace('16','8'))],
 'copy_forward': [(COPY,LOOP.replace('ITER','0..16'))],
 'copy_backward': [(COPY,LOOP.replace('ITER','(0..16).rev()'))],
 'copy_source_plus_one': [('span(image, image_base, source, 16)','span(image, image_base, source.wrapping_add(1), 16)')],
 'copy_destination_plus_one': [('span(image, image_base, destination, 16)','span(image, image_base, destination.wrapping_add(1), 16)')],
 'return_one': [('    Ok(0)','    Ok(1)')],
 'upper_rax_survives': [('    Ok(0)','    Ok(1_u64 << 32)')],
 'eager_destination': [('    match tag as u32 {','    let _ = span(image, image_base, destination, 8).ok_or(AccessError::Destination)?;\n    match tag as u32 {')],
 'eager_source': [('    match tag as u32 {','    let _ = span(image, image_base, source, 16).ok_or(AccessError::Source)?;\n    match tag as u32 {')],
 'strict_endpoint': [('end <= image.len()','end < image.len()')],
 'partial_output_before_refusal': [('            let to = span(image, image_base, destination, 16).ok_or(AccessError::Destination)?;',PARTIAL+'            let to = span(image, image_base, destination, 16).ok_or(AccessError::Destination)?;')],
}
ADMISSION_ONLY = {'eager_destination','eager_source','strict_endpoint'}


def mutate(original, patches):
    value = original
    for before, after in patches:
        require(value.count(before) == 1, 'mutation selector is not unique')
        value = value.replace(before, after)
    return value


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native output framing differs')
    count = admitted_values = admission = refused_inputs = refusal_state = 0; first = None
    for i, (got, want) in enumerate(zip(struct.iter_unpack('<BQ64s', actual), struct.iter_unpack('<BQ64s', expected))):
        if got != want:
            count += 1; admission += got[0] != want[0]
            admitted_values += got[0] == want[0] == 0 and got[1:] != want[1:]
            refused_inputs += want[0] != 0
            refusal_state += want[0] != 0 and got[2] != want[2]
            if first is None:
                first = {'index':i,'descriptor':list(struct.unpack_from('<5QH',inputs,106*i)),
                         'image_hex':inputs[106*i+42:106*(i+1)].hex(),
                         'actual_tag_rax_image':[got[0],got[1],got[2].hex()],'expected_tag_rax_image':[want[0],want[1],want[2].hex()]}
    return {'mismatches':count,'admission_cases':admission,'admitted_value_cases':admitted_values,
            'expected_refusal_cases':refused_inputs,'refusal_image_cases':refusal_state,'first_witness':first,'stdout_sha256':sha(actual)}


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
            name = label + '.' + suffix; streams[name] = raw
            logs[suffix] = {'file': name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [str(v).replace(str(ROOT), '<repo>').replace(str(rustc), '<rustc>') for v in argv],
                      'exit_code': result.returncode, 'stdin_sha256': None if data is None else sha(data), 'logs': logs})
        # Disk is constrained: checkpoint all raw streams losslessly in one
        # archive instead of retaining a second per-command copy. This also
        # preserves unexpected failures before the status assertion below.
        checkpoint = {'encoding':'base64','streams':{n:sha(r) for n,r in streams.items()},
                      'payloads':{sha(r):base64.b64encode(r).decode() for r in streams.values()}}
        (out / 'raw-streams.json.gz').write_bytes(gzip.compress(encoded(checkpoint),compresslevel=1,mtime=0))
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
                               '-Cmetadata=tag_store94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'tag_store_client', SOURCE / 'input_only_driver.rs',
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
        for length in [1, 107]:
            bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
            require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
        oversized = struct.pack('<5QH', 0, 0, 0, 0, 0, 65) + b'\0' * 64
        bad = run(label + '-oversized', [client], oversized, success=False)
        require(not bad.stdout and b'exceeds backing storage' in bad.stderr, 'oversized fixture accepted')
        profiles.append({'profile': label, 'cases': coverage['cases'], 'unit_tests_passed': 3, **comparison})
        for name, value in mutated.items():
            mutant = out / (name + '.rs'); mutant.write_text(value)
            _, _, wrong, _ = build(label + '-' + name, mutant, opt)
            mismatch = compare(wrong, expected, inputs)
            require(mismatch['mismatches'] > 0, 'surviving mutant: ' + name)
            if name == 'partial_output_before_refusal':
                require(mismatch['refusal_image_cases'] > 0, 'no partial-refusal state witness')
            elif name not in ADMISSION_ONLY:
                require(mismatch['admitted_value_cases'] > 0, 'no admitted value witness: ' + name)
            else:
                require(mismatch['admission_cases'] > 0, 'no admission witness: ' + name)
            controls.append({'profile': label, 'mutation': name, 'source_sha256': sha(mutant.read_bytes()), **mismatch})
    require(compare(bytes([expected[0] ^ 1]) + expected[1:], expected, inputs)['mismatches'] == 1,
            'changed-output comparator control')
    try:
        compare(expected[:-73], expected, inputs)
    except ValueError:
        pass
    else:
        raise ValueError('missing row comparator control')
    require(before == {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}, 'source drift during run')
    require(sha(rustc.read_bytes()) == RUSTC_SHA and sha(linker.read_bytes()) == linker_sha, 'tool drift during run')
    archive = {'encoding': 'base64', 'streams': {name: sha(raw) for name, raw in streams.items()},
               'payloads': {sha(raw): base64.b64encode(raw).decode() for raw in streams.values()}}
    archive_file = out / 'raw-streams.json.gz'; archive_file.write_bytes(gzip.compress(encoded(archive), compresslevel=1, mtime=0))
    decoded = json.loads(gzip.decompress(archive_file.read_bytes()))
    require(all(base64.b64decode(decoded['payloads'][decoded['streams'][name]], validate=True) == raw
                for name, raw in streams.items()), 'lossless archive mismatch')
    result = {'target_sha256': TARGET, 'source_sha256': before, 'compiler_sha256': RUSTC_SHA,
              'compiler_version': version, 'linker_sha256': linker_sha, 'linker_version': linker_version,
              'python': platform.python_version(), 'platform': platform.platform(), 'frozen': frozen,
              'profiles': profiles, 'repeated_builds': repeats, 'native_wrong_controls': controls,
              'comparator_controls': ['changed row detected', 'missing row rejected'],
              'raw_archive_sha256': sha(archive_file.read_bytes()), 'raw_archive_gzip': {'compresslevel':1,'mtime':0}, 'captured_execution': False,
              'instruction_emulation': False, 'target_compiled_byte_identity': 'not measured; new host value component'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': coverage['cases'], 'profiles': profiles, 'wrong_controls_detected': len(controls),
                      'repeated_artifacts_equal': len(repeats)}))


if __name__ == '__main__':
    main()
