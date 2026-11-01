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

SOURCE = ROOT / 'src/node94-two-table-lookup'
CRATE = 'node94_two_table_lookup'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'gate_strict': [('gate <= 2', 'gate < 2')],
 'gate_wide': [('gate <= 2', 'gate <= 3')],
 'gate_signed': [('gate <= 2', '(gate as i32) <= 2')],
 'gate_full_register': [('gate <= 2', 'first.wrapping_sub(3) <= 2')],
 'gate_origin_two': [('first32.wrapping_sub(3)', 'first32.wrapping_sub(2)')],
 'mode_full_register': [('mode as u32 == 1', 'mode == 1')],
 'mode_nonzero': [('mode as u32 == 1', 'mode as u32 != 0')],
 'mode_zero': [('mode as u32 == 1', 'mode as u32 == 0')],
 'first_unsigned': [('i64::from(first32 as i32)', 'i64::from(first32)')],
 'row_unsigned': [('i64::from(row as u32 as i32)', 'i64::from(row as u32)')],
 'row_signed16': [('i64::from(row as u32 as i32)', 'i64::from(row as u16 as i16)')],
 'row_full_register': [('i64::from(row as u32 as i32)', 'row as i64')],
 'index_narrow32': [('(index as u64).wrapping_mul(8)', '(index as i32 as u64).wrapping_mul(8)')],
 'second_coefficient_four': [('signed_row.wrapping_mul(3)', 'signed_row.wrapping_mul(4)')],
 'first_coefficient_nine': [('signed_row.wrapping_mul(10)', 'signed_row.wrapping_mul(9)')],
 'scale_four': [('(index as u64).wrapping_mul(8)', '(index as u64).wrapping_mul(4)')],
 'swap_bases': [('0x576db20u64', '0x576d9e0u64'),
                ('            0x576d9e0u64,\n            i64::from(first32',
                 '            0x576db20u64,\n            i64::from(first32')],
 'first_base_next_word': [('0x576d9e0u64', '0x576d9e8u64')],
 'second_base_next_word': [('0x576db20u64', '0x576db28u64')],
 'omitted_load_bias': [('.wrapping_add(load_bias)', '.wrapping_add(load_bias.wrapping_sub(load_bias))')],
 'saturating_load_bias': [('.wrapping_add(load_bias)', '.saturating_add(load_bias)')],
 'saturating_effective_address': [('.wrapping_add((index as u64).wrapping_mul(8))',
                                   '.saturating_add((index as u64).wrapping_mul(8))')],
 'big_endian': [('u64::from_le_bytes(bytes.try_into().unwrap())',
                 'u64::from_be_bytes(bytes.try_into().unwrap())')],
 'low32_value': [('Ok(u64::from_le_bytes(bytes.try_into().unwrap()))',
                  'Ok(u64::from(u64::from_le_bytes(bytes.try_into().unwrap()) as u32))')],
 'sign32_value': [('Ok(u64::from_le_bytes(bytes.try_into().unwrap()))',
                   'Ok(u64::from_le_bytes(bytes.try_into().unwrap()) as i32 as u64)')],
 'strict_image_end': [('image.len() as u128 > (1u128 << 64)', 'image.len() as u128 >= (1u128 << 64)')],
 'strict_selected_end': [('let bytes = image.get(offset..end).ok_or(AccessError::SelectedWord)?;',
                          'let bytes = if end < image.len() { image.get(offset..end) } else { None '
                          '}.ok_or(AccessError::SelectedWord)?;')]}
# Address-changing controls can be detected by refusal when their wrong
# address lies outside the compact image; those are reported separately.
ADMISSION_ONLY = ['first_unsigned', 'gate_signed', 'index_narrow32', 'omitted_load_bias', 'row_full_register', 'row_signed16', 'row_unsigned', 'saturating_effective_address', 'saturating_load_bias', 'strict_image_end', 'strict_selected_end']

def mutate(original, patches):
    value = original
    for before, after in patches:
        require(value.count(before) == 1, 'mutation selector is not unique')
        value = value.replace(before, after)
    return value


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native output framing differs')
    count = admitted_values = admission = refused_inputs = 0; first = None
    for i, (got, want) in enumerate(zip(struct.iter_unpack('<BQ', actual), struct.iter_unpack('<BQ', expected))):
        if got != want:
            count += 1; admission += got[0] != want[0]
            admitted_values += got[0] == want[0] == 0 and got[1:] != want[1:]
            refused_inputs += want[0] != 0
            if first is None:
                first = {'index':i,'descriptor':list(struct.unpack_from('<QQQQQH',inputs,554*i)),
                         'image_hex':inputs[554*i+42:554*(i+1)].hex(),
                         'actual_tag_value':list(got),'expected_tag_value':list(want)}
    return {'mismatches':count,'admission_cases':admission,'admitted_value_cases':admitted_values,
            'expected_refusal_cases':refused_inputs,'first_witness':first,'stdout_sha256':sha(actual)}


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
                               '-Cmetadata=two_table_lookup94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'two_table_lookup_client', SOURCE / 'input_only_driver.rs',
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
        for length in [1, 555]:
            bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
            require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
        oversized = struct.pack('<QQQQQH', 0, 0, 0, 0, 0, 513) + b'\0' * 512
        bad = run(label + '-oversized', [client], oversized, success=False)
        require(not bad.stdout and b'exceeds backing storage' in bad.stderr, 'oversized fixture accepted')
        profiles.append({'profile': label, 'cases': coverage['cases'], 'unit_tests_passed': 3, **comparison})
        for name, value in mutated.items():
            mutant = out / (name + '.rs'); mutant.write_text(value)
            _, _, wrong, _ = build(label + '-' + name, mutant, opt)
            mismatch = compare(wrong, expected, inputs)
            require(mismatch['mismatches'] > 0, 'surviving mutant: ' + name)
            if name not in ADMISSION_ONLY:
                require(mismatch['admitted_value_cases'] > 0, 'no admitted value witness: ' + name)
            else:
                require(mismatch['admission_cases'] > 0, 'no admission witness: ' + name)
            controls.append({'profile': label, 'mutation': name, 'source_sha256': sha(mutant.read_bytes()), **mismatch})
    require(compare(bytes([expected[0] ^ 1]) + expected[1:], expected, inputs)['mismatches'] == 1,
            'changed-output comparator control')
    try:
        compare(expected[:-9], expected, inputs)
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
              'raw_archive_sha256': sha(archive_file.read_bytes()), 'archive_parameters': {'compression':'gzip','level':1,'mtime':0}, 'captured_execution': False,
              'instruction_emulation': False, 'target_compiled_byte_identity': 'not measured; new host value component'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': coverage['cases'], 'profiles': profiles, 'wrong_controls_detected': len(controls),
                      'repeated_artifacts_equal': len(repeats)}))


if __name__ == '__main__':
    main()
