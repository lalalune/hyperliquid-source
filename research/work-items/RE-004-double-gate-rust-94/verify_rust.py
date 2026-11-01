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

SOURCE = ROOT / 'src/node94-double-gate'
CRATE = 'node94_double_gate'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'wrong_pointer_field': [('object.wrapping_add(0xf38)', 'object.wrapping_add(0xf40)')],
 'saturating_field_address': [('object.wrapping_add(0xf38)', 'object.saturating_add(0xf38)')],
 'next_payload_word': [('word(image, image_base, pointer)',
                        'word(image, image_base, pointer.wrapping_add(8))')],
 'payload_byte_order': [('let magnitude = bits &',
                         'let bits = bits.swap_bytes();\n    let magnitude = bits &')],
 'pointer_byte_order': [('.ok_or(Refusal::PointerField)?;', '.ok_or(Refusal::PointerField)?.swap_bytes();')],
 'ignore_invalid_mask': [('if nan && !mode.invalid_masked {', 'if nan && !mode.invalid_masked && false {')],
 'ucomisd_nan_rule': [('if nan && !mode.invalid_masked {',
                       'if nan && bits & 0x0008_0000_0000_0000 == 0 && !mode.invalid_masked {')],
 'inverted_invalid_mask': [('if nan && !mode.invalid_masked {', 'if nan && mode.invalid_masked {')],
 'infinity_is_nan': [('let nan = magnitude > 0x7ff0_0000_0000_0000;',
                      'let nan = magnitude >= 0x7ff0_0000_0000_0000;')],
 'ignore_denormal_exception': [('if denormal && !mode.denormals_are_zero && !mode.denormal_masked {',
                                'if denormal && !mode.denormals_are_zero && !mode.denormal_masked && false '
                                '{')],
 'ignore_daz': [('if denormal && !mode.denormals_are_zero && !mode.denormal_masked {',
                 'if denormal && (mode.denormals_are_zero || !mode.denormals_are_zero) && '
                 '!mode.denormal_masked {')],
 'inverted_denormal_mask': [('if denormal && !mode.denormals_are_zero && !mode.denormal_masked {',
                             'if denormal && !mode.denormals_are_zero && mode.denormal_masked {')],
 'zero_is_denormal': [('magnitude != 0 && magnitude <', 'magnitude <')],
 'strict_threshold': [('(0x3ff0_0000_0000_0000..=0x7ff0_0000_0000_0000)',
                       '(0x3ff0_0000_0000_0001..=0x7ff0_0000_0000_0000)')],
 'half_threshold': [('(0x3ff0_0000_0000_0000..=0x7ff0_0000_0000_0000)',
                     '(0x3fe0_0000_0000_0000..=0x7ff0_0000_0000_0000)')],
 'ignore_sign': [('.contains(&bits)', '.contains(&magnitude)')],
 'allow_nan_and_negative': [('(0x3ff0_0000_0000_0000..=0x7ff0_0000_0000_0000).contains(&bits)',
                             'bits >= 0x3ff0_0000_0000_0000')],
 'exclude_positive_infinity': [('(0x3ff0_0000_0000_0000..=0x7ff0_0000_0000_0000)',
                                '(0x3ff0_0000_0000_0000..0x7ff0_0000_0000_0000)')],
 'return_boolean': [('Ok((pointer & !0xff) | u64::from(gate))', 'Ok((pointer & 0) | u64::from(gate))')],
 'preserve_low_seven_bits': [('pointer & !0xff', 'pointer & !1')],
 'clear_two_bytes': [('pointer & !0xff', 'pointer & !0xffff')],
 'narrow_pointer': [('pointer & !0xff', 'u64::from(pointer as u32) & !0xff')],
 'or_without_clear': [('pointer & !0xff', 'pointer | 0')],
 'add_gate': [('Ok((pointer & !0xff) | u64::from(gate))', 'Ok(pointer.wrapping_add(u64::from(gate)))')],
 'null_pointer_refused': [('    let bits = word(image, image_base, pointer)',
                           '    if pointer == 0 { return Err(Refusal::Payload); }\n'
                           '    let bits = word(image, image_base, pointer)')],
 'strict_selected_end': [('    let end = offset.checked_add(8)?;',
                          '    let end = offset.checked_add(8)?;\n'
                          '    if end == image.len() { return None; }')],
 'strict_image_end': [('image.len() as u128 > (1u128 << 64)', 'image.len() as u128 >= (1u128 << 64)')],
 'word_narrow32': [('Some(u64::from_le_bytes(image.get(offset..end)?.try_into().ok()?))',
                    'Some(u64::from(u64::from_le_bytes(image.get(offset..end)?.try_into().ok()?) as u32))')]}
ADMISSION_ONLY = ['saturating_field_address', 'pointer_byte_order', 'ignore_invalid_mask', 'ucomisd_nan_rule', 'inverted_invalid_mask', 'infinity_is_nan', 'ignore_denormal_exception', 'ignore_daz', 'inverted_denormal_mask', 'zero_is_denormal', 'null_pointer_refused', 'strict_selected_end', 'strict_image_end']

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
                first = {'index':i,'descriptor':list(struct.unpack_from('<QQBH',inputs,147*i)),
                         'image_hex':inputs[147*i+19:147*(i+1)].hex(),
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
                               '-Cmetadata=double_gate94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'double_gate_client', SOURCE / 'input_only_driver.rs',
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
        for length in [1, 148]:
            bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
            require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
        for descriptor, mode, length in [('length', 0, 129), ('mode', 8, 128)]:
            invalid = struct.pack('<QQBH', 0, 0, mode, length) + bytes(128)
            bad = run(label + '-invalid-' + descriptor, [client], invalid, success=False)
            require(not bad.stdout and b'invalid image/mode descriptor' in bad.stderr, 'invalid descriptor accepted')
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
