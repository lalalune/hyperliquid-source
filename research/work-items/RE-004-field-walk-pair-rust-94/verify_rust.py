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
from oracle import fixtures, relation

SOURCE = ROOT / 'src/node94-field-walk-pair'
CRATE = 'node94_field_walk_pair'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'wrong_first_field': [('object.wrapping_add(0x788)', 'object.wrapping_add(0x790)')],
 'first_address_saturates': [('object.wrapping_add(0x788)', 'object.saturating_add(0x788)')],
 'wrong_second_field': [('p.wrapping_add(0x30)', 'p.wrapping_add(0x38)')],
 'narrow_chain_pointer': [('let q = word(image, image_base, p.wrapping_add(0x30))?;',
                           'let q = u64::from(word(image, image_base, p.wrapping_add(0x30))? as u32);')],
 'wrong_upper_field': [('q.wrapping_add(0xb20)', 'q.wrapping_add(0xb28)')],
 'wrong_lower_field': [('q.wrapping_add(0xb18)', 'q.wrapping_add(0xb10)')],
 'reversed_subtraction': [('a.wrapping_sub(b)', 'b.wrapping_sub(a)')],
 'saturating_subtraction': [('a.wrapping_sub(b)', 'a.saturating_sub(b)')],
 'addition': [('a.wrapping_sub(b)', 'a.wrapping_add(b)')],
 'logical_shift': [('((difference >> 4) as u64, q)', '(((difference as u64) >> 4), q)')],
 'shift_three': [('difference >> 4', 'difference >> 3')],
 'shift_five': [('difference >> 4', 'difference >> 5')],
 'division_toward_zero': [('difference >> 4', 'difference / 16')],
 'narrow_difference': [('let difference = a.wrapping_sub(b) as i64;',
                        'let difference = i64::from(a.wrapping_sub(b) as i32);')],
 'preserve_incoming_chain_rdx': [('((difference >> 4) as u64, q)',
                                  '((difference >> 4) as u64, incoming_rdx)')],
 'wrong_signed_field': [('incoming_rdx.wrapping_add(0x1438)', 'incoming_rdx.wrapping_add(0x143c)')],
 'signed_address_saturates': [('incoming_rdx.wrapping_add(0x1438)', 'incoming_rdx.saturating_add(0x1438)')],
 'unsigned_field': [('i64::from(i32::from_le_bytes(bytes)) as u64', 'u64::from(u32::from_le_bytes(bytes))')],
 'field_byte_order': [('i32::from_le_bytes(bytes)', 'i32::from_be_bytes(bytes)')],
 'eager_unused_object': [('Member::SignedField => {',
                          'Member::SignedField => {\n'
                          '            let _unused = word(image, image_base, object.wrapping_add(0x788))?;')],
 'field_requires_eight': [('span(image, image_base, address, 4)?', 'span(image, image_base, address, 8)?')],
 'zero_signed_rdx': [('(value, incoming_rdx)', '(value, 0)')],
 'return_value_not_one': [('Some(Registers { rax: 1, rdx })\n}\n\n#[cfg(test)]', 'Some(Registers { rax: value, rdx })\n}\n\n#[cfg(test)]')],
 'narrow_return_rdx': [('Some(Registers { rax: 1, rdx })\n}\n\n#[cfg(test)]', 'Some(Registers { rax: 1, rdx: u64::from(rdx as u32) })\n}\n\n#[cfg(test)]')],
 'output_next_word': [('span(image, image_base, output, 8)?',
                       'span(image, image_base, output.wrapping_add(8), 8)?')],
 'output_byte_order': [('copy_from_slice(&value.to_le_bytes())', 'copy_from_slice(&value.to_be_bytes())')],
 'four_byte_store': [('image[destination].copy_from_slice(&value.to_le_bytes());',
                      'image[destination.start..destination.start + '
                      '4].copy_from_slice(&value.to_le_bytes()[..4]);')],
 'early_output_before_fields': [('let a = word(image, image_base, q.wrapping_add(0xb20))?;',
                                 'if let Some(range) = span(image, image_base, output, 8) { '
                                 'image[range].fill(0); }\n'
                                 '            let a = word(image, image_base, q.wrapping_add(0xb20))?;')],
 'ignore_image_overflow': [('image.len() as u128 > (1u128 << 64)',
                            'image.len() as u128 > (1u128 << 64) && false')],
 'strict_span_end': [('(end <= image.len())', '(end < image.len())')]}
ADMISSION_ONLY = ['wrong_first_field', 'wrong_second_field', 'first_address_saturates', 'narrow_chain_pointer', 'signed_address_saturates', 'eager_unused_object', 'field_requires_eight', 'ignore_image_overflow', 'strict_span_end']

def mutate(original, patches):
    value = original
    for before, after in patches:
        require(value.count(before) == 1, 'mutation selector is not unique')
        value = value.replace(before, after)
    return value


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native output framing differs')
    count = admitted_values = admission = refused_inputs = 0; first = None
    for i in range(len(expected)//152):
        got, want = actual[i*152:(i+1)*152], expected[i*152:(i+1)*152]
        if got != want:
            gr, wr = struct.unpack_from('<3Q', got), struct.unpack_from('<3Q', want)
            count += 1; admission += gr[0] != wr[0]
            admitted_values += gr[0] == wr[0] == 1
            refused_inputs += wr[0] == 0
            if first is None:
                first = {'index':i,'descriptor':list(struct.unpack_from('<6Q',inputs,176*i)),
                         'input_image_hex':inputs[176*i+48:176*(i+1)].hex(),
                         'actual_registers':list(gr),'expected_registers':list(wr),
                         'actual_image_hex':got[24:].hex(),'expected_image_hex':want[24:].hex()}
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
    supplemental = json.loads((PACKET / 'post-freeze-admission.json').read_text())
    require(supplemental['primary_frozen_sha256'] == sha((PACKET / 'frozen.json').read_bytes()), 'primary freeze drift')
    require(supplemental['unchanged_pre_rust_oracle_sha256'] == sha((PACKET / 'oracle.py').read_bytes()), 'supplemental oracle drift')
    require(supplemental['unchanged_library_sha256'] == sha((SOURCE / 'lib.rs').read_bytes()), 'supplemental source drift')
    for item in supplemental['cases']:
        row = (*item['descriptor'], bytes.fromhex(item['image_hex']))
        registers, updated = relation(row)
        require(list(registers) == item['expected_registers'] and updated.hex() == item['expected_image_hex'], 'supplemental algebra differs')
        inputs += struct.pack('<6Q', *row[:-1]) + row[-1]
        expected += struct.pack('<3Q', *registers) + updated
    qualification_corpus = {'pre_rust_cases':coverage['cases'], 'post_freeze_admission_cases':len(supplemental['cases']),
                            'total_cases':coverage['cases']+len(supplemental['cases']),
                            'inputs_sha256':sha(inputs),'expected_sha256':sha(expected)}
    coverage = {**coverage, 'cases':qualification_corpus['total_cases']}
    require(sha(rustc.read_bytes()) == RUSTC_SHA, 'actual compiler pin')
    paths = [SOURCE / 'lib.rs', SOURCE / 'input_only_driver.rs', PACKET / 'oracle.py',
             PACKET / 'verify_static.py', PACKET / 'verify_rust.py', PACKET / 'post-freeze-admission.json']
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
                               '-Cmetadata=field_walk_pair94', *flags, '-o', library])
        run(name + '-client', [rustc, '--crate-name', 'field_walk_pair_client', SOURCE / 'input_only_driver.rs',
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
        for length in [1, 177]:
            bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
            require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
        for descriptor, member, length in [('length', 0, 129), ('member', 2, 128)]:
            invalid = struct.pack('<6Q', member, 0, 0, 0, 0, length) + bytes(128)
            bad = run(label + '-invalid-' + descriptor, [client], invalid, success=False)
            require(not bad.stdout and b'invalid member/image descriptor' in bad.stderr, 'invalid descriptor accepted')
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
        compare(expected[:-152], expected, inputs)
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
              'qualification_corpus': qualification_corpus, 'profiles': profiles, 'repeated_builds': repeats, 'native_wrong_controls': controls,
              'comparator_controls': ['changed row detected', 'missing row rejected'],
              'raw_archive_sha256': sha(archive_file.read_bytes()), 'archive_parameters': {'compression':'gzip','level':1,'mtime':0}, 'captured_execution': False,
              'instruction_emulation': False, 'target_compiled_byte_identity': 'not measured; new host value component'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': coverage['cases'], 'profiles': profiles, 'wrong_controls_detected': len(controls),
                      'repeated_artifacts_equal': len(repeats)}))


if __name__ == '__main__':
    main()
