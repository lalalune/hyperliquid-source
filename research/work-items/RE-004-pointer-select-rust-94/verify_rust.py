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

SOURCE = ROOT / 'src/node94-pointer-select'
CRATE = 'node94_pointer_select'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'full64_selector': [('selector as u32 == 1', 'selector == 1')],
 'lowbyte_selector': [('selector as u32 == 1', 'selector as u8 == 1')],
 'nonzero_selector': [('selector as u32 == 1', 'selector as u32 != 0')],
 'zero_selector': [('selector as u32 == 1', 'selector as u32 == 0')],
 'inverted_selector': [('selector as u32 == 1', 'selector as u32 != 1')],
 'signed_selector': [('selector as u32 == 1', '(selector as i32) <= 1')],
 'always_alternative': [('selector as u32 == 1', 'selector as u32 == 1 || true')],
 'always_default': [('selector as u32 == 1', 'selector as u32 == 1 && false')],
 'wrong_alternative_offset': [('adjusted.wrapping_add(0xe518)', 'adjusted.wrapping_add(0xe520)')],
 'wrong_default_offset': [('adjusted.wrapping_add(0xec10)', 'adjusted.wrapping_add(0xec18)')],
 'default_from_alternative': [('adjusted.wrapping_add(0xec10)',
                               'adjusted.wrapping_add(0xe518).wrapping_add(0xec10)')],
 'field_offset_minus_eight': [('selected.wrapping_add(0x78)', 'selected.wrapping_add(0x70)')],
 'field_offset_plus_eight': [('selected.wrapping_add(0x78)', 'selected.wrapping_add(0x80)')],
 'omitted_field_offset': [('selected.wrapping_add(0x78)', 'selected')],
 'narrow_rax': [('rax: value,', 'rax: u64::from(value as u32),')],
 'original_object_rdi': [('rdi: selected,', 'rdi: object,')],
 'adjusted_object_rdi': [('rdi: selected,', 'rdi: adjusted,')],
 'field_address_rdi': [('rdi: selected,', 'rdi: selected.wrapping_add(0x78),')],
 'narrow_rdi': [('rdi: selected,', 'rdi: u64::from(selected as u32),')],
 'narrow_rsi': [('rsi: selector,', 'rsi: u64::from(selector as u32),')],
 'zero_rsi': [('rsi: selector,', 'rsi: 0,')],
 'word_byte_order': [('u64::from_le_bytes', 'u64::from_be_bytes')],
 'narrow_object': [('    let adjusted = match entry {',
                    '    let object = u64::from(object as u32);\n    let adjusted = match entry {')],
 'saturating_alternative': [('adjusted.wrapping_add(0xe518)', 'adjusted.saturating_add(0xe518)')],
 'saturating_default': [('adjusted.wrapping_add(0xec10)', 'adjusted.saturating_add(0xec10)')],
 'saturating_field': [('selected.wrapping_add(0x78)', 'selected.saturating_add(0x78)')],
 'missing_inner_adjustment': [('Entry::Offset24 => object.wrapping_add(0x18),',
                               'Entry::Offset24 => object,')],
 'saturating_inner_adjustment': [('Entry::Offset24 => object.wrapping_add(0x18),',
                                  'Entry::Offset24 => object.saturating_add(0x18),')],
 'missing_outer_first_adjustment': [('object.wrapping_add(0x2998).wrapping_add(0x18)',
                                     'object.wrapping_add(0x18)')],
 'missing_outer_second_adjustment': [('object.wrapping_add(0x2998).wrapping_add(0x18)',
                                      'object.wrapping_add(0x2998)')],
 'saturating_outer_first': [('object.wrapping_add(0x2998).wrapping_add(0x18)',
                             'object.saturating_add(0x2998).wrapping_add(0x18)')],
 'saturating_outer_second': [('object.wrapping_add(0x2998).wrapping_add(0x18)',
                              'object.wrapping_add(0x2998).saturating_add(0x18)')],
 'ignore_image_overflow': [('image.len() as u128 > (1u128 << 64)',
                            'image.len() as u128 > (1u128 << 64) && false')],
 'strict_image_end': [('image.len() as u128 > (1u128 << 64)', 'image.len() as u128 >= (1u128 << 64)')],
 'strict_word_end': [('let end = start.checked_add(8)?;',
                      'let end = start.checked_add(8)?;\n    if end == image.len() { return None; }')],
 'zero_object_refused': [('    let adjusted = match entry {',
                          '    if object == 0 { return None; }\n    let adjusted = match entry {')],
 'require_both_candidates': [('    let selected = if selector as u32 == 1 {',
                              '    let _first = word(image, base, adjusted.wrapping_add(0xe590))?;\n'
                              '    let _second = word(image, base, adjusted.wrapping_add(0xec88))?;\n'
                              '    let selected = if selector as u32 == 1 {')],
 'require_selected_base': [('    let value = word(image, base, selected.wrapping_add(0x78))?;',
                            '    let _extra = word(image, base, selected)?;\n'
                            '    let value = word(image, base, selected.wrapping_add(0x78))?;')],
 'zero_result_refused': [('    Some(Registers {',
                          '    if value == 0 { return None; }\n    Some(Registers {')]}
ADMISSION_WITNESS_REQUIRED = ['default_from_alternative', 'narrow_object', 'saturating_field', 'missing_outer_first_adjustment', 'ignore_image_overflow', 'strict_image_end', 'strict_word_end', 'zero_object_refused', 'require_both_candidates', 'require_selected_base', 'zero_result_refused']


def mutate(original, patches):
    marker = '\n#[cfg(test)]\n'
    require(original.count(marker) == 1, 'one test module separator')
    value, tests = original.split(marker)
    for before, after in patches:
        require(value.count(before) == 1, 'production mutation selector is not unique')
        value = value.replace(before, after)
    return value + marker + tests


def compare(actual, expected, inputs):
    require(len(actual) == len(expected), 'native output framing differs')
    count = admitted_values = admission = refused_inputs = 0; first = None
    for i, (got, want) in enumerate(zip(struct.iter_unpack('<4Q', actual), struct.iter_unpack('<4Q', expected))):
        if got != want:
            count += 1; admission += got[0] != want[0]
            admitted_values += got[0] == want[0] == 1 and got[1:] != want[1:]
            refused_inputs += want[0] == 0
            if first is None:
                first = {'index':i,'descriptor':list(struct.unpack_from('<5Q',inputs,2088*i)),
                         'image_sha256':sha(inputs[2088*i+40:2088*(i+1)]),
                         'actual_registers':list(got),'expected_registers':list(want)}
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
    out.mkdir(parents=True); calls, streams = [], {}; rawdir = out / 'raw-checkpoints'; rawdir.mkdir()
    def archive():
        payloads = {}
        for item in streams.values():
            h = item['sha256']
            if h not in payloads:
                raw = gzip.decompress((rawdir / (h+'.gz')).read_bytes())
                require(sha(raw) == h and len(raw) == item['bytes'], 'checkpoint identity')
                payloads[h] = base64.b64encode(raw).decode()
        value = {'encoding':'base64','streams':{name:item['sha256'] for name,item in streams.items()},'payloads':payloads}
        path = out / 'raw-streams.json.gz'; path.write_bytes(gzip.compress(encoded(value),compresslevel=1,mtime=0))
        return path

    def run(label, argv, data=None, success=True):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, input=data, capture_output=True)
        logs = {}
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            name = label+'.'+suffix; h = sha(raw); path = rawdir / (h+'.gz')
            if not path.exists(): path.write_bytes(gzip.compress(raw,compresslevel=1,mtime=0))
            streams[name] = {'sha256':h,'bytes':len(raw)}
            logs[suffix] = {'file':name,'bytes':len(raw),'sha256':h}
        calls.append({'label':label,'argv':[str(v).replace(str(ROOT),'<repo>').replace(str(rustc),'<rustc>') for v in argv],
                      'exit_code':result.returncode,'stdin_sha256':None if data is None else sha(data),'logs':logs})
        # Each distinct raw stream is durably checkpointed before any assertion.
        # Only small metadata is rewritten; final consolidation occurs once.
        (out/'calls.json').write_bytes(encoded(calls)); (out/'stream-index.json').write_bytes(encoded(streams))
        if (result.returncode == 0) != success:
            archive(); raise ValueError(label+' failed; exact checkpoint/archive streams retained')
        return result

    try:
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
                                   '-Cmetadata=pointer_select94', *flags, '-o', library])
            run(name + '-client', [rustc, '--crate-name', 'pointer_select_client', SOURCE / 'input_only_driver.rs',
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
            for length in [1, 2089]:
                bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
                require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
            invalid = struct.pack('<5Q',0,0,0,0,2049) + bytes(2048)
            bad = run(label+'-invalid-length',[client],invalid,success=False)
            require(not bad.stdout and b'invalid image descriptor' in bad.stderr, 'invalid descriptor accepted')
            invalid_entry = struct.pack('<5Q',3,0,0,0,2048) + bytes(2048)
            bad = run(label+'-invalid-entry',[client],invalid_entry,success=False)
            require(not bad.stdout and b'invalid image descriptor' in bad.stderr, 'invalid entry accepted')
            profiles.append({'profile': label, 'cases': coverage['cases'], 'unit_tests_passed': 3, **comparison})
            for name, value in mutated.items():
                mutant = out / (name + '.rs'); mutant.write_text(value)
                _, _, wrong, _ = build(label + '-' + name, mutant, opt)
                mismatch = compare(wrong, expected, inputs)
                require(mismatch['mismatches'] > 0, 'surviving mutant: ' + name)
                if name not in ADMISSION_WITNESS_REQUIRED:
                    require(mismatch['admitted_value_cases'] > 0, 'no admitted value witness: ' + name)
                else:
                    require(mismatch['admission_cases'] > 0, 'no admission witness: ' + name)
                controls.append({'profile': label, 'mutation': name, 'source_sha256': sha(mutant.read_bytes()), **mismatch})
        require(compare(bytes([expected[0] ^ 1]) + expected[1:], expected, inputs)['mismatches'] == 1,
                'changed-output comparator control')
        try:
            compare(expected[:-32], expected, inputs)
        except ValueError:
            pass
        else:
            raise ValueError('missing row comparator control')
        require(before == {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}, 'source drift during run')
        require(sha(rustc.read_bytes()) == RUSTC_SHA and sha(linker.read_bytes()) == linker_sha, 'tool drift during run')
    except BaseException:
        archive()
        raise
    archive_file = archive()
    result = {'target_sha256': TARGET, 'source_sha256': before, 'compiler_sha256': RUSTC_SHA,
              'compiler_version': version, 'linker_sha256': linker_sha, 'linker_version': linker_version,
              'python': platform.python_version(), 'platform': platform.platform(), 'frozen': frozen,
              'profiles': profiles, 'repeated_builds': repeats, 'native_wrong_controls': controls,
              'comparator_controls': ['changed row detected', 'missing row rejected'],
              'raw_archive_sha256': sha(archive_file.read_bytes()), 'archive_parameters': {'compression':'gzip','level':1,'mtime':0,'checkpoint':'one content-addressed gzip per distinct raw stream; small index/call metadata updated before assertions; final lossless consolidation'}, 'captured_execution': False,
              'instruction_emulation': False, 'target_compiled_byte_identity': 'not measured; new host value component'}
    (out / 'results.json').write_bytes(encoded(result))
    print(json.dumps({'cases': coverage['cases'], 'profiles': profiles, 'wrong_controls_detected': len(controls),
                      'repeated_artifacts_equal': len(repeats)}))


if __name__ == '__main__':
    main()
