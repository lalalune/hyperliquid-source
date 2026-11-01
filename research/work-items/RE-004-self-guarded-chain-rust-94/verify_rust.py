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

SOURCE = ROOT / 'src/node94-self-guarded-chain'
CRATE = 'node94_self_guarded_chain'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'wrong_entry_field': [('object.wrapping_add(8)', 'object.wrapping_add(16)')],
 'entry_address_saturates': [('object.wrapping_add(8)', 'object.saturating_add(8)')],
 'narrow_object': [('object.wrapping_add(8)', 'u64::from(object as u32).wrapping_add(8)')],
 'narrow_guard': [('observed == pointer', 'observed as u32 == pointer as u32')],
 'inverted_guard': [('observed == pointer', 'observed != pointer')],
 'null_guard': [('observed == pointer', 'pointer == 0 && observed == observed')],
 'always_self': [('observed == pointer', 'observed == pointer || true')],
 'always_chain': [('observed == pointer', 'observed == pointer && false')],
 'zero_sentinel': [('        u64::MAX', '        0')],
 'narrow_sentinel': [('        u64::MAX', '        u64::from(u32::MAX)')],
 'eager_tail': [('let observed = word(image, image_base, pointer)?;',
                 'let observed = word(image, image_base, pointer)?;\n'
                 '    let _eager = word(image, image_base, pointer.wrapping_add(8))?;')],
 'wrong_next_field': [('pointer.wrapping_add(8)', 'pointer.wrapping_add(16)')],
 'wrong_middle_field': [('next.wrapping_add(16)', 'next.wrapping_add(8)')],
 'wrong_deep_field': [('field.wrapping_add(0xcb8)', 'field.wrapping_add(0xcc0)')],
 'middle_address_saturates': [('next.wrapping_add(16)', 'next.saturating_add(16)')],
 'deep_address_saturates': [('field.wrapping_add(0xcb8)', 'field.saturating_add(0xcb8)')],
 'word_byte_order': [('u64::from_le_bytes', 'u64::from_be_bytes')],
 'null_refused': [('let observed = word(image, image_base, pointer)?;',
                   'if pointer == 0 { return None; }\n'
                   '    let observed = word(image, image_base, pointer)?;')],
 'guard_value_in_rax': [('rax: value,', 'rax: observed,')],
 'pointer_in_rdx': [('rdx: value,', 'rdx: pointer,')],
 'narrow_rax': [('rax: value,', 'rax: u64::from(value as u32),')],
 'narrow_rdx': [('rdx: value,', 'rdx: u64::from(value as u32),')],
 'refuse_allones_result': [('    Some(Registers {',
                            '    if value == u64::MAX { return None; }\n    Some(Registers {')],
 'ignore_image_overflow': [('image.len() as u128 > (1u128 << 64)',
                            'image.len() as u128 > (1u128 << 64) && false')],
 'strict_image_end': [('image.len() as u128 > (1u128 << 64)', 'image.len() as u128 >= (1u128 << 64)')],
 'strict_word_end': [('let end = start.checked_add(8)?;',
                      'let end = start.checked_add(8)?;\n    if end == image.len() { return None; }')]}
ADMISSION_ONLY = ['wrong_entry_field', 'entry_address_saturates', 'narrow_object', 'eager_tail', 'wrong_next_field', 'wrong_middle_field', 'middle_address_saturates', 'deep_address_saturates', 'word_byte_order', 'null_refused', 'refuse_allones_result', 'ignore_image_overflow', 'strict_image_end', 'strict_word_end']

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
    for i, (got, want) in enumerate(zip(struct.iter_unpack('<3Q', actual), struct.iter_unpack('<3Q', expected))):
        if got != want:
            count += 1; admission += got[0] != want[0]
            admitted_values += got[0] == want[0] == 1 and got[1:] != want[1:]
            refused_inputs += want[0] == 0
            if first is None:
                first = {'index':i,'descriptor':list(struct.unpack_from('<3Q',inputs,152*i)),
                         'image_hex':inputs[152*i+24:152*(i+1)].hex(),
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
                                   '-Cmetadata=self_guarded_chain94', *flags, '-o', library])
            run(name + '-client', [rustc, '--crate-name', 'self_guarded_chain_client', SOURCE / 'input_only_driver.rs',
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
            for length in [1, 153]:
                bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
                require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
            invalid = struct.pack('<3Q',0,0,129) + bytes(128)
            bad = run(label+'-invalid-length',[client],invalid,success=False)
            require(not bad.stdout and b'invalid image descriptor' in bad.stderr, 'invalid descriptor accepted')
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
            compare(expected[:-24], expected, inputs)
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
