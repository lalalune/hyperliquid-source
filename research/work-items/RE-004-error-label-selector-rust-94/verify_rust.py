"""Qualify new native Rust against the independently frozen parity/interval relation."""
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

SOURCE = ROOT / 'src/node94-error-label-selector'
CRATE = 'node94_error_label_selector'
RUSTC_SHA = 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6'
COMMIT = 'e408947bfd200af42db322daf0fadfe7e26d3bd1'
MUTATIONS = {'omitted_xor': [('(value ^ 1) * 3 + 14', 'value * 3 + 14')],
 'wrong_xor_bit': [('(value ^ 1) * 3 + 14', '(value ^ 2) * 3 + 14')],
 'scale_two': [('(value ^ 1) * 3 + 14', '(value ^ 1) * 2 + 14')],
 'offset_thirteen': [('(value ^ 1) * 3 + 14', '(value ^ 1) * 3 + 13')],
 'omit_length_offset': [('(value ^ 1) * 3 + 14', '(value ^ 1) * 3')],
 'boolean_tag': [('u64::from(tag);', 'u64::from(tag != 0);')],
 'strip_tag_highbit': [('u64::from(tag);', 'u64::from(tag & 127);')],
 'signed_zero_selection': [('if value == 0 { first } else { second }',
                            'if (value as i8) <= 0 { first } else { second }')],
 'select_first_for_one': [('if value == 0 { first } else { second }',
                           'if value == 1 { first } else { second }')],
 'first_bias_saturates': [('load_bias.wrapping_add(0x21bf92)', 'load_bias.saturating_add(0x21bf92)')],
 'second_bias_saturates': [('load_bias.wrapping_add(0x21bfa3)', 'load_bias.saturating_add(0x21bfa3)')],
 'first_bias_narrowed': [('load_bias.wrapping_add(0x21bf92)',
                          'u64::from(load_bias as u32).wrapping_add(0x21bf92)')],
 'second_bias_narrowed': [('load_bias.wrapping_add(0x21bfa3)',
                           'u64::from(load_bias as u32).wrapping_add(0x21bfa3)')],
 'first_pointer_plus_one': [('load_bias.wrapping_add(0x21bf92)', 'load_bias.wrapping_add(0x21bf93)')],
 'second_pointer_plus_one': [('load_bias.wrapping_add(0x21bfa3)', 'load_bias.wrapping_add(0x21bfa4)')],
 'narrow_rax': [('rax: if value == 0 { first } else { second },',
                 'rax: u64::from((if value == 0 { first } else { second }) as u32),')],
 'narrow_length': [('rdx: length,', 'rdx: u64::from(length as u8),')],
 'signed_rcx': [('rcx: value,', 'rcx: (value as i8 as i64) as u64,')],
 'zero_rcx': [('rcx: value,', 'rcx: 0,')],
 'selected_rsi': [('rsi: second,', 'rsi: if value == 0 { first } else { second },')],
 'narrow_rsi': [('rsi: second,', 'rsi: u64::from(second as u32),')],
 'view_starts_at_first': [('let start = if tag == 0 { 0 } else { 17 };', 'let start = 0;')],
 'view_one_byte_early': [('let start = if tag == 0 { 0 } else { 17 };',
                          'let start = if tag == 0 { 0 } else { 16 };')],
 'view_only_literal': [('select(tag, 0).rdx as usize', 'select(tag, 0).rdx.min(14) as usize')],
 'view_drops_last': [('&window[start..start + length]', '&window[start..start + length - 1]')]}


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
    count = registers = views = 0; first = None
    for index in range(len(expected)//811):
        got, want = actual[811*index:811*(index+1)], expected[811*index:811*(index+1)]
        if got != want:
            count += 1; registers += got[:32] != want[:32]; views += got[32:] != want[32:]
            if first is None:
                first = {'index':index,'bias':int.from_bytes(inputs[805*index:805*index+8],'little'),
                         'tag':inputs[805*index+8], 'actual_registers':list(struct.unpack('<4Q',got[:32])),
                         'expected_registers':list(struct.unpack('<4Q',want[:32])),
                         'actual_view_sha256':sha(got[32:]),'expected_view_sha256':sha(want[32:])}
    return {'mismatches':count,'register_cases':registers,'byte_view_cases':views,
            'first_witness':first,'stdout_sha256':sha(actual)}


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
    require(all(frozen[k] == v for k, v in json.loads(encoded(coverage)).items()), 'frozen metadata drift')
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
                                   '-Cmetadata=error_label_selector94', *flags, '-o', library])
            run(name + '-client', [rustc, '--crate-name', 'error_label_selector_client', SOURCE / 'input_only_driver.rs',
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
            for length in [1, 804, 806]:
                bad = run(label + f'-partial-{length}', [client], b'\0' * length, success=False)
                require(not bad.stdout and b'partial input record' in bad.stderr, 'partial record emitted output')
            profiles.append({'profile': label, 'cases': coverage['cases'], 'unit_tests_passed': 3, **comparison})
            for name, value in mutated.items():
                mutant = out / (name + '.rs'); mutant.write_text(value)
                _, _, wrong, _ = build(label + '-' + name, mutant, opt)
                mismatch = compare(wrong, expected, inputs)
                require(mismatch['mismatches'] > 0, 'surviving mutant: ' + name)
                require(mismatch['register_cases'] + mismatch['byte_view_cases'] > 0, 'no observable value witness: ' + name)
                controls.append({'profile': label, 'mutation': name, 'source_sha256': sha(mutant.read_bytes()), **mismatch})
        require(compare(bytes([expected[0] ^ 1]) + expected[1:], expected, inputs)['mismatches'] == 1,
                'changed-output comparator control')
        try:
            compare(expected[:-811], expected, inputs)
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
