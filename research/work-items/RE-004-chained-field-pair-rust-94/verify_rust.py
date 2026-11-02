"""Compile only new Rust and compare to independently frozen chained reads and final-image expectations."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
from oracle import PACKET, ROOT, corpus, fixtures, require, sha

SOURCE = ROOT / 'src/node94-chained-field-pair'
MUTATIONS = {'zero_extend_signed': (' as i32 as i64 as u64', ' as u64'), 'wrong_first_field': ('object.wrapping_add(0x788)', 'object.wrapping_add(0x780)'), 'wrong_second_field': ('first.wrapping_add(0x30)', 'first.wrapping_add(0x38)'), 'wrong_signed_field': ('second.wrapping_add(0xb30)', 'second.wrapping_add(0xb31)'), 'wrong_wide_field': ('second.wrapping_add(0x1008)', 'second.wrapping_add(0x1000)'), 'saturate_first_address': ('object.wrapping_add(0x788)', 'object.saturating_add(0x788)'), 'saturate_second_address': ('first.wrapping_add(0x30)', 'first.saturating_add(0x30)'), 'saturate_value_address': ('second.wrapping_add(0xb30)', 'second.saturating_add(0xb30)'), 'big_endian_pointer': ('u64::from_le_bytes', 'u64::from_be_bytes'), 'big_endian_signed': ('u32::from_le_bytes', 'u32::from_be_bytes'), 'big_endian_store': ('image[destination].copy_from_slice(&value.to_le_bytes());', 'image[destination].copy_from_slice(&value.to_be_bytes());'), 'narrow_store': ('image[destination].copy_from_slice(&value.to_le_bytes());', 'image[destination.start..destination.start+4].copy_from_slice(&(value as u32).to_le_bytes());'), 'omit_store': ('image[destination].copy_from_slice(&value.to_le_bytes());', 'let _ = (destination,value);'), 'return_stored_value': ('    Ok(1)\n}', '    Ok(value)\n}'), 'return_zero': ('    Ok(1)\n}', '    Ok(0)\n}'), 'strict_endpoint': ('(end <= image.len())', '(end < image.len())'), 'early_output_check': ('    let first =', '    let _ = span(image, image_base, output, 8).ok_or(AccessError::Output)?;\n    let first =')}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    args = parser.parse_args()
    out, rustc = args.out.resolve(), args.rustc.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, streams = [], {}
    def run(argv, label, data=None, success=True):
        argv = [str(x) for x in argv]
        result = subprocess.run(argv, cwd=ROOT, input=data, capture_output=True)
        for suffix, raw in [('stdout', result.stdout), ('stderr', result.stderr)]:
            name = label + '.' + suffix
            (out / name).write_bytes(raw)
            streams[name] = raw
        commands.append({'argv': [x.replace(str(ROOT), '<repo>').replace(str(rustc), '<rustc>') for x in argv],
                         'label': label, 'returncode': result.returncode,
                         'stdin_sha256': None if data is None else sha(data),
                         'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require((result.returncode == 0) == success, label + ' status; inspect retained raw streams')
        return result
    run([sys.executable, '-O', '-B', PACKET / 'verify_static.py'], 'static')
    frozen = json.loads((PACKET / 'frozen.json').read_text())
    require(sha((PACKET / 'oracle.py').read_bytes()) == frozen['oracle_sha256_at_freeze'], 'pre-Rust oracle drift')
    inputs, expected, record = fixtures()
    require(all(frozen[k] == v for k, v in record.items()), 'frozen metadata drift')
    for name, raw in [('inputs', inputs), ('expected', expected)]:
        require(gzip.decompress((PACKET / (name + '.bin.gz')).read_bytes()) == raw, 'frozen stream drift')
    words, truth = corpus(), list(struct.iter_unpack('<BQ256s', expected))
    version = run([rustc, '-vV'], 'rustc-version').stdout.decode()
    require('release: 1.94.1\n' in version and
            'commit-hash: e408947bfd200af42db322daf0fadfe7e26d3bd1\n' in version, 'compiler version/commit')
    compiler_hash = sha(rustc.read_bytes())
    require(compiler_hash == 'b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6', 'actual compiler pin')
    linker_version = run(['/usr/bin/cc', '--version'], 'linker-version').stdout.decode()
    host = next(line.split(': ', 1)[1] for line in version.splitlines() if line.startswith('host: '))
    flags = ['--edition=2024', '--target', host, '-D', 'warnings', '-C', 'codegen-units=1',
             '-C', 'overflow-checks=yes', '-C', 'linker=/usr/bin/cc', '--remap-path-prefix', str(ROOT) + '=/source']
    def compare(raw):
        require(len(raw) == len(expected), 'native framing')
        rows = list(struct.iter_unpack('<BQ256s', raw))
        mismatches = [i for i, (got, want) in enumerate(zip(rows, truth)) if got != want]
        first = None
        if mismatches:
            i = mismatches[0]
            first = {'input_descriptor': list(words[i][:5])+[words[i][5].hex()], 'expected': {'tag':truth[i][0],'rax':truth[i][1],'image_hex':truth[i][2].hex()}, 'actual': {'tag':rows[i][0],'rax':rows[i][1],'image_hex':rows[i][2].hex()}}
        return {'mismatches': len(mismatches), 'original_normal_return_mismatches':sum(truth[i][0]==0 for i in mismatches), 'first_mismatch': first, 'output_sha256': sha(raw)}
    def build(source, name, opt):
        directory = out / name; directory.mkdir()
        artifact, executable = directory / 'libnode94_chained_field_pair.rlib', directory / 'client'
        specific = [*flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(opt)]
        run([rustc, *specific, '--crate-name', 'node94_chained_field_pair', '--crate-type', 'rlib', source, '-o', artifact], name + '-library')
        run([rustc, *specific, '--extern', 'node94_chained_field_pair=' + str(artifact), SOURCE / 'input_only_driver.rs', '-o', executable], name + '-client')
        raw = run([executable], name + '-run', inputs).stdout
        return executable, {**compare(raw), 'rlib_sha256': sha(artifact.read_bytes()), 'client_sha256': sha(executable.read_bytes())}
    builds = {}
    for opt in (0, 3):
        name = 'opt' + str(opt)
        executable, record = build(SOURCE / 'lib.rs', name, opt)
        require(record['mismatches'] == 0, name + ' native mismatch')
        _, repeat = build(SOURCE / 'lib.rs', name + '-repeat', opt)
        require(record == repeat, name + ' repeated results differ')
        bad = run([executable], name + '-partial', b'\0' * 17, success=False)
        require(not bad.stdout and b'partial chained-field input' in bad.stderr, 'malformed input must reject before output')
        bad_descriptor = run([executable], name + '-descriptor', b'\x02'+b'\0'*282, success=False)
        require(not bad_descriptor.stdout and b'invalid chained-field descriptor' in bad_descriptor.stderr,'invalid descriptor framing')
        test = out / (name + '-tests')
        run([rustc, *flags, '-C', 'opt-level=' + str(opt), '--test', SOURCE / 'lib.rs', '-o', test], name + '-test-build')
        result = run([test], name + '-test-run')
        require(b'3 passed; 0 failed' in result.stdout, 'unit tests did not run')
        builds[name] = record
    original = (SOURCE / 'lib.rs').read_text()
    mutants = {}
    for name, (before, after) in MUTATIONS.items():
        require(original.count(before) == 1, 'ambiguous mutation: ' + name)
        path = out / (name + '.rs'); path.write_text(original.replace(before, after))
        _, record = build(path, name, 3)
        require(record['mismatches'] > 0, 'surviving mutant: ' + name)
        mutants[name] = {**record, 'source_sha256': sha(path.read_bytes())}
    require(compare(bytes([expected[0] ^ 1]) + expected[1:])['mismatches'] == 1, 'changed row comparator')
    try:
        compare(expected[:-1])
    except ValueError:
        pass
    else:
        raise ValueError('missing output accepted')
    archive = {'streams': {name: sha(raw) for name, raw in streams.items()},
               'payloads': {sha(raw): base64.b64encode(raw).decode() for raw in streams.values()}}
    (out / 'streams.json.gz').write_bytes(gzip.compress((json.dumps(archive, sort_keys=True) + '\n').encode(), mtime=0))
    decoded = json.loads(gzip.decompress((out / 'streams.json.gz').read_bytes()))
    require(all(base64.b64decode(decoded['payloads'][decoded['streams'][name]], validate=True) == raw for name, raw in streams.items()), 'archive equality')
    result = {'target_sha256': json.loads((PACKET / 'static.json').read_text())['target_sha256'],
              'static_sha256': sha((PACKET / 'static.json').read_bytes()), 'oracle': frozen,
              'compiler_sha256': compiler_hash, 'linker_sha256': sha(Path('/usr/bin/cc').read_bytes()), 'linker_version': linker_version,
              'rust_sources': {x: sha((SOURCE / x).read_bytes()) for x in ('lib.rs', 'input_only_driver.rs')},
              'verification_sources': {x: sha((PACKET / x).read_bytes()) for x in ('oracle.py', 'verify_static.py', 'verify_rust.py')},
              'rustc': version, 'host': host, 'builds': builds, 'native_mutants': mutants,
              'raw_two_builds_equal_each_optimization': True, 'unit_tests_per_optimization': 3,
              'streams': {name: {'raw_bytes': len(raw), 'raw_sha256': sha(raw)} for name, raw in streams.items()},
              'comparator_controls': ['one changed row detected', 'missing byte rejected'],
              'captured_code_executed': False, 'instruction_emulation': False,
              'compiled_target_byte_comparison': 'not measured; host scalar value projection only'}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': len(words), 'builds': builds, 'mutants': {k: v['mismatches'] for k, v in mutants.items()}}, indent=2))


if __name__ == '__main__':
    main()
