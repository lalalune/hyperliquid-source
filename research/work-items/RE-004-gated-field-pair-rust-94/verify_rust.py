"""Compile only new Rust and compare to the independently frozen immutable-image relations."""
import argparse
import base64
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
from oracle import PACKET, ROOT, corpus, fixtures, require, sha

SOURCE = ROOT / 'src/node94-gated-field-pair'
MUTATIONS = {'wrong_gate_offset': ('object.wrapping_add(184)', 'object.wrapping_add(183)'), 'gate_only_one': ('Some(image[field.start] != 0)', 'Some(image[field.start] == 1)'), 'gate_inverted': ('Some(image[field.start] != 0)', 'Some(image[field.start] == 0)'), 'wrong_pointer_offset': ('object.wrapping_add(728)', 'object.wrapping_add(720)'), 'null_gate_eager': ('if pointer == 0 || !enabled(image, image_base, object)? {', 'if !enabled(image, image_base, object)? || pointer == 0 {'), 'null_gate_and': ('if pointer == 0 || !enabled(image, image_base, object)? {', 'if pointer == 0 && !enabled(image, image_base, object)? {'), 'wrong_first_source': ('pointer.wrapping_add(32)', 'pointer.wrapping_add(24)'), 'wrong_last_source': ('pointer.wrapping_add(96)', 'pointer.wrapping_add(88)'), 'skip_pointer_chase': ('let first = word(image, image_base, pointer.wrapping_add(32))?;', 'let first = word(image, image_base, object.wrapping_add(32))?;'), 'wrong_first_destination': ('let first_destination = span(image, image_base, external.wrapping_add(16), 8)?;', 'let first_destination = span(image, image_base, external.wrapping_add(8), 8)?;'), 'wrong_last_destination': ('let last_destination = span(image, image_base, external.wrapping_add(24), 8)?;', 'let last_destination = span(image, image_base, external.wrapping_add(32), 8)?;'), 'first_store_big_endian': ('image[first_destination].copy_from_slice(&first.to_le_bytes());', 'image[first_destination].copy_from_slice(&first.to_be_bytes());'), 'last_store_first': ('image[last_destination].copy_from_slice(&last.to_le_bytes());', 'image[last_destination].copy_from_slice(&first.to_le_bytes());'), 'copyout_boolean_rax': ('rax: last,', 'rax: u64::from(last != 0),'), 'closed_rax_entry': ('rax: pointer,', 'rax: incoming.rax,'), 'closed_rdx_zero': ('rdx: incoming.rdx,', 'rdx: 0,'), 'copyout_preserve_rdx': ('rdx: first,', 'rdx: incoming.rdx,'), 'copyin_eager_pointer': ('Member::CopyIn => {', 'Member::CopyIn => {\n            let _ = word(image,image_base,object.wrapping_add(728))?;'), 'copyin_eager_source': ('Member::CopyIn => {', 'Member::CopyIn => {\n            let _ = word(image,image_base,external.wrapping_add(16))?;'), 'copyin_wrong_destination': ('object.wrapping_add(696)', 'object.wrapping_add(704)'), 'copyin_duplicate_low': ('value[8..].copy_from_slice(&high.to_le_bytes());', 'value[8..].copy_from_slice(&(low | high.wrapping_mul(0)).to_le_bytes());'), 'copyin_closed_rax_zero': ('return Some(incoming);', 'return Some(Registers { rax: 0, rdx: incoming.rdx });'), 'word_big_endian': ('u64::from_le_bytes(', 'u64::from_be_bytes('), 'strict_image_end': ('(end <= image.len())', '(end < image.len())'), 'pointer_field_wrap_refused': ('object.wrapping_add(728)', 'object.checked_add(728)?'), 'gate_field_wrap_refused': ('object.wrapping_add(184)', 'object.checked_add(184)?'), 'early_copyout_store': ('let last = word(image, image_base, pointer.wrapping_add(96))?;', 'let early = span(image,image_base,external.wrapping_add(16),8)?;\n            image[early].copy_from_slice(&first.to_le_bytes());\n            let last = word(image, image_base, pointer.wrapping_add(96))?;'), 'copyin_truncated_low': ('value[..8].copy_from_slice(&low.to_le_bytes());', 'value[..8].copy_from_slice(&(low & 0xffff_ffff).to_le_bytes());')}

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
    words, truth = corpus(), [expected[i:i+824] for i in range(0,len(expected),824)]
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
        require(len(raw)==len(expected),'native framing')
        rows=[raw[i:i+824] for i in range(0,len(raw),824)]
        mismatches=[i for i,(got,want) in enumerate(zip(rows,truth)) if got!=want]
        first=None
        if mismatches:
            i=mismatches[0];first={'input_descriptor':list(words[i][:-1])+[words[i][-1].hex()],'expected':truth[i].hex(),'actual':rows[i].hex()}
        return {'mismatches':len(mismatches),'first_mismatch':first,'output_sha256':sha(raw)}
    def build(source, name, opt):
        directory = out / name; directory.mkdir()
        artifact, executable = directory / 'libnode94_gated_field_pair.rlib', directory / 'client'
        specific = [*flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(opt)]
        run([rustc, *specific, '--crate-name', 'node94_gated_field_pair', '--crate-type', 'rlib', source, '-o', artifact], name + '-library')
        run([rustc, *specific, '--extern', 'node94_gated_field_pair=' + str(artifact), SOURCE / 'input_only_driver.rs', '-o', executable], name + '-client')
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
        require(not bad.stdout and b'partial gated-field-pair input' in bad.stderr, 'malformed input must reject before output')
        invalid = run([executable],name+'-descriptor',struct.pack('<7Q',2,0,0,0,0,0,800)+bytes(800),success=False)
        require(not invalid.stdout and b'invalid gated-field-pair descriptor' in invalid.stderr,'invalid descriptor before output')
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
    (out / 'streams.json.gz').write_bytes(gzip.compress((json.dumps(archive, sort_keys=True) + '\n').encode(), compresslevel=1, mtime=0))
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
              'archive_compression': {'format':'gzip','level':1,'mtime':0},
              'captured_code_executed': False, 'instruction_emulation': False,
              'compiled_target_byte_comparison': 'not measured; host scalar value projection only'}
    (out / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'cases': len(words), 'builds': builds, 'mutants': {k: v['mismatches'] for k, v in mutants.items()}}, indent=2))


if __name__ == '__main__':
    main()
