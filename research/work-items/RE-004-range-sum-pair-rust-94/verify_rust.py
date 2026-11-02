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

SOURCE = ROOT / 'src/node94-range-sum-pair'
MUTATIONS = {'wrong_object_field': ('object.wrapping_add(0x788)', 'object.wrapping_add(0x790)'), 'wrong_container_field': ('first.wrapping_add(0x30)', 'first.wrapping_add(0x38)'), 'wrong_begin_field': ('container.wrapping_add(0xb18)', 'container.wrapping_add(0xb10)'), 'wrong_end_field': ('container.wrapping_add(0xb20)', 'container.wrapping_add(0xb18)'), 'stride8': ('cursor = cursor.wrapping_add(16);', 'cursor = cursor.wrapping_add(8);'), 'no_advance': ('cursor = cursor.wrapping_add(16);', 'cursor = cursor.wrapping_add(0);'), 'wrong_count_divisor': ('let count = distance / 16;', 'let count = distance / 8;'), 'ignore_endpoint_residue': ('if distance & 15 != 0 {', 'if distance & 15 != 0 && image.is_empty() {'), 'single_entry_only': ('let count = distance / 16;', 'let count = (distance / 16).min(1);'), 'reject_wrapped_terminal': ('let distance = end.wrapping_sub(begin);', 'if end < begin { return None; } let distance = end.wrapping_sub(begin);'), 'skip_first_entry': ('let mut cursor = begin;', 'let mut cursor = begin.wrapping_add(16);'), 'require_second_qword': ('let slot = word(image, base, cursor)?;', 'let slot = word(image, base, cursor)?; word(image, base, cursor.wrapping_add(8))?;'), 'skip_discarded_helper': ('let helper = word(image, base, argument.wrapping_add(16))?.wrapping_add(62);', 'let helper = if member == Member::SlotFieldSum {0} else {word(image, base, argument.wrapping_add(16))?.wrapping_add(62)};'), 'wrong_helper_offset': ('argument.wrapping_add(16)', 'argument.wrapping_add(24)'), 'wrong_helper_addend': ('?.wrapping_add(62);', '?.wrapping_add(61);'), 'wrong_slot_field': ('slot.wrapping_add(80)', 'slot.wrapping_add(88)'), 'field_uses_helper_return': ('Member::SlotFieldSum => word(image, base, slot.wrapping_add(80))?,', 'Member::SlotFieldSum => helper,'), 'helper_uses_slot_field': ('Member::HelperSum => helper,', 'Member::HelperSum => helper.wrapping_mul(0).wrapping_add(word(image, base, slot.wrapping_add(80))?),'), 'subtract_contributions': ('total = total.wrapping_add(contribution);', 'total = total.wrapping_sub(contribution);'), 'truncate_contribution': ('total = total.wrapping_add(contribution);', 'total = total.wrapping_add(u64::from(contribution as u32));'), 'empty_rdi_zero': ('let mut last_argument = object;', 'let mut last_argument = object.wrapping_mul(0);'), 'rdi_slot_pointer': ('last_argument = argument;', 'last_argument = slot;'), 'rsi_object': ('rsi: destination,', 'rsi: object,'), 'rax_total': ('    Some(Registers {\n        rax: 1,', '    Some(Registers {\n        rax: total,'), 'rdx_truncated': ('rdx: incoming_rdx,', 'rdx: u64::from(incoming_rdx as u32),'), 'big_endian_reads': ('u64::from_le_bytes(image[start..start + 8].try_into().ok()?)', 'u64::from_be_bytes(image[start..start + 8].try_into().ok()?)'), 'big_endian_store': ('copy_from_slice(&total.to_le_bytes())', 'copy_from_slice(&total.to_be_bytes())'), 'narrow_store': ('image[output..output + 8].copy_from_slice(&total.to_le_bytes());', 'image[output..output + 4].copy_from_slice(&(total as u32).to_le_bytes());'), 'early_zero_output': ('let first = word(image, base, object.wrapping_add(0x788))?;', 'image[output..output + 8].fill(0); let first = word(image, base, object.wrapping_add(0x788))?;'), 'reject_wrapped_object': ('object.wrapping_add(0x788)', 'object.checked_add(0x788)?'), 'strict_endpoint': ('<= image.len()', '< image.len()'), 'ignore_image_overflow': ('> (1u128 << 64) {', '> (1u128 << 64) && image.is_empty() {')}

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
            (out / (name+'.gz')).write_bytes(gzip.compress(raw,compresslevel=1,mtime=0))
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
    words, truth = corpus(), [expected[i:i+808] for i in range(0,len(expected),808)]
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
        rows=[raw[i:i+808] for i in range(0,len(raw),808)]
        mismatches=[i for i,(got,want) in enumerate(zip(rows,truth)) if got!=want]
        first=None
        if mismatches:
            i=mismatches[0];first={'input_descriptor':list(words[i][:-1])+[words[i][-1].hex()],'expected':truth[i].hex(),'actual':rows[i].hex()}
        return {'mismatches':len(mismatches),'first_mismatch':first,'output_sha256':sha(raw)}
    def build(source, name, opt):
        directory = out / name; directory.mkdir()
        artifact, executable = directory / 'libnode94_range_sum_pair.rlib', directory / 'client'
        specific = [*flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(opt)]
        run([rustc, *specific, '--crate-name', 'node94_range_sum_pair', '--crate-type', 'rlib', source, '-o', artifact], name + '-library')
        run([rustc, *specific, '--extern', 'node94_range_sum_pair=' + str(artifact), SOURCE / 'input_only_driver.rs', '-o', executable], name + '-client')
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
        require(not bad.stdout and b'partial range-sum-pair input' in bad.stderr, 'malformed input must reject before output')
        invalid = run([executable],name+'-descriptor',struct.pack('<6Q',2,0,0,0,0,768)+bytes(768),success=False)
        require(not invalid.stdout and b'invalid range-sum-pair descriptor' in invalid.stderr,'invalid descriptor before output')
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
