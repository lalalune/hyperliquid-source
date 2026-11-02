"""Compile only new Rust and compare to independently frozen byte exchange values and explicit atomic-IR controls."""
import argparse
import re
import base64
import gzip
import json
from pathlib import Path
import struct
import subprocess
import sys
from oracle import PACKET, ROOT, corpus, fixtures, require, sha

SOURCE = ROOT / 'src/node94-tag-exchange'
MUTATIONS = {'zero_stores_one': ('0 => 0,', '0 => 1,'), 'two_stores_one': ('2 => 2,', '2 => 1,'), 'other_stores_two': ('_ => 1,', '_ => 2,'), 'low_two_tag_bits': ('tag_bits as u8 {', '(tag_bits as u8 & 3) {'), 'low_seven_tag_bits': ('tag_bits as u8 {', '(tag_bits as u8 & 127) {'), 'full_tag_gate': ('match tag_bits as u8 {', 'match tag_bits {'), 'low32_tag_gate': ('match tag_bits as u8 {', 'match tag_bits as u32 {'), 'store_raw_tag': ('cell.swap(value, Ordering::SeqCst)', 'cell.swap(value.wrapping_mul(0).wrapping_add(tag_bits as u8), Ordering::SeqCst)'), 'fetch_or_not_exchange': ('cell.swap(value, Ordering::SeqCst)', 'cell.fetch_or(value, Ordering::SeqCst)'), 'return_stored_value': ('rax: u64::from(old)', 'rax: u64::from(value) + u64::from(old)*0'), 'return_boolean_old': ('rax: u64::from(old)', 'rax: u64::from(old!=0)'), 'return_signed_old': ('rax: u64::from(old)', 'rax: old as i8 as i64 as u64'), 'return_low_seven_old': ('rax: u64::from(old)', 'rax: u64::from(old & 127)'), 'rcx_not_cleared': ('rcx: 0,', 'rcx: 1,'), 'wrong_field_offset': ('object.wrapping_add(16)', 'object.wrapping_add(15)'), 'saturating_field': ('object.wrapping_add(16)', 'object.saturating_add(16)'), 'low32_field': ('object.wrapping_add(16)', 'u64::from((object as u32).wrapping_add(16))')}

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
    words, truth = corpus(), list(struct.iter_unpack('<4Q', expected))
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
        rows = list(struct.iter_unpack('<4Q', raw))
        mismatches = [i for i, (got, want) in enumerate(zip(rows, truth)) if got != want]
        first = None
        if mismatches:
            i = mismatches[0]
            first = {'input_descriptor': list(words[i]), 'expected': dict(zip(('rax','rcx','field_address','stored'),truth[i])), 'actual': dict(zip(('rax','rcx','field_address','stored'),rows[i]))}
        return {'mismatches': len(mismatches), 'first_mismatch': first, 'output_sha256': sha(raw)}
    def build(source, name, opt):
        directory = out / name; directory.mkdir()
        artifact, executable = directory / 'libnode94_tag_exchange.rlib', directory / 'client'
        specific = [*flags, '-C', 'panic=abort', '-C', 'opt-level=' + str(opt)]
        run([rustc, *specific, '--crate-name', 'node94_tag_exchange', '--crate-type', 'rlib', source, '-o', artifact], name + '-library')
        run([rustc, *specific, '--extern', 'node94_tag_exchange=' + str(artifact), SOURCE / 'input_only_driver.rs', '-o', executable], name + '-client')
        raw = run([executable], name + '-run', inputs).stdout
        return executable, {**compare(raw), 'rlib_sha256': sha(artifact.read_bytes()), 'client_sha256': sha(executable.read_bytes())}
    def atomic_ir(source, name):
        path=out/(name+'.ll')
        run([rustc,*flags,'-C','panic=abort','-C','opt-level=3','-C','link-dead-code=yes',
             '--crate-name','node94_tag_exchange','--crate-type','rlib','--emit','llvm-ir',source,'-o',path],name+'-emit')
        raw=path.read_bytes();streams[path.name]=raw
        return raw
    def check_ir(raw):
        text=raw.decode();lines=[line.strip() for line in text.splitlines() if 'atomicrmw ' in line]
        require(len(lines)==1 and re.search(r'atomicrmw xchg ptr .*?, i8 .*? seq_cst, align 1$',lines[0]),'one byte SeqCst atomic exchange')
        require(not any(x in text for x in ('load atomic','store atomic','cmpxchg ')),'no separate or extra atomic access')
        return lines[0]
    original_ir=atomic_ir(SOURCE/'lib.rs','correct-atomic-ir')
    atomic_contract={'correct_ir_sha256':sha(original_ir),'instruction':check_ir(original_ir),'controls':{}}
    builds = {}
    for opt in (0, 3):
        name = 'opt' + str(opt)
        executable, record = build(SOURCE / 'lib.rs', name, opt)
        require(record['mismatches'] == 0, name + ' native mismatch')
        _, repeat = build(SOURCE / 'lib.rs', name + '-repeat', opt)
        require(record == repeat, name + ' repeated results differ')
        bad = run([executable], name + '-partial', b'\0' * 17, success=False)
        require(not bad.stdout and b'partial tag-exchange input' in bad.stderr, 'malformed input must reject before output')
        invalid = run([executable],name+'-descriptor',struct.pack('<3Q',0,0,256),success=False)
        require(not invalid.stdout and b'invalid tag-exchange descriptor' in invalid.stderr,'invalid descriptor before output')
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
    for name,replacement in {
        'weakened_order':'cell.swap(value, Ordering::Relaxed)',
        'split_atomic_load_store':'{ let previous=cell.load(Ordering::SeqCst); cell.store(value, Ordering::SeqCst); previous }',
    }.items():
        require(original.count('cell.swap(value, Ordering::SeqCst)')==1,'unambiguous atomic control')
        path=out/(name+'.rs');path.write_text(original.replace('cell.swap(value, Ordering::SeqCst)',replacement))
        _,record=build(path,name,3)
        require(record['mismatches']==0,'isolated fixtures do not qualify atomicity/ordering')
        raw=atomic_ir(path,name+'-ir')
        try:check_ir(raw)
        except ValueError as e:atomic_contract['controls'][name]={'ir_rejection':str(e),'ir_sha256':sha(raw),'isolated_value_mismatches':record['mismatches'],'build':record}
        else:raise ValueError('atomic IR control survived '+name)
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
              'rustc': version, 'host': host, 'builds': builds, 'native_mutants': mutants,'atomic_ir_contract':atomic_contract,
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
