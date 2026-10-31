#!/usr/bin/env python3
"""Build our no_std byte-request protocol against authenticated native contracts.

Captured node bytes are read/disassembled only. Newly authored Rust and its
normal scripted callbacks execute. The protocol transcript is not rendering,
an original ABI/vtable, a memory trace or a full diagnostic formatter.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import bincode_diagnostic_field_static as original

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/node/94/hl-node'
COMPONENT = ROOT/'src/node94-newline-writer-protocol'
SOURCE = COMPONENT/'lib.rs'
DRIVER = COMPONENT/'test_driver.rs'
FIXTURE = COMPONENT/'target-transcripts.tsv'
CRATE = 'node94_newline_writer_protocol'
ORIGINAL_HEAD = '03fe0523bd86a74435d0606e70c6018950b930b1'
COMPILER_SHA256 = 'ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            h.update(raw)
    return h.hexdigest()


def cases():
    """Byte boundaries plus independent normal-callback stimuli, not answers."""
    examples = {b'', b'\n', b'\n\n', b'a\nb', b'    ', b'    \n    ',
                b'\x00\xff\x80\r\na\n\n\xff', b'\r', b'\r\n'}
    for length in (0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65):
        raw = bytes((index*71+128) & 255 for index in range(length))
        raw = raw.replace(b'\n', b'\xff')
        examples.add(raw)
        for position in {0, max(0, length-1), min(length-1, 7), min(length-1, 8), min(length-1, 15), min(length-1, 16)}:
            if length:
                examples.add(raw[:position]+b'\n'+raw[position+1:])
    values = set()
    def add(raw, flag, actions=(), default=(0, None)):
        values.add((raw, flag, tuple(actions), default))
    for raw in examples:
        for flag in (0, 1, 2, 128, 255):
            add(raw, flag)
    for value in range(256):
        for flag in (0, 2, 255):
            add(bytes([value]), flag)
        add(b'\na\nb', value, ((0, 0), (0, 255), (0, 0), (0, 128)))
    for raw in (b'', b'\n', b'\n\n', b'a\nb', b'    ', b'    \n    ', b'a\nb\nc'):
        for flag in (0, 2, 255):
            for mutation in (None, 0, 1, 2, 128, 255):
                add(raw, flag, ((0, mutation), (0, 0), (0, 255), (0, 2), (0, 128), (0, None)))
            for index in range(6):
                for result in (1, 2, 128, 255):
                    for mutation in (None, 0, 255):
                        add(raw, flag, tuple([(0, None)]*index+[(result, mutation)]))
    def key(row):
        raw, flag, actions, default = row
        normalize = lambda a: (a[0], -1 if a[1] is None else a[1])
        return raw, flag, tuple(map(normalize, actions)), normalize(default)
    return sorted(values, key=key)


def encode_action(action):
    result, mutation = action
    return f'{result}:{"-" if mutation is None else mutation}'


def stimulus_line(index, case):
    raw, flag, actions, default = case
    return f'c{index:04d}|{raw.hex()}|{flag}|{",".join(map(encode_action, actions))}|{encode_action(default)}'


def transcript(index, case, facts):
    """Abstract target-derived request relation, not a native instruction runner.

    Cuts are LF byte indexes plus one and, only if needed, the final input end.
    They are independent of Rust's split_inclusive. Proxy actions are stimuli;
    no expected role tag is exposed in either actual or expected transcripts.
    """
    raw, flag, actions, default = case
    lf = next(iter(set(facts['delimiters'].values())))
    cuts = [position+1 for position, value in enumerate(raw) if value == lf]
    if raw and (not cuts or cuts[-1] != len(raw)):
        cuts.append(len(raw))
    requests = []
    def request(value):
        nonlocal flag
        call = len(requests)
        result, mutation = actions[call] if call < len(actions) else default
        before = flag
        if mutation is not None:
            flag = mutation
        requests.append(f'{call}:{value.hex()}:{before}:{result}:{"-" if mutation is None else mutation}')
        return result
    start = 0
    status = 0
    for end in cuts:
        need(start < end <= len(raw), 'Native-proved chunk progress violated')
        if flag != facts['flag_compare']:
            if request(bytes.fromhex(facts['indentation']['bytes_hex'])):
                status = facts['failure_AL']; break
        # This is the target-proved PRE-payload store, not a callback-preservation assumption.
        flag = int(raw[end-1] == lf)
        if request(raw[start:end]):
            status = facts['failure_AL']; break
        start = end
    return f'c{index:04d};{status};{flag};{len(requests)};{",".join(requests)}'


def oracle(binary=TARGET):
    # One immutable admitted object supplies EVERY parser, literal and proof fact.
    # Native consumers receive only the existing producer's tiny copied spans.
    data = Path(binary).read_bytes()
    need(len(data) == 91774280 and sha(data) == original.SHA256, 'Input is not authenticated node94')
    record, _ = original._analyze(data)
    need(sha(data) == original.SHA256, 'Admitted immutable node94 snapshot differs')
    adapter = record['used_adapter_contract']
    facts = adapter['operand_facts']
    need(set(facts['delimiters'].values()) == {10} and facts['flag_compare'] == 0
         and facts['failure_AL'] == 1 and facts['indentation']['bytes_hex'] == '20202020'
         and facts['indentation']['length'] == 4, 'Native byte-request contract differs')
    need(adapter['write_protocol']['flag_store']['order'] == 'before payload callback', 'Native flag ordering differs')
    inputs, expected, fixture = [], [], []
    values = cases()
    for index, case in enumerate(values):
        given = stimulus_line(index, case)
        wanted = transcript(index, case, facts)
        inputs.append(given); expected.append(wanted); fixture.append(given+'\t'+wanted)
    encode = lambda lines: ('\n'.join(lines)+'\n').encode('ascii')
    return {'record': record, 'facts': facts, 'cases': values, 'inputs': encode(inputs),
            'expected': encode(expected), 'fixture': encode(fixture),
            'metadata': {'target_sha256': original.SHA256, 'original_head': ORIGINAL_HEAD,
                         'adapter_range': adapter['range'], 'adapter_sha256': adapter['span_sha256'],
                         'case_count': len(values), 'inputs_sha256': sha(encode(inputs)),
                         'expected_sha256': sha(encode(expected)), 'fixture_sha256': sha(encode(fixture)),
                         'native_facts': {k: facts[k] for k in ('delimiters', 'flag_compare', 'failure_AL', 'indentation')},
                         'native_write_protocol': adapter['write_protocol'],
                         'expectation_method': 'LF-index cuts and target-proved abstract callback/flag transfer with given stimuli; not Rust/split_inclusive, rendering, captured instructions or original callbacks.',
                         'actual_trace_fields': 'Case, low-byte status, final Cell, request count, then actual callindex/rawbytes/entryflag/supplied AL/optional supplied mutation. No expected kind tags.',
                         'domain': 'Valid safe Rust references and immutable bytes; finite normal callbacks; native frame/alias/metadata/dispatch assumptions stay external. Empty safe references are stronger than native raw empty-pointer admission.'}}


def verify_fixture(expected, path=FIXTURE):
    need(Path(path).read_bytes() == expected['fixture'], 'Rust transcript fixture differs from fresh native-contract expectations')


HARNESS = r'''extern crate node94_newline_writer_protocol;
#[path = "__DRIVER__"] mod test_driver;
use std::io::{self, Write};
fn main() {
    let path = std::env::args().nth(1).expect("input-only stimuli path");
    let inputs = std::fs::read_to_string(path).expect("input-only stimuli");
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let trace = test_driver::transcript(line, |input, flag, writer| {
            node94_newline_writer_protocol::write_indented_chunks(input, flag, writer)
        });
        writeln!(output, "{}", trace).unwrap();
    }
}
'''


def build(binary, rustc, output, controls=False):
    output = Path(output)
    need(not output.exists(), 'Output directory must be new; previous evidence is preserved')
    expected = oracle(binary)
    verify_fixture(expected)
    rustc = Path(rustc).absolute()
    compiler_before = file_digest(rustc)
    need(compiler_before == COMPILER_SHA256, 'Research compiler differs from authenticated1.94.1 executable')
    linker = shutil.which('cc'); need(linker is not None, 'C linker driver cc is required')
    linker_before = file_digest(linker)
    paths = tuple(sorted(COMPONENT.glob('*')))+(Path(__file__), ROOT/'tools/bincode_diagnostic_field_static.py', ROOT/'tools/bincode_diagnostic_adapter_static.py')
    source_before = {str(p.relative_to(ROOT)): file_digest(p) for p in paths if p.is_file()}
    output.mkdir(parents=True, exist_ok=False)
    (output/'oracle.json').write_text(json.dumps(expected['metadata'], indent=2)+'\n')
    (output/'inputs.txt').write_bytes(expected['inputs']); (output/'expected.txt').write_bytes(expected['expected'])
    (output/'comparison-main.rs').write_text(HARNESS.replace('__DRIVER__', str(DRIVER)))
    calls = []
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    def execute(label, argv, required_exit=0):
        start = time.monotonic()
        process = subprocess.run([str(a) for a in argv], cwd=ROOT, env=environment,
                                 stdin=subprocess.DEVNULL, capture_output=True)
        logs = {}
        for kind, raw in (('stdout', process.stdout), ('stderr', process.stderr)):
            path = output/(label+'.'+kind); path.write_bytes(raw)
            logs[kind] = {'file': path.name, 'bytes': len(raw), 'sha256': sha(raw)}
        calls.append({'label': label, 'argv': [str(a) for a in argv], 'exit_code': process.returncode,
                      'seconds': round(time.monotonic()-start, 3), 'logs': logs})
        (output/'CALLS.json').write_text(json.dumps(calls, indent=2)+'\n')
        if required_exit is not None:
            need(process.returncode == required_exit, label+' failed; exact raw outputs retained')
        return process
    try:
        version = execute('rustc-identity', [rustc, '-vV']).stdout.decode()
        need(version.startswith('rustc 1.94.1 ') and 'e408947bfd200af42db322daf0fadfe7e26d3bd1' in version,
             'Actual research compiler full identity differs')
        linker_version = execute('linker-identity', [linker, '--version']).stdout.decode()
        def flags(opt):
            return ['--edition=2021', '-D', 'warnings', '-C', 'codegen-units=1', '-C', f'opt-level={opt}',
                    '-C', 'overflow-checks=on', '-C', 'linker='+linker,
                    '--remap-path-prefix', str(ROOT)+'=/reconstruction']
        def library(label, source, opt, directory):
            directory.mkdir(parents=True, exist_ok=False); path = directory/('lib'+CRATE+'.rlib')
            execute(label, [rustc, '--crate-name', CRATE, '--crate-type=rlib', source, '-o', path,
                            '-C', 'metadata=node94-newline-protocol', *flags(opt)])
            return path
        def production(label, path, opt, directory):
            binary = directory/'comparison'
            execute(label+'-link', [rustc, '--crate-name', 'newline_comparison', output/'comparison-main.rs',
                    '--extern', CRATE+'='+str(path), '-o', binary, *flags(opt)])
            return execute(label+'-run', [binary, output/'inputs.txt']).stdout
        profiles = []
        for name, opt in (('debug', 0), ('optimized', 3)):
            directory = output/name; path = library(name+'-library', SOURCE, opt, directory)
            unit = directory/'module-tests'
            execute(name+'-test-build', [rustc, '--crate-name', CRATE, '--test', SOURCE, '-o', unit, *flags(opt)])
            tests = execute(name+'-tests', [unit, '--nocapture'])
            need(b'1 passed; 0 failed; 0 ignored' in tests.stdout, 'Actual ordinary Rust corpus test did not run')
            actual = production(name+'-production', path, opt, directory)
            need(actual == expected['expected'], name+' production transcript differs from fresh native contract')
            profiles.append({'name': name, 'opt_level': opt, 'ordinary_Rust_tests': 1,
                             'independent_production_cases': len(expected['cases']), 'matched': True,
                             'actual_sha256': sha(actual), 'expected_sha256': sha(expected['expected']),
                             'library_sha256': file_digest(path)})
        a = library('repro-a', SOURCE, 3, output/'repro-a'); b = library('repro-b', SOURCE, 3, output/'repro-b')
        repro = {'a_bytes': a.stat().st_size, 'b_bytes': b.stat().st_size, 'a_sha256': file_digest(a),
                 'b_sha256': file_digest(b), 'raw_equal': a.read_bytes() == b.read_bytes(),
                 'normalization': 'none', 'original_node_match_claimed': False}
        need(repro['raw_equal'], 'Own library rebuilds differ')
        mutants = []
        if controls:
            source = SOURCE.read_text()
            store = "flag.set(u8::from(piece.last() == Some(&b'\\n')));\n        if writer(piece, flag) != 0 {\n            return 1;\n        }"
            changes = [('raw-flag-is-one', 'flag.get() != 0', 'flag.get() == 1'),
                       ('three-spaces', 'writer(b"    ", flag)', 'writer(b"   ", flag)'),
                       ('CR-cuts', "input.split_inclusive(|byte| *byte == b'\\n')", "input.split_inclusive(|byte| *byte == b'\\r')"),
                       ('post-payload-store', store, "let failed = writer(piece, flag);\n        flag.set(u8::from(piece.last() == Some(&b'\\n')));\n        if failed != 0 {\n            return 1;\n        }"),
                       ('ignore-indent-error', 'if flag.get() != 0 && writer(b"    ", flag) != 0 {\n            return 1;\n        }', 'if flag.get() != 0 { let _ = writer(b"    ", flag); }'),
                       ('raw-payload-AL', 'if writer(piece, flag) != 0 {\n            return 1;\n        }', 'let result = writer(piece, flag);\n        if result != 0 { return result; }'),
                       ('trailing-empty-request', '    }\n    0\n}', '    }\n    if input.last() == Some(&10) { let _ = writer(&[], flag); }\n    0\n}')]
            for name, needle, replacement in changes:
                need(source.count(needle) == 1, 'Ambiguous mutation site: '+name)
                directory = output/('mutant-'+name); directory.mkdir()
                path = directory/'lib.rs'; path.write_text(source.replace(needle, replacement))
                shutil.copyfile(DRIVER, directory/'test_driver.rs'); shutil.copyfile(FIXTURE, directory/'target-transcripts.tsv')
                lib = library('mutant-'+name+'-library', path, 0, directory/'build')
                actual = production('mutant-'+name+'-production', lib, 0, directory)
                lines = actual.splitlines(); wanted = expected['expected'].splitlines()
                need(len(lines) == len(wanted), 'Mutant case output count differs')
                mismatches = [{'case': i, 'expected': e.decode(), 'actual': v.decode()}
                              for i, (e, v) in enumerate(zip(wanted, lines)) if e != v]
                need(mismatches, 'Compiled mutant escaped transcript comparison')
                unit = directory/'module-tests'
                execute('mutant-'+name+'-test-build', [rustc, '--crate-name', CRATE, '--test', path, '-o', unit, *flags(0)])
                failure = execute('mutant-'+name+'-tests', [unit, '--nocapture'], required_exit=None)
                need(failure.returncode == 101 and b'assertion' in failure.stdout+failure.stderr,
                     'Compiled semantic mutant did not fail an actual assertion')
                mutants.append({'name': name, 'compiled': True, 'semantic_test_exit': failure.returncode,
                                'mismatch_count': len(mismatches), 'first_witness': mismatches[0],
                                'source_sha256': file_digest(path), 'library_sha256': file_digest(lib)})
        after = {str(p.relative_to(ROOT)): file_digest(p) for p in paths if p.is_file()}
        need(source_before == after and compiler_before == file_digest(rustc)
             and linker_before == file_digest(linker), 'Source/compiler/linker changed')
        need(file_digest(binary) == original.SHA256, 'Node94 bytes changed during build')
        result = {'status': 'NEWLINE_BYTE_REQUEST_PROTOCOL_COMPONENT_PASS', 'original_head': ORIGINAL_HEAD,
                  'compiler': {'path': str(rustc), 'version': version, 'sha256': compiler_before,
                               'meaning': 'Research toolchain, not recovered original node compiler.'},
                  'linker': {'path': linker, 'version': linker_version, 'sha256': linker_before, 'explicit': True},
                  'sources': source_before, 'source_compiler_target_unchanged': True,
                  'oracle': expected['metadata'], 'profiles': profiles, 'own_rebuild': repro,
                  'compiled_mutants': mutants, 'commands': calls, 'captured_execution_or_emulation': False,
                  'limits': ['Chosen safe valid-reference low-byte/Cell/proxy protocol, stronger than raw native empty-pointer admission.',
                             'No original vtable/type/ABI/parent390B/physical rendering/unwind/runtime/byte-identity/gate claim.',
                             'Input-only harness receives stimuli and normal callback actions, not expected transcripts or role tags; no sandbox claim.']}
        (output/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n'); return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'status': 'FAILED_COMPONENT_RUN', 'error': str(error),
                'commands': calls, 'outputs_preserved': True, 'captured_execution_or_emulation': False}, indent=2)+'\n')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args(); result = build(args.binary, args.rustc, args.output, args.controls)
    print(json.dumps({'status': result['status'], 'profiles': result['profiles'],
                      'compiled_mutants': len(result['compiled_mutants']), 'own_rebuild': result['own_rebuild']}, sort_keys=True))
