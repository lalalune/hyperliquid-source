#!/usr/bin/env python3
"""Build and compare independently authored Rust; no captured code execution."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import decimal96 as native

ROOT, COMPONENT, PACKET = native.ROOT, native.COMPONENT, native.PACKET
CRATE = 'node115_decimal96_normalize'
DRIVER = r'''extern crate node115_decimal96_normalize;
use node115_decimal96_normalize::normalize_parts;
use std::io::{self, Write};
fn main() {
    let input = std::fs::read_to_string(std::env::args().nth(1).expect("input-only file")).unwrap();
    let mut output = io::BufWriter::new(io::stdout().lock());
    for line in input.lines() {
        let p: Vec<u32> = line.split('\t').map(|w| w.parse().unwrap()).collect();
        assert_eq!(p.len(), 4);
        let w = normalize_parts(p[0], p[1], p[2], p[3]).observed_words();
        writeln!(output, "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", p[0], p[1], p[2], p[3], w[0], w[1], w[2], w[3]).unwrap();
    }
}
'''

def controls(data):
    results = []
    # These are lower-layer operand counterfactuals; production always requires the full identity.
    for name, va, value, witness in [
        ('reject-threshold', 0x3be4c79, 0, (10, 0, 0, 1 << 16)),
        ('inverse-five', 0x3be4c83, 0, (11, 0, 0, 1 << 16)),
    ]:
        changed = bytearray(data)
        off, _ = native.mapped(data, native.sections(data), va, 8)
        changed[off:off+8] = value.to_bytes(8, 'little')
        expected = native.limb_relation(*witness, native.parameters(data))
        observed = native.limb_relation(*witness, native.parameters(changed))
        native.need(expected != observed, 'operand control lacks semantic witness')
        try:
            native.analyze(changed, authenticate=False)
        except ValueError as error:
            reason = str(error)
        else:
            raise ValueError('lower-layer changed instruction was accepted')
        results.append({'name': name, 'image_va': hex(va), 'inputs': witness,
                        'expected': expected, 'counterfactual': observed,
                        'lower_layer_rejection': reason, 'capture_executed': False})
    return results

def build(args):
    data = args.binary.read_bytes()
    static = native.validate(args.binary)
    expected = (COMPONENT/'target-vectors.tsv').read_bytes()
    source = COMPONENT/'lib.rs'
    native.need(not args.output.exists(), 'output must be a new directory')
    version = subprocess.check_output([str(args.rustc), '-vV'], text=True, timeout=30)
    native.need(version.startswith('rustc 1.95.0 '), 'this packet pins research compiler Rust1.95.0')
    before = {p.name: native.digest(p.read_bytes()) for p in (source, args.rustc, args.linker, Path(__file__))}
    out = args.output
    out.mkdir(parents=True)
    inputs = b''.join(b'\t'.join(line.split(b'\t')[:4])+b'\n' for line in expected.splitlines())
    (out/'inputs.tsv').write_bytes(inputs)
    (out/'expected.tsv').write_bytes(expected)
    (out/'driver.rs').write_text(DRIVER)
    commands = []

    def execute(label, argv, expected_failure=False):
        argv = list(map(str, argv))
        print('PHASE:', label, flush=True)
        process = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        (out/(label+'.stdout')).write_bytes(process.stdout)
        (out/(label+'.stderr')).write_bytes(process.stderr)
        commands.append({'label': label, 'exitCode': process.returncode,
                         'argv': [a.replace(str(out), '$OUTPUT').replace(str(ROOT), '$REPO')
                                  .replace(str(args.rustc), '$RUSTC').replace(str(args.linker), '$LINKER') for a in argv],
                         'stdout_sha256': native.digest(process.stdout), 'stderr_sha256': native.digest(process.stderr)})
        native.need(process.returncode != 0 if expected_failure else process.returncode == 0,
                    label+' unexpected exit; preserve stdout/stderr')
        return process.stdout

    def profile(name, src, opt, mutant=False):
        folder = out/name
        folder.mkdir()
        flags = ['--edition=2021', '-D', 'warnings', '-C', f'opt-level={opt}',
                 '-C', 'overflow-checks=on', '-C', 'codegen-units=1',
                 '--remap-path-prefix', str(ROOT)+'=/reconstruction',
                 '--remap-path-prefix', str(out)+'=/validation',
                 '-C', 'linker='+str(args.linker), '-C', 'linker-flavor=ld.lld',
                 '-C', 'link-self-contained=yes']
        library = folder/('lib'+CRATE+'.rlib')
        execute(name+'-library', [args.rustc, '--crate-name', CRATE, '--crate-type=rlib', src, '-o', library, *flags])
        driver = folder/'driver.exe'
        execute(name+'-link', [args.rustc, out/'driver.rs', '--extern', CRATE+'='+str(library), '-o', driver, *flags])
        actual = execute(name+'-run', [driver, out/'inputs.tsv'])
        native.need(len(actual.splitlines()) == static['cases'], 'missing output rows')
        mismatches = sum(a != b for a, b in zip(actual.splitlines(), expected.splitlines()))
        native.need(mismatches > 0 if mutant else actual == expected, 'value comparator result unexpected')
        tests = folder/'tests.exe'
        execute(name+'-test-build', [args.rustc, '--crate-name', CRATE, '--test', src, '-o', tests, *flags])
        test_output = execute(name+'-tests', [tests], expected_failure=mutant)
        if not mutant:
            native.need(b'3 passed; 0 failed' in test_output, 'three ordinary Rust tests must execute')
        return {'name': name, 'opt_level': opt, 'cases': static['cases'], 'mismatches': mismatches,
                'library_sha256': native.digest(library.read_bytes()), 'output_sha256': native.digest(actual)}

    profiles = [profile('debug', source, 0), profile('optimized', source, 3)]
    repeat = profile('optimized-repeat', source, 3)
    native.need(repeat['library_sha256'] == profiles[1]['library_sha256'], 'optimized own library differs on repeat')
    mutants = []
    text = source.read_text(encoding='utf-8-sig')
    for name, old, new in [
        ('truncate-high-limb', '(u128::from(hi) << 64)', '(u128::from(hi & 0) << 64)'),
        ('negative-zero', 'coefficient: 0, flags: 0', 'coefficient: 0, flags'),
        ('scale-zero-flags', 'Normalized { coefficient, flags };', 'Normalized { coefficient, flags: flags & 0x8000_0000 };'),
        ('ignore-scale-cap', 'while scale > 0 && coefficient % 10 == 0 {', 'while coefficient % 10 == 0 {'),
    ]:
        native.need(text.count(old) == 1, 'ambiguous production mutant site')
        folder = out/('source-'+name)
        folder.mkdir()
        path = folder/'lib.rs'
        path.write_text(text.replace(old, new))
        (folder/'target-vectors.tsv').write_bytes(expected)
        if name == 'ignore-scale-cap':
            # Incorrect cap mutant must still finish normally for value comparison.
            path.write_text(path.read_text().replace('scale -= 1;', 'scale = scale.saturating_sub(1);'))
        mutants.append(profile('mutant-'+name, path, 0, mutant=True))
    native.need(before == {p.name: native.digest(p.read_bytes()) for p in (source, args.rustc, args.linker, Path(__file__))}, 'build input changed')
    native.need(native.digest(args.binary.read_bytes()) == native.SHA, 'target input changed')
    result = {'status': 'PASS', 'target_sha256': native.SHA, 'static': static, 'compiler': version,
              'source_tool_compiler_linker_sha256': before, 'profiles': profiles, 'optimized_repeat': repeat,
              'rust_mutants': mutants, 'operand_controls': controls(data), 'commands': commands,
              'captured_execution_or_emulation': False, 'abi_or_whole_function_equivalence': False,
              'component_gates_changed': False}
    (out/'RESULT.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'status': 'PASS', 'cases': static['cases'], 'profiles': 3, 'compiled_mutants': len(mutants), 'operand_controls': 2}))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'artifacts/node/115/hl-node')
    parser.add_argument('--rustc', required=True, type=Path)
    parser.add_argument('--linker', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    build(parser.parse_args())
