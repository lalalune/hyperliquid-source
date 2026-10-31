#!/usr/bin/env python3
"""Compare the standalone Rust contract with authenticated static transfers.

Only independently authored Rust is compiled/run. The captured ELF is inert
input to GNU/LLVM disassembly and the existing bounded equation evaluator.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from artifacts import ROOT, check
from short_string_alias import TARGET, alias_transfers, decode, feed_transfers, fixtures

CRATE = ROOT / 'src/node94-alias'
VECTORS = CRATE / 'evidence/contract-vectors.txt'
PACKET = ROOT / 'research/work-items/RE-001-short-string-alias-94'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vectors(binary):
    identity = next(x for x in json.loads((ROOT/'provenance/artifacts.json').read_text())['files']
                    if x['path'] == 'artifacts/node/94/hl-node')
    if identity['sha256'] != TARGET:
        raise ValueError('Unexpected target identity')
    check(binary, identity)
    code, _ = decode(binary, binary.read_bytes())
    retained = json.loads((PACKET/'observed/records.json').read_text())
    if retained['target_sha256'] != TARGET:
        raise ValueError('Retained target identity differs')
    lines = ['# node94 static instruction-transfer expectations; not native runtime output',
             '# target_sha256=' + TARGET,
             '# a|input hex (- empty)|alias hex|ten full counter hashes',
             '# f|four chunk hex strings|four logical states (v0,v1,v2,v3,length,tail,count)']
    actual_vectors = []
    hx = lambda b: b.hex() or '-'
    for message in fixtures():
        output, transfers = alias_transfers(code, message)
        hashes = [f'{h:016x}' for _, h in transfers.counter_hashes]
        if [i for i, _ in transfers.counter_hashes] != list(range(10)):
            raise ValueError('Incomplete counter observations')
        actual_vectors.append({'input_hex': message.hex(), 'bytes': len(message),
                               'alias_ascii': output.decode('ascii'), 'counter_hashes_hex': hashes})
        lines.append('|'.join(['a', hx(message), output.hex(), ','.join(hashes)]))
    if actual_vectors != retained['alias_vectors']:
        raise ValueError('Fresh target transfers differ from retained alias/hash observations')
    writes = 0
    for prefix in range(8):
        for size in range(33):
            chunks = [bytes(range(prefix)), bytes((i*37+5) & 255 for i in range(size)),
                      b'\xff', b'\x09\0\0\0']
            history, _ = feed_transfers(code, chunks)
            if len(history) != 4:
                raise ValueError('Incomplete streaming observations')
            states = [','.join(f'{v:016x}' for v in [*words, length, tail, count])
                      for words, length, tail, count in history]
            lines.append('|'.join(['f', ','.join(map(hx, chunks)), ';'.join(states)]))
            writes += len(history)
    if len(actual_vectors) != 78 or writes != 1056:
        raise ValueError('Comparison denominator changed')
    return ('\n'.join(lines)+'\n').encode()


def run(output, controls=False):
    binary = ROOT / 'artifacts/node/94/hl-node'
    expected = vectors(binary)
    if VECTORS.read_bytes() != expected:
        raise ValueError('Committed Rust expectations differ from fresh instruction transfers')
    output.mkdir(parents=True, exist_ok=True)
    (output/'fresh-vectors.txt').write_bytes(expected)
    commands = []
    # Each invocation gets two new directories; cached prior builds cannot
    # masquerade as the two clean builds recorded by this run.
    build_a = Path(tempfile.mkdtemp(prefix='build-a-', dir=output))
    build_b = Path(tempfile.mkdtemp(prefix='build-b-', dir=output))

    def execute(label, args, *, crate=CRATE, target=None, failing=False):
        command = ['cargo', *args, '--manifest-path', str(crate/'Cargo.toml')]
        environment = dict(os.environ, CARGO_TARGET_DIR=str(target or build_a))
        process = subprocess.run(command, cwd=ROOT, env=environment,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        text = process.stdout.replace(str(ROOT), '<repo>').replace(str(crate), '<crate>')
        if crate != CRATE:
            text = text.replace(str(crate.parent), '<control>')
        text = text.replace(str(output), '<output>')
        (output/f'{label}.log').write_text(text)
        manifest = ('src/node94-alias/Cargo.toml' if crate == CRATE
                    else '<mutated-copy>/Cargo.toml')
        row = {'check': label, 'command': ['cargo', *args, '--manifest-path', manifest],
               'exit_code': process.returncode}
        if failing:
            if process.returncode == 0 or 'test result: FAILED' not in process.stdout:
                raise ValueError('Rust corruption did not produce an actual comparison failure: '+label)
        elif process.returncode:
            raise ValueError('Rust command failed: '+label+'; see '+str(output/f'{label}.log'))
        commands.append(row)

    execute('debug-tests', ['test', '--locked', '--offline'])
    execute('release-tests', ['test', '--release', '--locked', '--offline'])
    execute('release-build-a', ['build', '--release', '--locked', '--offline'])
    execute('release-build-b', ['build', '--release', '--locked', '--offline'],
            target=build_b)
    a = build_a/'release/libnode94_alias.rlib'
    b = build_b/'release/libnode94_alias.rlib'
    if digest(a) != digest(b):
        raise ValueError('Two independent release builds differ; no reproducibility claim')

    mutations = [
        ('initial-word', '0x736f6d6570736575', '0x736f6d6570736574'),
        ('delimiter', 'state.write(&[0xff]);', 'state.write(&[0xfe]);'),
        ('counter-endian', '(counter as u32).to_le_bytes()', '(counter as u32).to_be_bytes()'),
        ('mix-rotation', 'rotate_left(13)', 'rotate_left(12)'),
        ('word-endian', 'u64::from_le_bytes', 'u64::from_be_bytes'),
        ('length-byte', '(self.length & 255) << 56', '(self.length & 127) << 56'),
        ('final-domain', 'words[2] ^= 255;', 'words[2] ^= 254;'),
        ('output-offset', '*letter = 65 +', '*letter = 66 +'),
    ]
    if controls:
        source = (CRATE/'src/lib.rs').read_text()
        for label, before, after in mutations:
            if source.count(before) != 1:
                raise ValueError('Ambiguous Rust mutation anchor: '+label)
            with tempfile.TemporaryDirectory(prefix='node94-alias-rust-control-') as temp:
                changed = Path(temp)/'crate'
                shutil.copytree(CRATE, changed, ignore=shutil.ignore_patterns('target'))
                (changed/'src/lib.rs').write_text(source.replace(before, after))
                execute('mutation-'+label, ['test', '--release', '--locked', '--offline'],
                        crate=changed, target=Path(temp)/'target', failing=True)

    sources = ['Cargo.toml', 'Cargo.lock', 'src/lib.rs', 'src/tests.rs',
               'evidence/contract-vectors.txt']
    result = {
        'target_sha256': TARGET,
        'target_bytes': binary.stat().st_size,
        'rustc': subprocess.check_output(['rustc', '-vV'], text=True),
        'cargo': subprocess.check_output(['cargo', '-V'], text=True).strip(),
        'host_platform': sys.platform,
        'source_sha256': {str((CRATE/p).relative_to(ROOT)): digest(CRATE/p) for p in sources},
        'comparison_script_sha256': digest(Path(__file__)),
        'static_evaluator_sha256': digest(ROOT/'tools/short_string_alias.py'),
        'fresh_vectors_sha256': hashlib.sha256(expected).hexdigest(),
        'alias_comparisons_per_profile': 78,
        'full_hash_comparisons_per_profile': 780,
        'stream_sequences_per_profile': 264,
        'per_write_state_comparisons_per_profile': 1056,
        'profiles': ['debug', 'release'],
        'rust_source_corruption_controls': len(mutations) if controls else 0,
        'rust_source_mutations': [{'name': label, 'before': before, 'after': after}
                                  for label, before, after in mutations] if controls else [],
        'release_build_a_sha256': digest(a),
        'release_build_b_sha256': digest(b),
        'release_builds_raw_equal': True,
        'release_build_normalization': None,
        'commands': commands,
        'captured_executable_launched': False,
        'external_dependencies': 0,
        'scope': 'Host Rust contract vs finite static transfers, not captured runtime/ABI/whole-ELF equivalence. '
                 'No allocator/cache/constructor implementation, target-native build, component gate or speed claim.',
    }
    (output/'comparison.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'work/short-string-alias-rust')
    parser.add_argument('--controls', action='store_true')
    parser.add_argument('--write-vectors', action='store_true',
                        help='Explicitly regenerate the committed, target-derived test expectations')
    args = parser.parse_args()
    if args.write_vectors:
        VECTORS.parent.mkdir(parents=True, exist_ok=True)
        VECTORS.write_bytes(vectors(ROOT/'artifacts/node/94/hl-node'))
        print('Wrote target-derived vectors: '+str(VECTORS.relative_to(ROOT)))
    else:
        print(json.dumps(run(args.output.resolve(), controls=args.controls), indent=2))
