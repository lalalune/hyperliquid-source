"""Task-local static admission and compiled Rust value/read-order qualification."""

def require(condition, message):
    if not condition:
        raise ValueError(message)
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / 'src/node94-errno-gate'
MUTANTS = [('signed-low-word', 'input <= 0xffff_ffff_ffff_ff88', '(input as i32) >= 0'), ('boundary-120', '0xffff_ffff_ffff_ff88', '0xffff_ffff_ffff_ff87'), ('unnegated-word', '(input as u32).wrapping_neg()', 'input as u32')]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--rustc', default='rustc')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('contract', PACKET / 'contract.py')
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    freeze = json.loads((PACKET / 'preparation/ORACLE-FREEZE.json').read_text())
    require(sha(PACKET / 'contract.py') == freeze['contract_sha256'], 'qualification precondition failed')
    vectors = (SOURCE / 'vectors.tsv').read_bytes()
    require(hashlib.sha256(vectors).hexdigest() == freeze['vectors_sha256'], 'qualification precondition failed')
    require(vectors == (PACKET / 'preparation/vectors.tsv').read_bytes() == contract.vector_bytes(), 'qualification precondition failed')
    require(contract.admit(args.binary) == freeze['admitted'], 'qualification precondition failed')
    rows = [r.split(b'\t') for r in vectors.splitlines()]
    require(len(rows) == freeze['cases'], 'qualification precondition failed')
    inputs = b''.join((i + b'\t' + v + b'\n' for i, v, _ in rows))
    expected = [i + b'\t' + e for i, _, e in rows]
    work = ROOT / 'work/RE-004-errno-gate-rust-94'
    work.mkdir(parents=True, exist_ok=True)
    log = []

    def run(argv, stdin=None, allow_mismatch=False):
        proc = subprocess.run([str(x) for x in argv], input=stdin, capture_output=True, cwd=ROOT)
        log.append({'argv': [str(x) for x in argv], 'exit': proc.returncode, 'stdout': proc.stdout.decode(errors='replace'), 'stderr': proc.stderr.decode(errors='replace')})
        if proc.returncode:
            print(proc.stdout.decode(errors='replace'), proc.stderr.decode(errors='replace'), file=sys.stderr)
            raise RuntimeError('Command failed: ' + str(argv))
        return proc.stdout
    version = run([args.rustc, '-vV']).decode()
    require('rustc 1.94.1 ' in version and 'LLVM version: 21.1.8' in version, 'qualification precondition failed')
    result = {'kind': 'errno-gate', 'freeze_sha256': sha(PACKET / 'preparation/ORACLE-FREEZE.json'), 'target_sha256': freeze['admitted']['target_sha256'], 'cases': len(rows), 'toolchain': version, 'target_executed': False, 'target_emulated': False, 'native_byte_comparison': False, 'full_domain_formal_proof': False, 'source_sha256': {p.name: sha(p) for p in sorted(SOURCE.iterdir()) if p.is_file()}, 'compiled': [], 'mutants': [], 'body_corruptions_rejected': []}
    original = (SOURCE / 'lib.rs').read_text()

    def build(directory, source, opt, tests=False):
        directory.mkdir(exist_ok=True)
        for p in SOURCE.iterdir():
            if p.is_file():
                shutil.copyfile(p, directory / p.name)
        (directory / 'lib.rs').write_text(source)
        common = ['--edition=2021', '-C', 'opt-level=' + str(opt), '-C', 'overflow-checks=yes']
        if tests:
            run([args.rustc, *common, '--test', directory / 'lib.rs', '-o', directory / 'tests'])
            run([directory / 'tests', '--nocapture'])
        rlib = directory / 'libnode94_leaf.rlib'
        run([args.rustc, *common, '--crate-name', 'node94_leaf', '--crate-type=rlib', directory / 'lib.rs', '-o', rlib])
        run([args.rustc, *common, directory / 'client.rs', '--extern', 'node94_leaf=' + str(rlib), '-o', directory / 'client'])
        output = run([directory / 'client'], inputs)
        (directory / 'observed.tsv').write_bytes(output)
        observed = output.splitlines()
        require(len(observed) == len(expected), 'qualification precondition failed')
        return (sum((a != b for a, b in zip(observed, expected))), hashlib.sha256(output).hexdigest(), common, rlib)
    for opt in [0, 3]:
        directory = work / ('O' + str(opt))
        mismatches, output_sha, common, rlib = build(directory, original, opt, tests=True)
        require(mismatches == 0, 'qualification precondition failed')
        run([args.rustc, *common, '--crate-name', 'node94_leaf', '--crate-type=rlib', '--emit=llvm-ir', SOURCE / 'lib.rs', '-o', directory / 'library.ll'])
        run([args.rustc, *common, '--emit=llvm-ir', SOURCE / 'client.rs', '--extern', 'node94_leaf=' + str(rlib), '-o', directory / 'client.ll'])
        definitions = []
        for name in ['library.ll', 'client.ll']:
            definitions.extend((line.strip() for line in (directory / name).read_text().splitlines() if line.startswith('define ') and any((s in line for s in ['negative_band']))))
        require(definitions, 'qualification precondition failed')
        result['compiled'].append({'optimization': opt, 'cases': len(rows), 'mismatches': mismatches, 'observed_sha256': output_sha, 'llvm_definitions': definitions})
    for name, old, new in MUTANTS:
        pattern = '\\s*'.join((re.escape(token) for token in old.split()))
        matches = list(re.finditer(pattern, original))
        require(len(matches) == 1, (name, len(matches)))
        mutated = re.sub(pattern, lambda _: new, original)
        mismatches, output_sha, _, _ = build(work / name, mutated, 0)
        require(mismatches > 0, name)
        result['mutants'].append({'name': name, 'mismatches': mismatches, 'cases': len(rows), 'observed_sha256': output_sha})
    data = bytearray(args.binary.read_bytes())
    from elf_index import sections
    secs = sections(data)
    for start, end, _ in freeze['admitted']['windows']:
        sec = next((s for s in secs if s['type'] != 8 and s['address'] <= start < s['address'] + s['size']))
        for address in [start, end - 1]:
            offset = sec['offset'] + address - sec['address']
            data[offset] ^= 1
            try:
                contract.body_checks(data)
            except ValueError:
                result['body_corruptions_rejected'].append(hex(address))
            else:
                raise AssertionError('Body corruption accepted')
            finally:
                data[offset] ^= 1
    wrong = work / 'wrong-capture'
    wrong.write_bytes(b'not the captured binary')
    try:
        contract.admit(wrong)
    except ValueError:
        result['wrong_capture_rejected'] = True
    else:
        raise AssertionError('Wrong capture accepted')
    public = PACKET / 'qualification'
    public.mkdir(exist_ok=True)

    def normalized(value):
        return value.replace(str(ROOT), '<REPO>').replace(str(Path.home()), '<HOME>')
    for directory in sorted(work.iterdir()):
        if directory.is_dir():
            for filename in ['observed.tsv', 'library.ll', 'client.ll']:
                p = directory / filename
                if p.exists():
                    content = normalized(p.read_text()).encode()
                    (public / (directory.name + '-' + filename + '.gz')).write_bytes(gzip.compress(content, mtime=0))
    (public / 'commands.json.gz').write_bytes(gzip.compress(normalized(json.dumps(log, indent=2)).encode(), mtime=0))
    result = json.loads(normalized(json.dumps(result)))
    (public / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['kind', 'cases', 'compiled', 'mutants', 'body_corruptions_rejected']}, indent=2))
if __name__ == '__main__':
    main()
