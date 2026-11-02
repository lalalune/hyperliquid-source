#!/usr/bin/env python3
"""Verify and build the migrated, target-bound u128-to-binary64 projection."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-004-node115-u128-binary64'
SOURCE = ROOT / 'src/node115-u128-binary64'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x63f00d0, 0x63f0154


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    data = TARGET.read_bytes()
    if digest(data) != SHA:
        raise ValueError('Node #115 digest mismatch')
    record = json.loads((PACKET / 'records.json').read_text())
    if (record['start'], record['end']) != (START, END):
        raise ValueError('Migration bounds changed')
    _, fdes = eh_frame_records(data)
    matches = [f for f in fdes if f['start'] == START and f['end'] == END]
    if len(matches) != 1 or matches[0] != record['fde']:
        raise ValueError('Exact FDE changed')
    mapped = [s for s in sections(data) if s['flags'] & 4 and s['type'] != 8
              and s['address'] <= START and END <= s['address'] + s['size']]
    if len(mapped) != 1:
        raise ValueError('Ambiguous executable mapping')
    offset = mapped[0]['offset'] + START - mapped[0]['address']
    body = data[offset:offset + END - START]
    if body != (PACKET / 'official-body.bin').read_bytes() or digest(body) != record['body_sha256']:
        raise ValueError('Full body correspondence changed')
    for name, key in [('inputs.tsv.gz', 'inputs_sha256'), ('expected.tsv.gz', 'expected_sha256')]:
        if digest((PACKET / name).read_bytes()) != record[key]:
            raise ValueError('Frozen corpus changed')
    return record


def build(output):
    record = verify()
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('Use a new output directory')
    output.mkdir(parents=True)
    rustc = subprocess.check_output(['rustup', 'which', '--toolchain', '1.95.0', 'rustc'], text=True).strip()
    version = subprocess.check_output([rustc, '-vV'], text=True)
    inputs = gzip.decompress((PACKET / 'inputs.tsv.gz').read_bytes())
    expected = gzip.decompress((PACKET / 'expected.tsv.gz').read_bytes())
    (output / 'inputs.tsv').write_bytes(inputs)
    runs = []
    for opt in ('0', '3'):
        lib, client = output / f'lib-o{opt}.rlib', output / f'client-o{opt}'
        subprocess.run([rustc, '--edition=2021', '--crate-name', 'node115_u128_binary64',
                        '--crate-type', 'rlib', '-C', f'opt-level={opt}', '-D', 'warnings',
                        str(SOURCE / 'lib.rs'), '-o', str(lib)], check=True)
        subprocess.run([rustc, '--edition=2021', '-C', f'opt-level={opt}', '-D', 'warnings',
                        str(SOURCE / 'input_only_driver.rs'), '--extern', f'node115_u128_binary64={lib}',
                        '-o', str(client)], check=True)
        result = subprocess.run([str(client), str(output / 'inputs.tsv')], capture_output=True, check=True)
        (output / f'actual-o{opt}.tsv').write_bytes(result.stdout)
        if result.stdout != expected:
            raise ValueError('Compiled Rust differs from the frozen oracle')
        runs.append({'opt_level': opt, 'cases': len(inputs.splitlines()), 'equal': True})
    controls = []
    original = (SOURCE / 'lib.rs').read_text()
    for name, old, new in [('exponent-bias', '+ 1023', '+ 1022'),
                           ('tie-parity', 'significand & 1 != 0', 'significand & 1 == 0')]:
        if original.count(old) != 1:
            raise ValueError('Mutation source anchor changed')
        mutant = output / f'{name}.rs'
        mutant.write_text(original.replace(old, new))
        lib, client = output / f'lib-{name}.rlib', output / f'{name}-client'
        subprocess.run([rustc, '--edition=2021', '--crate-name', 'node115_u128_binary64',
                        '--crate-type', 'rlib', '-C', 'opt-level=3', '-D', 'warnings',
                        str(mutant), '-o', str(lib)], check=True)
        subprocess.run([rustc, '--edition=2021', '-C', 'opt-level=3', '-D', 'warnings',
                        str(SOURCE / 'input_only_driver.rs'), '--extern', f'node115_u128_binary64={lib}',
                        '-o', str(client)], check=True)
        result = subprocess.run([str(client), str(output / 'inputs.tsv')], capture_output=True, check=True)
        mismatches = sum(a != b for a, b in zip(result.stdout.splitlines(), expected.splitlines()))
        if len(result.stdout.splitlines()) != len(expected.splitlines()) or not mismatches:
            raise ValueError('Compiled source corruption escaped')
        controls.append({'name': name, 'mismatches': mismatches, 'rejected': True})
    report = {'target_sha256': SHA, 'target_body_sha256': record['body_sha256'],
              'compiler': version, 'runs': runs, 'compiled_controls': controls, 'captured_node_executed': False,
              'rust_source_sha256': digest((SOURCE / 'lib.rs').read_bytes())}
    (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    result = build(args.build_dir) if args.build_dir else verify()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
