#!/usr/bin/env python3
"""Verify the three target-bound count projections without target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-tagged-count'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SOURCE = ROOT / 'src/node115-tagged-count'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def verify(data=None):
    data = TARGET.read_bytes() if data is None else data
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    record = json.loads((PACKET / 'records.json').read_text())
    if not isinstance(record, dict) \
            or not {'target_sha256', 'body_sha256', 'windows', 'fixture_sha256', 'cases'} <= record.keys() \
            or not isinstance(record['windows'], list) \
            or not all(isinstance(row, dict) and {'start', 'end', 'fde', 'file_offset'} <= row.keys()
                       for row in record['windows']):
        raise ValueError('Invalid tagged-count record')
    if record['target_sha256'] != SHA:
        raise ValueError('Record target changed')
    body = bytes.fromhex((PACKET / 'body.hex').read_text())
    if len(body) != 69 or hashlib.sha256(body).hexdigest() != record['body_sha256']:
        raise ValueError('Body reference changed')
    _, fdes = eh_frame_records(data)
    segments = sections(data)
    if len(record['windows']) != 3:
        raise ValueError('Window count changed')
    for row in record['windows']:
        matching = [f for f in fdes if (f['start'], f['end']) == (row['start'], row['end'])]
        if matching != [row['fde']]:
            raise ValueError('Exact FDE changed')
        seg = [s for s in segments if s['flags'] & 4 and s['address'] <= row['start'] and row['end'] <= s['address'] + s['size']]
        if len(seg) != 1:
            raise ValueError('Ambiguous code mapping')
        offset = seg[0]['offset'] + row['start'] - seg[0]['address']
        if offset != row['file_offset'] or row['end'] - row['start'] != len(body):
            raise ValueError('Body mapping changed')
        if data[offset:offset + 69] != body:
            raise ValueError('Native body changed')
    if hashlib.sha256((PACKET / 'vectors.tsv').read_bytes()).hexdigest() != record['fixture_sha256']:
        raise ValueError('Frozen fixture changed')
    return record


def build(output):
    record = verify()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    rustc = subprocess.check_output(['rustup', 'which', '--toolchain', '1.95.0', 'rustc'], text=True).strip()
    original = (SOURCE / 'lib.rs').read_text()
    variants = [('original', original),
                ('full-width-one', original.replace('tag as u32 == 1', 'tag == 1')),
                ('wrapping-subtraction', original.replace('left.saturating_sub(right)', 'left.wrapping_sub(right)'))]
    runs, controls = [], []
    for name, source in variants:
        if name != 'original' and source == original:
            raise ValueError('Mutation source anchor changed')
        # Preserve the relative frozen-fixture include while keeping mutant
        # source and compiler output in the ignored build directory.
        source = source.replace('../../research/work-items/RE-001-node115-tagged-count/vectors.tsv',
                                str(PACKET / 'vectors.tsv'))
        path = output / f'{name}.rs'
        path.write_text(source)
        for opt in (('0', '3') if name == 'original' else ('3',)):
            executable = output / f'{name}-o{opt}'
            subprocess.run([rustc, '--edition=2021', '--test', '-D', 'warnings', '-C',
                            f'opt-level={opt}', str(path), '-o', str(executable)], check=True)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            (output / f'{name}-o{opt}.log').write_text(result.stdout + result.stderr)
            if name == 'original':
                if result.returncode:
                    raise ValueError('Compiled Rust differs from frozen instruction-derived vectors')
                runs.append({'opt_level': opt, 'cases': record['cases'], 'equal': True})
            else:
                if result.returncode != 101 or 'assertion `left == right` failed' not in result.stdout:
                    raise ValueError('Compiled semantic corruption escaped or failed unexpectedly')
                controls.append({'name': name, 'rejected': True})
    report = {'target_sha256': SHA, 'body_sha256': record['body_sha256'],
              'mapped_complete_fdes': len(record['windows']),
              'rust_source_sha256': hashlib.sha256((SOURCE / 'lib.rs').read_bytes()).hexdigest(),
              'compiler': subprocess.check_output([rustc, '-vV'], text=True),
              'runs': runs, 'compiled_controls': controls, 'captured_node_executed': False}
    (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.build_dir) if args.build_dir else verify(), indent=2))
