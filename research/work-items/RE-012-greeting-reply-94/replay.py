#!/usr/bin/env python3
"""Compare independent Rust against pre-existing frozen mathematical fixtures.

Only the independent component/adapter executes. Captured code does not run.
The source corpora are read unchanged; no peer implementation is imported.
"""
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
OUT = ROOT / 'work/greeting-reply-94/replay'
OUT.mkdir(parents=True, exist_ok=True)
MAX = (1 << 64) - 1


def projection(row, family):
    expected = row['expected']
    memory = {}
    for cell in expected['cells']:
        if 'hex' in cell:
            for n, byte in enumerate(bytes.fromhex(cell['hex'])):
                memory[cell['offset'] + n] = byte
    tag = memory[0]
    success = tag == (18 if family == 'maps' else 0)
    if success:
        status = 'ok'
        if family == 'maps':
            data = b''.join(bytes.fromhex(r['keyHex']) + b''.join(int(n).to_bytes(8, 'little') for n in r['words']) + bytes([r['byte']]) for r in expected['associations'])
        else:
            length = 6192 if family == 'records' else 65
            data = bytes(memory[n] for n in range(8, 8 + length))
    else:
        offset = 0 if family == 'maps' else 8
        kind = memory[offset]
        if kind == 0:
            needed = int.from_bytes(bytes(memory[offset + 8 + n] for n in range(8)), 'little')
            status = f'e0:{needed}'
        elif kind in (1, 2):
            status = f'e{kind}'
        elif kind == 3:
            status = f'e3:{memory[offset+1]}:{memory[offset+2]}'
        else:
            raise ValueError(('unexpected fixture error kind', kind))
        data = b''
    return f'{status}|{expected["consumed"]}|{expected["charge"]}|{data.hex()}\n'


counts = {}
excluded_rebases = []
with (OUT / 'requests.tsv').open('w') as requests, (OUT / 'expected.tsv').open('w') as expected, (OUT / 'ids.txt').open('w') as ids:
    for source in json.loads((PACKET / 'fixtures/sources.json').read_text()):
        family = source['name']
        path = PACKET / 'fixtures' / (family + '.jsonl.gz')
        assert hashlib.sha256(path.read_bytes()).hexdigest() == source['sha256']
        count = 0
        with gzip.open(path, 'rt') as f:
            for line in f:
                row = json.loads(line)
                inp = row['input']
                if inp['charge'] != 0 or inp.get('mode', 1) != 1:
                    continue
                if family == 'values' and (row.get('family') != 'paired-value' or inp['limit'] < 76):
                    continue
                base = {'records': 24, 'values': 84, 'maps': 56}[family]
                if any(value > MAX - base for value in [row['expected']['charge'], *row['expected']['stores']]):
                    excluded_rebases.append({'family': family, 'id': row['id'], 'reason': 'a recorded charge plus the required greeting prefix exceeds u64'})
                    continue
                prefix = {'records': bytes([0, 0, 0, 2]), 'maps': bytes(36), 'values': bytes(36) + bytes([1]) + bytes(20)}[family]
                requests.write(f'{family}|{min(MAX, inp["limit"] + base)}|{prefix.hex()}{inp["dataHex"]}\n')
                expected.write(projection(row, family))
                ids.write(f'{family}:{row["id"]}\n')
                count += 1
        counts[family] = count

manifest = ROOT / 'src/node94-tcp-frame/Cargo.toml'
command = ['cargo', 'build', '--locked', '--offline', '--release', '--all-features', '--manifest-path', str(manifest), '--message-format=json']
run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
(OUT / 'cargo.log').write_text(run.stdout + run.stderr)
artifacts = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
rlib = next(Path(name) for record in artifacts if record.get('reason') == 'compiler-artifact' and record['target']['name'] == 'node94_tcp_frame' for name in record['filenames'] if name.endswith('.rlib'))
deps = rlib.parent / 'deps' if (rlib.parent / 'deps').is_dir() else rlib.parent
command2 = ['rustc', '--edition=2024', '-C', 'opt-level=2', '-L', f'dependency={deps}', '--extern', f'node94_tcp_frame={rlib}', str(PACKET / 'replay.rs'), '-o', str(OUT / 'replay')]
run = subprocess.run(command2, cwd=ROOT, capture_output=True, text=True)
(OUT / 'rustc.log').write_text(run.stdout + run.stderr)
run.check_returncode()
with (OUT / 'requests.tsv').open() as inp, (OUT / 'actual.tsv').open('w') as out:
    run = subprocess.run([str(OUT / 'replay')], stdin=inp, stdout=out, stderr=subprocess.PIPE, text=True, check=True)
(OUT / 'stderr.log').write_text(run.stderr)
failures = []
with (OUT / 'expected.tsv').open() as expected, (OUT / 'actual.tsv').open() as actual, (OUT / 'ids.txt').open() as ids:
    for index, (want, got, ident) in enumerate(itertools.zip_longest(expected, actual, ids), 1):
        if want != got:
            failures.append({'row': index, 'id': ident.strip() if ident else None, 'expected': want, 'actual': got})
result = {'result': 'PASSED' if not failures else 'FAILED', 'cases': sum(counts.values()), 'counts': counts, 'excluded_rebases': excluded_rebases, 'failures': failures[:20], 'commands': [command, command2], 'scope': 'Mode-1 logical projections, rebased from zero initial charge into a real greeting envelope. Every retained recorded charge/store plus its prefix fits u64. Original corpora remain mathematical predictions, not captured target executions.', 'hashes': {name: hashlib.sha256((OUT/name).read_bytes()).hexdigest() for name in ['requests.tsv', 'expected.tsv', 'actual.tsv', 'ids.txt', 'replay']}}
(PACKET / 'replay-result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['failures','commands','hashes']}, indent=2))
if failures:
    print(json.dumps(failures[:3], indent=2)[:6000])
    sys.exit(1)
