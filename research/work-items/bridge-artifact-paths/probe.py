#!/usr/bin/env python3
"""Run the bridge CLI on four paths to the same authenticated node #94 bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        raise SystemExit('Use a new, empty output directory; stale reports are not evidence')
    args.out.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'artifacts/node/94/hl-node'
    if sha(source.read_bytes()) != DIGEST:
        raise SystemExit('Pinned node #94 identity mismatch')
    rows = []
    with tempfile.TemporaryDirectory(prefix='bridge-artifact-input-') as directory:
        external = Path(directory) / 'verified-node94'
        shutil.copyfile(source, external)
        cases = [('default', []),
                 ('relative', ['--artifact', 'artifacts/node/94/hl-node']),
                 ('absolute', ['--artifact', str(source)]),
                 ('external', ['--artifact', str(external)])]
        for name, options in cases:
            output = args.out / name
            run = subprocess.run(
                [sys.executable, 'tools/bridge_inventory.py', *options,
                 '--out', str(output)], cwd=ROOT, capture_output=True,
                text=True, timeout=120,
            )
            error = run.stderr.replace(str(ROOT), '<checkout>').replace(directory, '<external-input>')
            (args.out / (name + '.stderr.txt')).write_text(error)
            record = json.loads(run.stdout) if run.returncode == 0 else None
            row = {'case': name, 'exit': run.returncode,
                   'report_written': (output / 'bridge-inventory.json').is_file(),
                   'error': error.splitlines()[-1] if error else None,
                   'artifact_label': record['artifact'] if record else None,
                   'stdout_sha256': sha(run.stdout.encode()) if record else None}
            if record:
                record.pop('artifact')
                row['facts_sha256_excluding_artifact_label'] = sha(
                    json.dumps(record, sort_keys=True, separators=(',', ':')).encode())
                row['excerpts'] = {p.name: sha(p.read_bytes()) for p in sorted(output.glob('*.bin'))}
            rows.append(row)
    result = {'target_release': '94', 'target_sha256': DIGEST,
              'source_tool_sha256': sha((ROOT / 'tools/bridge_inventory.py').read_bytes()),
              'captured_binary_executed': False, 'cases': rows}
    text = json.dumps(result, indent=2) + '\n'
    (args.out / 'result.json').write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
