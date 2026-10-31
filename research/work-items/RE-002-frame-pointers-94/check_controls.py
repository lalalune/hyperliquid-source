#!/usr/bin/env python3
"""Exercise the real survey CLIs with corrupt inputs in a temporary directory."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(script, arguments, expected_error, destination):
    result = subprocess.run([sys.executable, str(PACKET / script), *arguments],
                            cwd=ROOT, text=True, capture_output=True, timeout=60)
    require(result.returncode != 0 and expected_error in result.stderr,
            f'{script} did not reject the control: {result.stderr}')
    require(not destination.exists(), f'{script} published output for a rejected control')
    return {'script': script, 'exit': result.returncode, 'output_created': False}


def main():
    results = []
    (ROOT / 'work').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='frame-controls-', dir=ROOT / 'work') as directory:
        scratch = Path(directory)
        original = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
        changed = bytearray(original)
        changed[0] ^= 1
        for name, data in [('truncated', original[:64]), ('one-byte-changed', changed)]:
            source = scratch / name
            source.write_bytes(data)
            for script in ('survey.py', 'check_readelf.py'):
                destination = scratch / (name + '-' + script + '-output')
                arguments = ['--input', str(source)]
                if script == 'survey.py':
                    arguments += ['--output-dir', str(destination)]
                else:
                    arguments += ['--summary', str(PACKET / 'summary.json'),
                                  '--output', str(destination)]
                result = run(script, arguments, 'Expected exact node #94', destination)
                results.append({'case': name, **result})
        summary = json.loads((PACKET / 'summary.json').read_text(encoding='utf-8'))
        summary['cfa_register_sets']['7'] += 1
        manifest = scratch / 'wrong-count.json'
        manifest.write_text(json.dumps(summary), encoding='utf-8')
        destination = scratch / 'wrong-count-output.json'
        result = run('check_readelf.py', ['--input', str(ROOT / 'artifacts/node/94/hl-node'),
                     '--summary', str(manifest), '--output', str(destination)],
                     'Independent counts differ', destination)
        results.append({'case': 'altered-cfa-count', **result})
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
