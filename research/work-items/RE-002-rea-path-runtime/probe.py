"""Compare actual REA CLI launches with two installed Node runtimes.

Use an incompatible runtime first and a supported runtime later in PATH.
The pinned rea-agents package must already be installed in the checkout.
This does not install/register anything or open a captured target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def probe(first, later):
    root = Path(__file__).resolve().parents[3]
    launcher = root / 'tools/rea.py'
    first, later = first.resolve(), later.resolve()
    versions = [subprocess.check_output([str(p), '--version'], text=True).strip()
                for p in (first, later)]
    package = json.loads((root / 'node_modules/rea-agents/package.json').read_text(encoding='utf-8'))
    env = dict(os.environ)
    env.pop('REA_NODE', None)
    env['PATH'] = os.pathsep.join([str(first.parent), str(later.parent), env.get('PATH', '')])
    rows = []
    for name, override in [('automatic', None), ('explicit-incompatible', first), ('explicit-compatible', later)]:
        selected = dict(env)
        if override is not None:
            selected['REA_NODE'] = str(override)
        result = subprocess.run([sys.executable, str(launcher), '--version'],
                                cwd=root, env=selected, text=True, capture_output=True, timeout=60)
        rows.append({'case': name, 'exit': result.returncode,
                     'stdout': result.stdout.strip(), 'stderr': result.stderr.strip()})
    return {'runtimeVersionsInPathOrder': versions, 'reaVersion': package['version'],
            'launcherSha256': hashlib.sha256(launcher.read_bytes()).hexdigest(),
            'cases': rows, 'capturedTargetExecuted': False, 'registrationChanged': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--first', type=Path, required=True)
    parser.add_argument('--later', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = probe(args.first, args.later)
    args.out.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))
    raise SystemExit(0 if [r['exit'] for r in result['cases']] == [0, 1, 0] else 1)
