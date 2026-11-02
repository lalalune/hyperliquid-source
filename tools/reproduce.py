#!/usr/bin/env python3
"""Reproduce inventories for the active node and optional analysis fixture."""
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = root / 'work/reproduced'
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(root / 'tools/artifacts.py'), 'verify'], check=True)
for relative, name in [('artifacts/node/115/hl-node', 'hl-node-115'),
                       ('artifacts/visor/captured/hl-visor', 'hl-visor')]:
    path = out / f'{name}.inventory.json'
    result = subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/inv.py'),
                             str(root / relative), str(path)], capture_output=True, check=True)
    (out / f'{name}.stdout').write_bytes(result.stdout)
    (out / f'{name}.stderr').write_bytes(result.stderr)
    expected = root / f'research/imported/{name}.inventory.json'
    if json.loads(path.read_text()) != json.loads(expected.read_text()):
        raise ValueError(f'Inventory differs: {name}')
    print(f'Reproduced {name} inventory.')
