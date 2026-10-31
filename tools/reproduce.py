#!/usr/bin/env python3
"""Regenerate inventories and the preserved heuristic literal classification."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

from source_files import rust_files

root = Path(__file__).resolve().parents[1]
out = root / 'work/reproduced'
out.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(root / 'tools/artifacts.py'), 'verify'], check=True)
for release in ['94', '115']:
    name = f'hl-node-{release}.inventory.json'
    subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/inv.py'),
                    str(root / f'artifacts/node/{release}/hl-node'), str(out / name)], check=True)
    if json.loads((out / name).read_text()) != json.loads((root / 'research/imported' / name).read_text()):
        raise ValueError(f'Inventory differs: {name}')
name = 'hl-visor.inventory.json'
subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/inv.py'),
                str(root / 'artifacts/visor/captured/hl-visor'), str(out / name)], check=True)
if json.loads((out / name).read_text()) != json.loads((root / 'research/imported' / name).read_text()):
    raise ValueError(f'Inventory differs: {name}')
name = 'can1357-literal-classes.json'
# The imported classifier intentionally walks its whole input directory.
# Give it the same committed Rust membership as the other pinned consumers,
# preserving the imported tool bytes and the reference's original contents.
reference = root / 'references/can1357-hl'
with tempfile.TemporaryDirectory(prefix='hl-literal-inputs-') as temporary:
    view = Path(temporary)
    for source in rust_files(reference):
        target = view / source.relative_to(reference)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    subprocess.run([sys.executable, '-I', str(root / 'tools/legacy/drift.py'),
                    str(view), str(root / 'artifacts/node/94/hl-node'),
                    str(root / 'artifacts/node/115/hl-node'), str(out / 'can1357-literal-classes.raw.json')], check=True)
old = json.loads((root / 'research/imported' / name).read_text())
new = json.loads((out / 'can1357-literal-classes.raw.json').read_text())
if old['counts'] != new['counts']:
    raise ValueError('Raw classification no longer reproduces the imported aggregate counts')
# Preserve the original item-level refinements as explicit, auditable labels.
# These labels are imported evidence, not new semantic validation.
import collections
items = {(i['crate'], i['literal']): i for i in new['items']}
for correction in json.loads((root / 'provenance/literal-overrides.json').read_text())['overrides']:
    item = items[(correction['crate'], correction['literal'])]
    if item['class'] != correction['from']:
        raise ValueError('Override precondition changed')
    item['class'] = correction['to']
new['counts'] = dict(collections.Counter(i['class'] for i in new['items']))
per = collections.defaultdict(collections.Counter)
for item in new['items']:
    per[item['crate']][item['class']] += 1
new['per_crate'] = {k: dict(v) for k, v in per.items()}
(out / name).write_text(json.dumps(new, indent=1) + '\n')
def canonical(d):
    return sorted((i['crate'], i['literal'], i['class']) for i in d['items'])
if canonical(old) != canonical(new):
    raise ValueError('Classification differs from imported evidence; retain both and investigate')
print('Inventories, raw counts and refined item classifications reproduce the imported evidence.')
print('Refined counts:', new['counts'])
