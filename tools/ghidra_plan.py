#!/usr/bin/env python3
"""Print a verified, release-specific Ghidra import command; do not launch it."""
import argparse
import json
from pathlib import Path
import shlex

from artifacts import ROOT, check
from doctor import locate_ghidra

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--release', choices=['94', '115'], required=True)
args = p.parse_args()
ghidra = locate_ghidra()
if not ghidra:
    raise SystemExit('Set GHIDRA_HOME to an installation with support/analyzeHeadless')
relative = f'artifacts/node/{args.release}/hl-node'
manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
    raise SystemExit('Invalid artifact manifest: provenance/artifacts.json must be an object with a files list')
for entry in manifest['files']:
    if not isinstance(entry, dict) or 'path' not in entry:
        raise SystemExit('Invalid artifact record in provenance/artifacts.json: entry without path')
item = next((i for i in manifest['files'] if i['path'] == relative), None)
if item is None:
    raise SystemExit(f'No provenance/artifacts.json entry for {relative}')
check(ROOT / relative, item)
project_dir = ROOT / 'work/ghidra'
name = f"hl-node-{args.release}-{item['sha256'][:12]}"
if (project_dir / (name + '.gpr')).exists():
    raise SystemExit('Existing Ghidra project found. Reuse it explicitly; do not reimport or overwrite it.')
command = [str(ghidra / 'support/analyzeHeadless'), str(project_dir), name,
           '-import', str(ROOT / relative), '-processor', 'x86:LE:64:default',
           '-analysisTimeoutPerFile', '1800', '-max-cpu', '4',
           '-log', str(ROOT / 'work' / f'{name}.ghidra.log')]
print('# Static import plan only. Creates a separate analysis project; no node execution.')
print('mkdir -p ' + shlex.quote(str(project_dir)))
print(shlex.join(command))
