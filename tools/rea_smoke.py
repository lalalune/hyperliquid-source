#!/usr/bin/env python3
"""Check pinned REA CLI identity and static inspection against authenticated inputs."""
import json
from pathlib import Path
import subprocess
import sys

from artifacts import ROOT, check

version = subprocess.check_output([sys.executable, str(ROOT / 'tools/rea.py'), '--version'], text=True).strip()
config = json.loads((ROOT / 'config/rea.json').read_text())
if version != config['version']:
    raise SystemExit('Unexpected REA CLI version')
manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text())
if not isinstance(manifest, dict) or not isinstance(manifest.get('files'), list):
    raise SystemExit('Invalid artifact manifest: provenance/artifacts.json must be an object with a files list')
for entry in manifest['files']:
    if not isinstance(entry, dict) or 'path' not in entry:
        raise SystemExit('Invalid artifact record in provenance/artifacts.json: entry without path')
out = ROOT / 'work/rea-smoke'
out.mkdir(parents=True, exist_ok=True)
for release in ['94', '115']:
    relative = config['targets'][release]
    expected = next((i for i in manifest['files'] if i['path'] == relative), None)
    if expected is None:
        raise SystemExit(f'No provenance/artifacts.json entry for {relative}')
    check(ROOT / relative, expected)
    output = subprocess.check_output([sys.executable, str(ROOT / 'tools/rea.py'), 'inspect-rust-binary', str(ROOT / relative), '--format', 'json'], text=True)
    evidence = json.loads(output)
    observed = evidence['normalized_result']['artifact']
    if observed['sha256'] != expected['sha256'] or observed['bytes'] != expected['size']:
        raise SystemExit('REA analyzed a different artifact')
    if evidence['operation'] != 'inspect_rust_binary':
        raise SystemExit('Unexpected REA operation')
    (out / f'node-{release}-rust.json').write_text(output)
    print(f"REA {version}: #{release} static input verified ({evidence['evidence_id']})")
