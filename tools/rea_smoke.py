#!/usr/bin/env python3
"""Check pinned REA CLI identity and static inspection against authenticated inputs."""
import json
from pathlib import Path
import subprocess
import sys

from artifacts import ROOT, check, load_manifest

version = subprocess.check_output([sys.executable, str(ROOT / 'tools/rea.py'), '--version'], text=True, encoding='utf-8').strip()
config = json.loads((ROOT / 'config/rea.json').read_text())
if version != config['version']:
    raise SystemExit('Unexpected REA CLI version')
try:
    manifest = load_manifest(ROOT)
except ValueError as error:
    raise SystemExit(str(error)) from error
out = ROOT / 'work/rea-smoke'
out.mkdir(parents=True, exist_ok=True)
for release in ['115']:
    relative = config['targets'][release]
    expected = next((i for i in manifest['files'] if i['path'] == relative), None)
    if expected is None:
        raise SystemExit(f'No provenance/artifacts.json entry for {relative}')
    missing = [field for field in ('size', 'sha256') if field not in expected]
    if missing:
        raise SystemExit(f'provenance/artifacts.json entry for {relative} is missing {", ".join(missing)}')
    check(ROOT / relative, expected)
    output = subprocess.check_output([sys.executable, str(ROOT / 'tools/rea.py'), 'inspect-rust-binary', str(ROOT / relative), '--format', 'json'], text=True, encoding='utf-8')
    evidence = json.loads(output)
    observed = evidence['normalized_result']['artifact']
    if observed['sha256'] != expected['sha256'] or observed['bytes'] != expected['size']:
        raise SystemExit('REA analyzed a different artifact')
    if evidence['operation'] != 'inspect_rust_binary':
        raise SystemExit('Unexpected REA operation')
    (out / f'node-{release}-rust.json').write_text(output, encoding='utf-8', newline='\n')
    print(f"REA {version}: #{release} static input verified ({evidence['evidence_id']})")
