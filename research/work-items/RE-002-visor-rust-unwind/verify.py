#!/usr/bin/env python3
"""Reproduce this bounded static packet; never execute the captured visor."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import visor_rust_unwind as subject

pins = json.loads((HERE/'source-sha256.json').read_text())
for path, digest in pins.items():
    if hashlib.sha256((ROOT/path).read_bytes()).hexdigest() != digest:
        raise SystemExit('Packet source pin differs: '+path)
facts, exports, versions = subject.collect(ROOT/'artifacts/visor/captured/hl-visor')
if facts != json.loads((HERE/'observed/ownership.json').read_text()):
    raise SystemExit('Reproduced ownership facts differ')
recorded = json.loads((HERE/'observed/toolchain.json').read_text())
if versions == recorded:
    for name, text in exports.items():
        if text != (HERE/'observed'/name).read_text():
            raise SystemExit('Same-toolchain native export differs: '+name)
    print('Ownership facts and all11 native exports reproduce byte-identically.')
else:
    print('Ownership facts match; both native byte/boundary checks pass.')
    print('Tool versions differ: native display-text equality NOT CLAIMED.')
print(json.dumps(facts['denominator'],sort_keys=True))
