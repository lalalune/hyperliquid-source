#!/usr/bin/env python3
"""Regenerate the evidence from authenticated local inputs and verify the manifest."""
import hashlib
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('evm_rpc_method_path', ROOT / 'tools/evm_rpc_method_path.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def main():
    for line in (HERE / 'MANIFEST.sha256').read_text().splitlines():
        sha, filename = line.split('  ', 1)
        if hashlib.sha256((HERE / filename).read_bytes()).hexdigest() != sha:
            raise ValueError('manifest mismatch: ' + filename)
    inputs = {k: (ROOT / k).read_bytes() for k in mod.INPUTS}
    result = mod.build((ROOT / 'artifacts/node/94/hl-node').read_bytes(),
                       (ROOT / 'artifacts/node/115/hl-node').read_bytes(), inputs)
    if mod.render(result) != (HERE / 'evm-rpc-method-path.json').read_bytes():
        raise ValueError('regenerated JSON differs')
    if result['method_count'] != 26 or result['fde_count'] != 121299:
        raise ValueError('unexpected inventory')
    print('PASS')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise SystemExit(1)
