#!/usr/bin/env python3
"""Capture only authenticated disassembly; no original instructions are executed."""
import argparse
import json
from pathlib import Path
import subprocess
import collect


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    collect.load(args.root)
    args.output.mkdir(exist_ok=False, parents=True)
    (args.output / 'native').mkdir()
    spec = Path(__file__).with_name('spec.json').read_bytes()
    (args.output / 'spec.json').write_bytes(spec)
    versions = {}
    for tool in ['objdump', 'llvm-objdump']:
        versions[tool] = subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
        for name, lo, hi, _ in collect.RANGES:
            cmd = [tool, '-d', '--start-address=' + hex(lo), '--stop-address=' + hex(hi)]
            if tool == 'objdump':
                cmd += ['-M', 'intel', '--insn-width=16']
            cmd += ['artifacts/node/115/hl-node']
            (args.output / 'native' / (name + '.' + tool + '.txt')).write_bytes(
                subprocess.check_output(cmd, cwd=args.root))
    (args.output / 'native/tools.json').write_text(json.dumps(versions, sort_keys=True, indent=2) + '\n')
    records = collect.collect(args.root, args.output)
    (args.output / 'records.json').write_text(json.dumps(records, sort_keys=True, indent=2) + '\n')
    print('Authenticated static export complete; no captured execution or emulation.')


if __name__ == '__main__':
    main()
