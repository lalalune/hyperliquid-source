#!/usr/bin/env python3
"""Compare tools/fde_extents.py output with an independent GNU readelf frame decode."""
import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
FDE = re.compile(r'^([0-9a-f]+) [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)$', re.M)
CIE = re.compile(r'^[0-9a-f]+ [0-9a-f]+ 0+ CIE$', re.M)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=['94', '115'], required=True)
    p.add_argument('--readelf', default='readelf')
    args = p.parse_args()
    binary = ROOT / f'artifacts/node/{args.release}/hl-node'
    # The reported binary_sha256 comes from the fde_extents summary, so the
    # bytes readelf is about to parse must first be verified against the
    # pinned manifest, exactly as tools/fde_extents.py does before it
    # generates that summary. Without this, a substituted or corrupted
    # binary still cross-checks as identical under the pinned digest.
    sys.path.insert(0, str(ROOT / 'tools'))
    from artifacts import check
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                if i['path'] == f'artifacts/node/{args.release}/hl-node')
    check(binary, item)
    summary = json.loads((ROOT / f'work/index/node-{args.release}-fde.json').read_text())
    with (ROOT / f'work/index/node-{args.release}-fde.tsv').open() as handle:
        ours = {(int(r['start_va'], 16), int(r['end_va'], 16), int(r['fde_va'], 16))
                for r in csv.DictReader(handle, delimiter='\t')}
    sections = subprocess.run([args.readelf, '-SW', str(binary)], capture_output=True, text=True, check=True).stdout
    frame = next(line.split('.eh_frame ')[1].split() for line in sections.splitlines() if ' .eh_frame ' in line)
    frame_va = int(frame[1], 16)
    dump = subprocess.run([args.readelf, '--wide', '--debug-dump=frames', str(binary)],
                          capture_output=True, text=True, check=True).stdout
    theirs = {(int(m[2], 16), int(m[3], 16), frame_va + int(m[1], 16)) for m in FDE.finditer(dump)}
    version = subprocess.run([args.readelf, '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    result = {'release': args.release, 'binary_sha256': summary['binary_sha256'], 'readelf': version,
              'readelf_cies': len(CIE.findall(dump)), 'tool_cies': summary['cie_records'],
              'readelf_fdes': len(theirs), 'tool_fdes': len(ours),
              'only_in_tool': len(ours - theirs), 'only_in_readelf': len(theirs - ours)}
    result['identical'] = ours == theirs and result['readelf_cies'] == result['tool_cies']
    print(json.dumps(result, indent=2))
    if not result['identical']:
        raise SystemExit('FDE extents differ from readelf')


if __name__ == '__main__':
    main()
