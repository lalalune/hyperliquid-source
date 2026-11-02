#!/usr/bin/env python3
"""Validate retained static facts; never execute the captured target."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from elf_index import sections
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

def require(ok, message):
    if not ok:
        raise ValueError(message)

def context(path):
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET, 'Target SHA mismatch')
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    return data, secs, fdes

def window(ctx, va, size):
    data, secs, _ = ctx
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'Ambiguous executable mapping')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return off, data[off:off + size]

def check(ctx, evidence, raw):
    require(evidence['target'] == {'release': 'node94', 'sha256': TARGET}, 'Target identity mismatch')
    require(len(evidence['ranges']) == 5, 'Expected five ranges')
    seen = set()
    decoded = {}
    for row in evidence['ranges']:
        va = int(row['start'], 16)
        require(va not in seen, 'Duplicate range')
        seen.add(va)
        size = row['requestedBytes']
        off, data = window(ctx, va, size)
        require(hex(off) == row['fileOffset'], 'File offset mismatch')
        require(hashlib.sha256(data).hexdigest() == row['sha256'], 'Body hash mismatch')
        fs = [f for f in ctx[2] if f['start'] == va]
        require(len(fs) == 1, 'FDE start not unique')
        f = fs[0]
        require({k: hex(v) if isinstance(v, int) else v for k,v in f.items()} == row['fde'], 'FDE mismatch')
        require(f['end'] - va == size, 'FDE extent mismatch')
        if not row.get('retainedParent'):
            decoded[va] = (va, va + size)
    require(seen == {0x53c3c70, 0x53c4ec0, 0x53c74c0, 0x510ab70, 0x53c7490}, 'Range identity mismatch')
    require(hashlib.sha256(raw.encode()).hexdigest() == evidence['disassemblySha256'], 'Disassembly hash mismatch')
    positions = {v: v for v in decoded}
    for line in raw.splitlines():
        if not line.strip():
            continue
        address, rest = line.split(': ', 1)
        va = int(address, 16)
        encoded = rest.split(' ', 1)[0]
        body = bytes.fromhex(encoded)
        ranges = [v for v,(start,end) in decoded.items() if start <= va < end]
        require(len(ranges) == 1, 'Disassembly outside selected ranges')
        start = ranges[0]
        require(positions[start] == va, 'Disassembly overlap or gap')
        _, actual = window(ctx, va, len(body))
        require(actual == body, 'Disassembly bytes mismatch')
        positions[start] += len(body)
    require(all(positions[v] == end for v,(_,end) in decoded.items()), 'Incomplete disassembly')
    for a in evidence['anchors']:
        expected = bytes.fromhex(a['bytes'])
        _, actual = window(ctx, int(a['va'],16), len(expected))
        require(actual == expected, 'Instruction anchor mismatch')
    require(len(evidence['anchors']) == 10, 'Expected ten instruction anchors')
    require([int(e['elements']) for e in evidence['analyticalEdges']] == [0,1,2,2147483649,4294967296], 'Analytical edge coverage mismatch')
    for edge in evidence['analyticalEdges']:
        count = int(edge['elements'])
        stored = (count - 1) & 0xffffffff
        require(hex(stored) == edge['parentStored'] and (stored < count) == edge['guard'], 'Analytical edge mismatch')
    return {'ranges':len(seen),'retainedDisassemblyBytes':sum(end-start for start,end in decoded.values()),'instructionAnchors':len(evidence['anchors'])}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifact', type=Path, default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--controls', action='store_true')
    args = p.parse_args()
    manifest = (HERE/'MANIFEST.sha256').read_text().splitlines()
    expected_names = {'README.md','VALIDATION.md','evidence.json','disassembly.txt','verify.py'}
    require(len(manifest) == len(expected_names), 'Manifest file count mismatch')
    names = set()
    for row in manifest:
        digest, name = row.split('  ',1)
        require(name in expected_names and name not in names, 'Manifest filename mismatch')
        require(hashlib.sha256((HERE/name).read_bytes()).hexdigest() == digest, 'Manifest digest mismatch')
        names.add(name)
    evidence = json.loads((HERE/'evidence.json').read_text())
    raw = (HERE/'disassembly.txt').read_text()
    require(hashlib.sha256((ROOT/'tools/fde_extents.py').read_bytes()).hexdigest() == evidence['tools']['parserSha256'], 'Unwind parser version mismatch')
    ctx = context(args.artifact)
    result = check(ctx,evidence,raw)
    rejected = []
    if args.controls:
        for name in ['target','offset','extent','fde','body','anchor','duplicate','edge','disassembly']:
            e = copy.deepcopy(evidence)
            text = raw
            if name == 'target': e['target']['sha256'] = '0'*64
            elif name == 'offset': e['ranges'][0]['fileOffset'] = '0x0'
            elif name == 'extent': e['ranges'][0]['requestedBytes'] += 1
            elif name == 'fde': e['ranges'][0]['fde']['cie'] = '0x0'
            elif name == 'body': e['ranges'][0]['sha256'] = '0'*64
            elif name == 'anchor': e['anchors'][2]['bytes'] = '0f9cc0'
            elif name == 'duplicate': e['ranges'][1] = copy.deepcopy(e['ranges'][0])
            elif name == 'edge': e['analyticalEdges'][0]['guard'] = True
            else: text = raw.replace('f30f1efa','f30f1efb',1); e['disassemblySha256'] = hashlib.sha256(text.encode()).hexdigest()
            try:
                check(ctx,e,text)
            except ValueError:
                rejected.append(name)
            else:
                raise ValueError('Corruption accepted: '+name)
    print(json.dumps({**result,'controlsRejected':rejected,'targetExecuted':False,'semanticExecutionOrEquivalence':False},sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
