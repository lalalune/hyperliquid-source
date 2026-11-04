#!/usr/bin/env python3
"""Verify closed packet/source inventory and replay authenticated target facts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[3]
P = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
import node115_cli_command_factory as f

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-output',type=Path)
    parser.add_argument('--objdump',default=shutil.which('objdump'))
    args=parser.parse_args()
    manifest=json.loads((P/'MANIFEST.json').read_text())
    expected=set(manifest['files'])
    actual={str(p.relative_to(ROOT).as_posix()) for p in P.rglob('*') if p.is_file() and p.name not in ('MANIFEST.json','MANIFEST.sha256')}
    actual|={'tools/node115_cli_command_factory.py','tests/test_node115_cli_command_factory.py'}
    f.require(expected==actual,'closed file inventory')
    for name,digest in manifest['files'].items():
        p=ROOT/name
        f.require(p.resolve().is_relative_to(ROOT.resolve()) and not p.is_symlink(),'source path')
        f.require(all(not q.is_symlink() for q in [p.parent,*p.parents] if q!=ROOT.parent),'symlink ancestry')
        f.require(hashlib.sha256(p.read_bytes()).hexdigest()==digest,'file digest: '+name)
    hashes=dict(manifest['files'])
    hashes[str((P/'MANIFEST.json').relative_to(ROOT).as_posix())]=hashlib.sha256((P/'MANIFEST.json').read_bytes()).hexdigest()
    sha_text=''.join(digest+'  '+name+'\n' for name,digest in sorted(hashes.items()))
    f.require((P/'MANIFEST.sha256').read_text()==sha_text,'sha256sum inventory')
    blob=(ROOT/'artifacts/node/115/hl-node').read_bytes()
    spec=json.loads((P/'spec.json').read_text())
    record=f.collect(blob,spec)
    canonical=json.dumps(record,indent=2,sort_keys=True)+'\n'
    f.require((P/'records.json').read_bytes()==canonical.encode(),'re-derived records')
    native=json.loads((P/'native-comparison.json').read_text())
    rows=json.loads((P/'instruction-bytes.json').read_text())
    secs=f.sections(blob)
    for n,body in zip(native['functions'],rows,strict=True):
        f.require(n['start']==body['start'] and n['end']==body['end'],'native range')
        raw=(P/n['GNU']).read_bytes()
        f.require(hashlib.sha256(raw).hexdigest()==n['originalStdoutSHA256'],'native stdout digest')
        parsed=[]
        for line in raw.decode().splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m:parsed.append((int(m[1],16),bytes.fromhex(m[2])))
        wanted=[(int(r['va'],16),bytes.fromhex(r['bytes'])) for r in body['rows']]
        f.require(parsed==wanted,'retained independent disassembler rows')
        cursor=int(body['start'],16)
        for address,data in wanted:
            f.require(address==cursor and data==f.read_va(blob,secs,address,len(data)),'contiguous target instruction bytes')
            cursor+=len(data)
        f.require(cursor==int(body['end'],16),'complete native range')
        if args.native_output:
            f.require(bool(args.objdump),'GNU objdump required for native replay')
            args.native_output.mkdir(parents=True,exist_ok=True)
            cmd=[args.objdump,'-d','-w','-Mintel','--start-address='+body['start'],'--stop-address='+body['end'],'artifacts/node/115/hl-node']
            result=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=60)
            (args.native_output/n['GNU']).write_bytes(result.stdout)
            (args.native_output/(n['GNU']+'.stderr')).write_bytes(result.stderr)
            f.require(result.returncode==0,'fresh native exit')
            fresh=[]
            for line in result.stdout.decode().splitlines():
                m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
                if m:fresh.append((int(m[1],16),bytes.fromhex(m[2])))
            f.require(fresh==wanted,'fresh native address-byte comparison')
    print('Verified closed inventory, re-derived records, 15 full native ranges; no target execution')

if __name__=='__main__':
    main()
