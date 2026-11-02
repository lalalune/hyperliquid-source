#!/usr/bin/env python3
"""Compare full-range GNU/LLVM decodes; retain only the bounded caller link."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import verify


def parse(text):
    rows=[]
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+?)\s*$',line)
        if m:
            rows.append((int(m[1],16),m[2].replace(' ',''),line))
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gnu',default='objdump')
    p.add_argument('--llvm',required=True)
    p.add_argument('--binary',type=Path,default=verify.ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    verify.require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == verify.SHA,'target SHA-256 mismatch')
    args.out.mkdir(parents=True,exist_ok=True)
    report=[]
    for provider,exe,options in (('gnu',args.gnu,['-M','intel','--insn-width=16']),
                                 ('llvm',args.llvm,['--x86-asm-syntax=intel'])):
        version=subprocess.check_output([exe,'--version'],text=True).splitlines()[0]
        for f in verify.frozen():
            command=[exe,'-d',*options,'--start-address='+f['start'],'--stop-address='+f['end'],str(args.binary)]
            result=subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            all_rows=parse(result.stdout)
            verify.require(len(all_rows) == f['decoded_count'],'full decoded count changed')
            if f['role'] == 'caller_link':
                digest=hashlib.sha256(json.dumps([(hex(a),b) for a,b,_ in all_rows],separators=(',',':')).encode()).hexdigest()
                verify.require(digest == f['full_decode_sha256'],'complete caller decode changed')
                rows=[r for r in all_rows if 0x3709f41 <= r[0] < 0x3709f65]
                retained='Selected verbatim instruction rows from full-FDE decode; other caller rows are not retained.\n'+'\n'.join(r[2] for r in rows)+'\n'
            else:
                rows=all_rows
                retained=result.stdout
            expected=[(int(i['va'],16),i['bytes']) for i in f['instructions']]
            verify.require([(a,b) for a,b,_ in rows] == expected,'instruction boundaries or bytes changed')
            (args.out/(f['role']+'.'+provider+'.txt')).write_text(retained)
            report.append(dict(provider=provider,version=version,command=command,
                               role=f['role'],decoded_count=len(all_rows),retained_count=len(rows),
                               full_stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                               retained_stdout_sha256=hashlib.sha256(retained.encode()).hexdigest(),stderr=result.stderr))
    (args.out/'agreement.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('PASS: GNU/LLVM agree on 415 bounded instructions and all 600 caller boundaries; 8 caller instructions retained')


if __name__ == '__main__':
    main()
