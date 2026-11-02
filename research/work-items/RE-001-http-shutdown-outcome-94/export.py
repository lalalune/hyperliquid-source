#!/usr/bin/env python3
"""Re-export the five complete shutdown FDEs; no captured code execution."""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('shutdown_verify',HERE/'verify.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=v.ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=v.ROOT/'work/http-shutdown-outcome-94')
    p.add_argument('--objdump',default='objdump')
    p.add_argument('--capstone',type=Path,help='Optional existing Capstone module directory; does not install')
    a=p.parse_args()
    if a.capstone:sys.path.insert(0,str(a.capstone))
    import capstone
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    data=a.binary.read_bytes()
    if hashlib.sha256(data).hexdigest()!=v.TARGET:raise ValueError('Wrong node94 capture identity')
    # Recheck semantic anchors/FDEs/relocations before exporting.
    v.observe(data);secs=v.sections(data);md=Cs(CS_ARCH_X86,CS_MODE_64)
    exports={};raw=[];metrics=[]
    a.out.mkdir(parents=True,exist_ok=True)
    for start,end,fde,digest in v.RANGES:
        maps=[s['offset']+start-s['address'] for s in secs if s['type']!=8 and s['address']<=start and end<=s['address']+s['size']]
        if len(maps)!=1:raise ValueError('Ambiguous FDE VA')
        body=data[maps[0]:maps[0]+end-start];ins=list(md.disasm(body,start))
        if sum(i.size for i in ins)!=len(body):raise ValueError('Incomplete disassembly')
        run=subprocess.run([a.objdump,'-d','--wide','--insn-width=16','-M','intel',
            '--start-address='+str(start),'--stop-address='+str(end),str(a.binary)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=True)
        (a.out/(f'{start:x}.stderr.txt')).write_bytes(run.stderr)
        pairs=[]
        for line in run.stdout.decode('utf8').splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m and start<=int(m[1],16)<end:pairs.append((int(m[1],16),bytes.fromhex(m[2])))
        if pairs!=[(i.address,bytes(i.bytes)) for i in ins]:raise ValueError('Independent decoder mismatch')
        exports[f'{start:x}']={'start':hex(start),'end':hex(end),'fde':hex(fde),
            'bytes':len(body),'sha256':digest,'instructions':[{'va':hex(i.address),
            'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}
        raw.append(b'\n=== '+f'{start:x}'.encode()+b'.objdump.txt ===\n'+run.stdout)
        metrics.append({'start':hex(start),'instructions':len(ins),'bytes':len(body)})
        print(json.dumps(metrics[-1]),flush=True)
    (a.out/'disassembly.json.gz').write_bytes(gzip.compress(json.dumps(exports,indent=2).encode(),mtime=0))
    (a.out/'gnu.objdump.txt.gz').write_bytes(gzip.compress(b''.join(raw),mtime=0))
    result={'capstoneWrapperVersion':capstone.__version__,'capstoneApiVersion':list(capstone.cs_version()),
            'objdumpVersion':subprocess.run([a.objdump,'--version'],stdout=subprocess.PIPE,check=True,timeout=10).stdout.decode().splitlines()[0],
            'pythonVersion':sys.version.split()[0],'ranges':metrics,'targetExecuted':False,
            'normalizations':[],'archiveHashes':{n:hashlib.sha256((a.out/n).read_bytes()).hexdigest()
            for n in ['disassembly.json.gz','gnu.objdump.txt.gz']}}
    # Both freshly generated exports are checked against the capture again.
    v.verify_exports(data,a.out)
    (a.out/'export-report.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
if __name__=='__main__':main()
