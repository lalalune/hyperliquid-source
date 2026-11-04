#!/usr/bin/env python3
"""Re-export only the five authenticated ELF ranges through installed native tools."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
import collect
def main():
    a=argparse.ArgumentParser();a.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[3])
    a.add_argument('--output',required=True,type=Path);args=a.parse_args()
    collect.load(args.root) # authenticate before invoking either native parser
    args.output.mkdir(parents=True,exist_ok=False);(args.output/'native').mkdir()
    versions={}
    for tool in ('objdump','llvm-objdump'):
        versions[tool]=subprocess.check_output([tool,'--version'],text=True).splitlines()[0]
        for name,lo,hi,_,_ in collect.RANGES:
            command=[tool,'-d','--start-address='+hex(lo),'--stop-address='+hex(hi)]
            if tool=='objdump':command+=['-M','intel','--insn-width=16']
            command+=['artifacts/node/115/hl-node']
            (args.output/'native'/f'{name}.{tool}.txt').write_bytes(subprocess.check_output(command,cwd=args.root))
    versions['python']=sys.version.split()[0]
    (args.output/'native/tools.json').write_text(json.dumps(versions,indent=2,sort_keys=True)+'\n')
    records=collect.collect(args.root,args.output)
    (args.output/'records.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
    print('Static native captures and records written; no target execution/emulation')
if __name__=='__main__':main()
