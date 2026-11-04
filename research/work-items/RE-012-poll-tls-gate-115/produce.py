#!/usr/bin/env python3
"""Export selected static native ranges using installed tools, without execution."""
import json
from pathlib import Path
import subprocess
import sys

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
sys.path.insert(0,str(PACKET))
from collect import RANGES, load

load(ROOT)  # Authenticate before invoking static disassemblers.
(PACKET/'native').mkdir(exist_ok=True)
versions={}
for tool,exe,args in [('gnu','objdump',['-d','-M','intel','--insn-width=16']),
                      ('llvm','llvm-objdump-18',['-d','--x86-asm-syntax=intel'])]:
    versions[tool]=subprocess.check_output([exe,'--version'],text=True).splitlines()[0]
    for name,a,b,*_ in [*RANGES,('sender-callsite',0x2b7b071,0x2b7b090)]:
        command=[exe,*args,f'--start-address={hex(a)}',f'--stop-address={hex(b)}','artifacts/node/115/hl-node']
        (PACKET/'native'/f'{name}.{tool}.objdump').write_bytes(subprocess.check_output(command,cwd=ROOT))
versions['python']=sys.version.split()[0]
(PACKET/'producer.json').write_text(json.dumps(versions,indent=2,sort_keys=True)+'\n')
