#!/usr/bin/env python3
"""Export complete bound ranges with a second static decoder. Never executes ELF."""
import gzip,hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def main():
    bindings=json.loads(gzip.decompress((HERE/'bindings.json.gz').read_bytes()))
    bodies=bindings['bodies']+[c['body'] for c in bindings['incoming']]
    outputs=[];commands=[]
    for b in bodies:
        command=[os.environ.get('GNU_OBJDUMP','/opt/homebrew/opt/binutils/bin/objdump'),'-d','-M','intel','--insn-width=16',f'--start-address={b["start"]}',f'--stop-address={b["end"]}','artifacts/node/115/hl-node']
        p=subprocess.run(command,cwd=ROOT,capture_output=True,check=True)
        outputs.append(dict(start=b['start'],stdout=p.stdout.decode(),stderr=p.stderr.decode()))
        commands.append(dict(start=b['start'],argv=['$GNU_OBJDUMP',*command[1:]],exit_code=p.returncode,stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),stderr_sha256=hashlib.sha256(p.stderr).hexdigest()))
    (HERE/'disassembly.json.gz').write_bytes(gzip.compress((json.dumps(outputs,sort_keys=True)+'\n').encode(),mtime=0))
    (HERE/'disassembly-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    print(json.dumps(dict(bodies=len(bodies),bytes=sum(b['length'] for b in bodies),instructions=sum(len(b['instructions']) for b in bodies))))
if __name__=='__main__':main()
