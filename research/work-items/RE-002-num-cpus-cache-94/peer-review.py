"""Independent exact-rational nearest-neighbor audit, not instruction execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

MAX=(1<<64)-1
TOP=0x43f0000000000000

def rational(bits):
    exponent=(bits>>52)&2047;mantissa=bits&((1<<52)-1)
    if exponent:
        mantissa|=1<<52;power=exponent-1075
    else:power=-1074
    return (mantissa<<power,1) if power>=0 else (mantissa,1<<-power)

def nearest(n,d):
    # Monotone search of the ordered positive binary64 bit space. Unlike the
    # author oracle, no exponent estimate or rounded significand is used.
    lo,hi=0,TOP+1
    while lo+1<hi:
        mid=(lo+hi)//2;a,b=rational(mid)
        if a*d<=n*b:lo=mid
        else:hi=mid
    a,b=rational(lo)
    if a*d==n*b:return lo
    c,e=rational(hi)
    lower=(n*b-a*d)*e
    upper=(c*d-n*e)*b
    return lo if lower<upper or (lower==upper and lo%2==0) else hi

def independent(row):
    q,p,l=row['quota'],row['period'],row['logical']
    if p==0:return dict.fromkeys(['quota_bits','period_bits','ratio_bits','rounded_quota','store'])
    qb,pb=nearest(q,1),nearest(p,1)
    qn,qd=rational(qb);pn,pd=rational(pb)
    rb=nearest(qn*pd,qd*pn);rn,rd=rational(rb)
    quotient,remainder=divmod(rn,rd);rounded=min(MAX,quotient+bool(remainder))
    return {'quota_bits':f'{qb:016x}','period_bits':f'{pb:016x}','ratio_bits':f'{rb:016x}',
            'rounded_quota':rounded,'store':None if rounded==0 else min(rounded,l)}

def main(args):
    root=args.root.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    packet=root/'research/work-items/RE-002-num-cpus-cache-94'
    inputs=json.loads((packet/'oracle/vectors.json').read_text());fail=[]
    for index,row in enumerate(inputs):
        want=independent(row)
        if any(row[k]!=v for k,v in want.items()):fail.append({'index':index,'row':row,'independent':want})
    sys.path.insert(0,str(root/'tools'))
    from socket_calls_static import Image
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    data=(root/'artifacts/node/94/hl-node').read_bytes();digest=hashlib.sha256(data).hexdigest()
    assert digest=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
    image=Image(data);md=Cs(CS_ARCH_X86,CS_MODE_64);ranges=[]
    for start,end in [(0x4e04830,0x4e061bd),(0x4e061c0,0x4e061d2),(0x4e06870,0x4e069a8),(0x565f670,0x565f6e7)]:
        assert image.fde_of(start)==(start,end)
        body=image.read(start,end-start);rows=list(md.disasm(body,start));assert sum(i.size for i in rows)==len(body)
        argv=['/opt/homebrew/opt/binutils/bin/objdump','-d','-M','intel','--insn-width=16',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(root/'artifacts/node/94/hl-node')]
        p=subprocess.run(argv,capture_output=True);assert p.returncode==0
        (out/f'{start:x}.gnu.stdout').write_bytes(p.stdout)
        ranges.append({'start':hex(start),'end':hex(end),'bytes':len(body),'instructions':len(rows),'sha256':hashlib.sha256(body).hexdigest(),'gnu_stdout_sha256':hashlib.sha256(p.stdout).hexdigest()})
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data);segments=[]
    for i in range(header[10]):
        ph=struct.unpack_from('<IIQQQQQQ',data,header[5]+i*header[9])
        if ph[0]==1 and ph[3]<=0x57883f8 and 0x5788400<=ph[3]+ph[6]:segments.append(ph)
    assert len(segments)==1 and segments[0][3]+segments[0][5]<=0x57883f8
    p=subprocess.run([sys.executable,'-B','-O',str(packet/'verify.py')],cwd=root,capture_output=True)
    (out/'static-verify.stdout').write_bytes(p.stdout);(out/'static-verify.stderr').write_bytes(p.stderr)
    reviewed=[packet/'README.md',packet/'PROOF.md',packet/'rust/src/lib.rs',packet/'rust/src/main.rs',packet/'preparation/build_oracle.py',packet/'oracle/vectors.json',packet/'oracle/FREEZE.json',root/'tools/cpu_cache_static.py',root/'tests/test_cpu_cache_static.py']
    result={'target_sha256':digest,'reviewed_sha256':{str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in reviewed},
            'independent_oracle':'Monotone positive-binary64 bit-space search; exact rational nearest-neighbor distances and parity ties. No import of author oracle or host float arithmetic.',
            'vectors':len(inputs),'mismatches':fail,'fresh_ranges':ranges,'loader_zero_tail':{'pt_load':list(segments[0]),'file_va_end':hex(segments[0][3]+segments[0][5]),'memory_va_end':hex(segments[0][3]+segments[0][6]),'cache':'0x57883f8..0x5788400'},
            'static_optimized_verify_exit':p.returncode,'semantic_findings':[],
            'documentation_notes':['Default floating environment should explicitly include masked invalid/precision exceptions: initial CVTTSD2SI is out of signed range for high admitted quota ratios. Values match under the stated default, not arbitrary MXCSR masks.','Loader zero initialization is supported by actual writable PT_LOAD zero-fill tail, not SHT_NOBITS alone. Target map independently checked here.'],
            'limits':['No target or emulator execution.','No independent native rerun; parent recorded native results were reviewed.','No exact num_cpus release/source-build provenance inferred from the dependency API match.','Initial narrow GNU window started midinstruction at4e05820 and was not used; complete FDE GNU/Capstone decodes above replace it.']}
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'vectors':len(inputs),'mismatches':len(fail),'static_verify_exit':p.returncode,'review':str(out/'review.json')}))
    if fail or p.returncode:raise SystemExit(1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);main(p.parse_args())
