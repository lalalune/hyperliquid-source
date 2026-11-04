#!/usr/bin/env python3
"""Independent read-only ELF/data checks; no target execution or instruction emulator."""
import argparse,hashlib,json,os,re,struct,subprocess
from pathlib import Path

def need(ok, message):
    if not ok: raise ValueError(message)

def sha(data): return hashlib.sha256(data).hexdigest()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args()
    root=args.root.resolve();p=root/'research/work-items/RE-001-runtime-entry-115';out=args.out;out.mkdir(parents=True,exist_ok=True)
    binary=root/'artifacts/node/115/hl-node';b=binary.read_bytes();need(sha(b)=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','target')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b);need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[2]==62,'x86_64 ELF');need(h[11]==64 and h[9]==56,'header widths')
    ss=[struct.unpack_from('<IIQQQQIIQQ',b,h[6]+i*h[11]) for i in range(h[12])]
    def read(va,n):
        hits=[s[4]+va-s[3] for s in ss if s[1]!=8 and s[3]<=va and va+n<=s[3]+s[5]]
        need(len(hits)==1,'unique file-backed mapping');return b[hits[0]:hits[0]+n]
    rs=[]
    for s in ss:
        if s[1]==4:
            need(s[5]%24==0,'RELA extent')
            rs += [struct.unpack_from('<QQq',b,at) for at in range(s[4],s[4]+s[5],24)]
    records=json.loads((p/'records.json').read_text());bodies=[];commands=[]
    for r in records['bodies']:
        a,z=int(r['start'],16),int(r['end_exclusive'],16);raw=read(a,z-a);need(sha(raw)==r['sha256'],'full body hash')
        cmd=[os.environ.get('GNU_OBJDUMP','objdump'),'-d','-M','intel','--insn-width=16','--start-address='+hex(a),'--stop-address='+hex(z),str(binary)]
        proc=subprocess.run(cmd,capture_output=True);need(proc.returncode==0 and not proc.stderr,'fresh GNU')
        cursor=a;extracted=bytearray()
        for line in proc.stdout.decode().splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m:
                va=int(m[1],16);chunk=bytes.fromhex(m[2]);need(va==cursor,'GNU byte order');extracted.extend(chunk);cursor+=len(chunk)
        need(cursor==z and bytes(extracted)==raw,'complete fresh GNU byte cover')
        clean=proc.stdout.replace(str(binary).encode(),b'<authenticated-node115>')
        (out/(r['name']+'.gnu.stdout')).write_bytes(clean)
        bodies.append({'name':r['name'],'bytes':z-a,'sha256':sha(raw),'fresh_gnu_sha256':sha(clean)})
        commands.append({'argv':[v.replace(str(binary),'<authenticated-node115>') for v in cmd],'target_filename_presentation_normalized':True,'exit':proc.returncode,'stdout_sha256':sha(clean),'stderr_sha256':sha(proc.stderr)})
    need(h[4]==0x1419300,'entry')
    need(read(0x6440b48,24)==struct.pack('<QQQ',0,8,8),'vtable header')
    for slot,target in [(0x64e6c30,0x5c99970),(0x6440b60,0x292e230),(0x6440b68,0x292c5c0),(0x6440b70,0x292c5c0),(0x64df9f0,0x5c87d50)]:
        writers=[r for r in rs if r[0]<slot+8 and slot<r[0]+8];need(writers==[(slot,8,target)],'unique RELATIVE binding')
    need(read(0x292e230,13).hex()=='50488b3fe837d9340031c059c3','once adapter returnzero')
    need(read(0x292c5c0,13).hex()=='50488b3fe8a7f5340031c059c3','shared adapter returnzero')
    need(read(0x2c7bb70,5).hex()=='50ffd758c3','indirect callback adapter')
    targets=[0x9486e8+x for x in struct.unpack('<4i',read(0x9486e8,16))]
    need(targets==[0x5c99bc7,0x5c99b4b,0x5c99bc0,0x5c99bbe],'SIGPIPE map')
    fallback=[x for x in range(23) if (0x401800>>x)&1];need(fallback==[11,12,22],'poll fallback')
    ph=[struct.unpack_from('<IIQQQQQQ',b,h[5]+56*i) for i in range(h[10])];globals_=[]
    for name,r in records['globals'].items():
        va,n=int(r['va'],16),r['size'];segs=[s for s in ph if s[0]==1 and s[3]<=va and va+n<=s[3]+s[6]];need(len(segs)==1,'global PT_LOAD');seg=segs[0]
        need(not [r for r in rs if r[0]<va+n and va<r[0]+8],'global relocation overlap')
        if va+n<=seg[3]+seg[5]:
            raw=b[seg[2]+va-seg[3]:seg[2]+va-seg[3]+n];need(name=='cleanup_once' and raw==b'\x03\0\0\0','cleanup file value');kind='file'
        else:need(seg[1]&2 and va>=seg[3]+seg[5],'writable zero tail');kind='zero-tail'
        globals_.append({'name':name,'va':hex(va),'kind':kind,'overlapping_relocations':0})
    for va,n in [(0x6440b48,24),(0x9486e8,16),(0x453950,16),(0x44fa5e,10)]:need(not [r for r in rs if r[0]<va+n and va<r[0]+8],'data relocation overlap')
    result={'target_sha256':sha(b),'bodies':bodies,'bytes':sum(x['bytes'] for x in bodies),'sigpipe_destinations':list(map(hex,targets)),'poll_fallback_errno':fallback,'retry_errno':4,'globals':globals_,'commands':commands,'reviewed_files':{str(x.relative_to(root)):sha(x.read_bytes()) for x in [p/'CONTRACT.md',p/'records.json',root/'tools/runtime_entry_115_static.py']},'review_script_sha256':sha(Path(__file__).read_bytes()),'limits':['ELF/section/RELA/program headers independently parsed; FDE extents supplied by packet and full bytes authenticated, no independent FDE parser.','Normal-return callback/SIGPIPE/sigaction-unchecked/exit-CAS semantics manually reviewed against fresh GNU; script does not execute or emulate instructions.','No syscall, target execution or runtime oracle; opaque callee and LSDA/action/personality limits remain.'],'finding':'No semantic blocker in requested boundaries.'}
    (out/'review.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'bytes':result['bytes'],'bodies':len(bodies),'globals':len(globals_)}))

if __name__=='__main__':main()
