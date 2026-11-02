"""Standalone reviewer ELF/RELA parsing with GNU full-body/FDE countercheck."""
from pathlib import Path
import argparse,base64,gzip,hashlib,json,os,re,struct,subprocess
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
def sha(b):return hashlib.sha256(b).hexdigest()
def need(a,m):
    if not a:raise ValueError(m)
class ELF:
    def __init__(self,b):
        self.b=b;need(b[:6]==b'\x7fELF\x02\x01','ELF64 LE');need(struct.unpack_from('<H',b,18)[0]==62,'x86-64')
        self.loads=[];off=struct.unpack_from('<Q',b,32)[0];stride,n=struct.unpack_from('<HH',b,54)
        for i in range(n):
            k,flags,f,v,_,fs,ms,align=struct.unpack_from('<IIQQQQQQ',b,off+i*stride)
            if k==1:self.loads.append((f,v,fs,ms))
        off=struct.unpack_from('<Q',b,40)[0];stride,n,names=struct.unpack_from('<HHH',b,58)
        ss=[struct.unpack_from('<IIQQQQIIQQ',b,off+i*stride) for i in range(n)];st=ss[names];ns=b[st[4]:st[4]+st[5]]
        self.sections={ns[s[0]:ns.index(0,s[0])].decode():s for s in ss}
        sy=self.sections['.dynsym'];ds=self.sections['.dynstr'];strings=b[ds[4]:ds[4]+ds[5]]
        symbols=[]
        for x in range(sy[4],sy[4]+sy[5],24):
            name=struct.unpack_from('<I',b,x)[0];symbols.append(strings[name:strings.index(0,name)].decode())
        self.relas=[]
        for r in self.sections.values():
            if r[1]!=4:continue
            need(ss[r[6]]==sy,'RELA dynamic symbol table')
            for x in range(r[4],r[4]+r[5],24):
                at,info,add=struct.unpack_from('<QQq',b,x);index=info>>32;k=info&0xffffffff
                self.relas.append({'address':at,'kind':k,'addend':add,'file_offset':x,'symbol':symbols[index] if index else None})
    def read(self,v,n):
        hits=[f+v-a for f,a,fs,ms in self.loads if a<=v and v+n<=a+fs]
        need(len(hits)==1,('unique file-backed PT_LOAD',hex(v),n))
        return self.b[hits[0]:hits[0]+n]
    def initial(self,v,n):
        mapped=[(f,a,fs,ms) for f,a,fs,ms in self.loads if a<=v and v+n<=a+ms]
        need(len(mapped)==1,('unique mapped PT_LOAD',hex(v),n));f,a,fs,ms=mapped[0]
        file_bytes=max(0,min(n,a+fs-v))
        return self.b[f+v-a:f+v-a+file_bytes]+bytes(n-file_bytes)
    def writers(self,a,n):return [r for r in self.relas if r['address']<a+n and a<r['address']+8]

def main(root,out):
    out.mkdir(parents=True,exist_ok=False);p=root/'research/work-items/RE-008-tc-parallel-abort-115';target=root/'artifacts/node/115/hl-node';raw=target.read_bytes();need(sha(raw)==SHA,'target')
    b=json.loads(gzip.decompress((p/'bindings.json.gz').read_bytes()));e=ELF(raw);need(len(e.relas)==b['relocation_count'],'RELA count')
    gnu=os.environ.get('GNU_OBJDUMP','objdump');readelf=os.environ.get('GNU_READELF','readelf');commands=[]
    def run(argv,label):
        r=subprocess.run(argv,capture_output=True);need(r.returncode==0,(argv,r.returncode,r.stderr.decode()))
        stdout=r.stdout.replace(str(target).encode(),b'<authenticated-node115>');stderr=r.stderr.replace(str(target).encode(),b'<authenticated-node115>')
        commands.append({'argv':[x.replace(str(target),'<authenticated-node115>') for x in argv],'exit':r.returncode,'stdout_sha256':sha(stdout),'stderr_sha256':sha(stderr)})
        if label:(out/(label+'.stdout')).write_bytes(stdout);(out/(label+'.stderr')).write_bytes(stderr)
        return stdout
    frames=run([readelf,'--debug-dump=frames','--wide',str(target)],None).decode();fm={};sections=frames.split('\n\n')
    for block in sections:
        m=re.search(r'^([0-9a-f]+)\s+.*? FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)',block,re.M)
        if m:fm.setdefault(int(m[1],16),[]).append((int(m[2],16),int(m[3],16),block))
    bodies={r['start']:r for r in b['bodies']}
    for caller in b['incoming']['callers']:
        r=caller['body'];need(r['start'] not in bodies or bodies[r['start']]==r,'duplicate context equality');bodies[r['start']]=r
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;body_results=[];frameparts=[];relas={};branches=0;selectedraw={}
    def check_record(r):
        a=r['address'];actual=e.writers(a,8);need(actual==[r],('unique RELA',hex(a)));relas[a]=r
    for start,r in sorted(bodies.items()):
        end=r['end'];code=e.read(start,end-start);need(code.hex()==r['hex'] and sha(code)==r['sha256'],'whole body')
        fde=e.read(r['fde'],len(bytes.fromhex(r['fde_hex'])));cie=e.read(r['cie'],len(bytes.fromhex(r['cie_hex'])))
        need(fde.hex()==r['fde_hex'] and cie.hex()==r['cie_hex'],'frame raw')
        at=r['fde']-e.sections['.eh_frame'][3];hits=fm.get(at,[]);need(len(hits)==1 and hits[0][:2]==(start,end),('readelf independent FDE',hex(start),hits));frameparts.append(hits[0][2])
        stdout=run([gnu,'-d','-M','intel','--insn-width=15','--start-address='+hex(start),'--stop-address='+hex(end),str(target)],hex(start)+'.gnu').decode()
        rows=[]
        for line in stdout.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m:rows.append((int(m[1],16),bytes.fromhex(m[2])))
        pos=start
        for va,rb in rows:need(va==pos,'GNU contiguous');pos+=len(rb)
        need(pos==end and b''.join(x[1] for x in rows)==code,'GNU whole body')
        ins=list(md.disasm(code,start));need([(x.address,bytes(x.bytes)) for x in ins]==rows,'GNU instruction boundaries')
        need([(x[0],x[1].hex()) for x in rows]==[(x[0],x[1]) for x in r['instructions']],'retained instruction map')
        starts={i.address for i in ins};selectedraw[start]=ins
        for i in ins:
            if i.group(CS_GRP_JUMP) and i.operands[0].type==X86_OP_IMM:
                dest=i.operands[0].imm
                if start<=dest<end:need(dest in starts,'branch boundary');branches+=1
        for rr in r['rip_operands']:
            need(e.initial(rr['address'],rr['size']).hex()==rr['hex'],'RIP initial file or PT_LOAD zero-tail')
            need(e.writers(rr['address'],rr['size'])==rr['relocations'],'RIP overlapping writers')
            for writer in rr['relocations']:check_record(writer)
        for edge in r['edges']:
            if 'relocations' in edge:
                need(e.writers(edge['slot'],8)==edge['relocations'],'edge writers')
                for writer in edge['relocations']:check_record(writer)
        body_results.append({'start':hex(start),'end':hex(end),'bytes':len(code),'instructions':len(ins),'sha256':sha(code),'independent_readelf_fde':True})
    for s in b['data_spans']:
        need(e.read(s['address'],s['length']).hex()==s['hex'],'data span')
        need(e.writers(s['address'],s['length'])==s['relocations'],'data writer interval')
        for r in s['relocations']:check_record(r)
    for r in b['naming_relocations']:check_record(r)
    for a in b['anchor_facts'].values():need(e.read(a['address'],len(bytes.fromhex(a['hex']))).hex()==a['hex'],'anchor')
    sites=0
    for c in b['incoming']['callers']:
        for s in c['sites']:
            v=s['site'];n=e.read(v,5);need(n[0]==0xe8 and v+5+struct.unpack_from('<i',n,1)[0]==s['target'],'incoming E8');sites+=1
    (out/'selected.frames.txt').write_text('\n\n'.join(frameparts)+'\n');(out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    result={'target_sha256':SHA,'body_count':len(body_results),'bodies':body_results,'bytes':sum(x['bytes'] for x in body_results),'instructions':sum(x['instructions'] for x in body_results),'whole_relocation_count':len(e.relas),'unique_selected_relocations':len(relas),'data_spans':len(b['data_spans']),'internal_branch_boundaries':branches,'actual_incoming_E8':sites,'anchors':len(b['anchor_facts']),'input_pins':{n:sha((p/n).read_bytes()) for n in ['bindings.json.gz','freeze.json','oracle.py','rust/lib.rs','rust/driver.rs']},'author_collector_imported':False,'captured_execution':False,'limits':['Body selections and claims supplied by packet; extents independently checked through GNU readelf and raw PT_LOAD bytes.','No full symbolic execution, opaque callee proof, global scheduler-order proof or native requalification.']}
    (out/'review.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='bodies'}))
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('root',type=Path);a.add_argument('out',type=Path);p=a.parse_args();main(p.root,p.out)
