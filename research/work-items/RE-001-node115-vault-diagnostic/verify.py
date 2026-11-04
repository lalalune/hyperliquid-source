"""One pinned node115 source/Location/LEA/FDE binding; static bytes only."""
from pathlib import Path
import hashlib,json,re,struct,subprocess
TARGET=Path('artifacts/node/115/hl-node')
DIGEST='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START,END,XREF,LOCATION=0x283c6b0,0x283c768,0x283c6dc,0x643bb20
SOURCE=b'l1/src/action/vault_transfer.rs'
def require(ok,message):
    if not ok: raise ValueError(message)
def uleb(b,pos,signed=False):
    value=shift=0
    while True:
        require(pos<len(b) and shift<64,'invalid LEB128')
        byte=b[pos];pos+=1;value|=(byte&127)<<shift;shift+=7
        if byte<128:break
    if signed and byte&64:value-=1<<shift
    return value,pos
def structural(b):
    require(b[:6]==b'\x7fELF\x02\x01','ELF format')
    po=struct.unpack_from('<Q',b,32)[0];psz,pn=struct.unpack_from('<HH',b,54)
    loads=[struct.unpack_from('<IIQQQQQQ',b,po+i*psz) for i in range(pn)]
    def offset(va,n):
        matches=[s[2]+va-s[3] for s in loads if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]]
        require(len(matches)==1,'unambiguous VA mapping');return matches[0]
    so=struct.unpack_from('<Q',b,40)[0];ss,sn,si=struct.unpack_from('<HHH',b,58)
    secs=[struct.unpack_from('<IIQQQQIIQQ',b,so+i*ss) for i in range(sn)]
    names=b[secs[si][4]:secs[si][4]+secs[si][5]]
    def section(name):
        found=[s for s in secs if names[s[0]:].split(b'\0',1)[0]==name]
        require(len(found)==1,'unique section');return found[0]
    loc=offset(LOCATION,24)
    require(struct.unpack_from('<QQII',b,loc)==(0,len(SOURCE),27,18),'Location fields')
    rel=section(b'.rela.dyn');require(rel[9]==24,'RELA entry width')
    refs=[(o,struct.unpack_from('<QQq',b,o)) for o in range(rel[4],rel[4]+rel[5],24) if struct.unpack_from('<Q',b,o)[0]==LOCATION]
    require(len(refs)==1 and refs[0][1][1]==8,'unique relative relocation')
    ro,(_,_,sourceva)=refs[0];sf=offset(sourceva,len(SOURCE))
    require(b[sf:sf+len(SOURCE)]==SOURCE,'source token')
    xf=offset(XREF,7)
    require(b[xf:xf+3]==b'\x4c\x8d\x1d','LEA opcode')
    require(XREF+7+struct.unpack_from('<i',b,xf+3)[0]==LOCATION,'LEA destination')
    eh=section(b'.eh_frame');fe=eh[4]+0xb4424
    length,back=struct.unpack_from('<II',b,fe)
    require(length>=16 and fe+4+length<=eh[4]+eh[5],'FDE length')
    ci=fe+4-back;require(eh[4]<=ci<fe,'CIE pointer')
    clen,cid=struct.unpack_from('<II',b,ci)
    require(cid==0 and ci+4+clen<=fe and b[ci+8]==1,'CIE header')
    end=b.index(0,ci+9,ci+4+clen);aug=b[ci+9:end]
    require(aug==b'zR','supported CIE augmentation')
    pos=end+1;_,pos=uleb(b,pos);_,pos=uleb(b,pos,True);_,pos=uleb(b,pos)
    alen,pos=uleb(b,pos)
    require(alen==1 and b[pos]==0x1b,'pcrel sdata4 FDE encoding')
    start=eh[3]+fe-eh[4]+8+struct.unpack_from('<i',b,fe+8)[0]
    stop=start+struct.unpack_from('<I',b,fe+12)[0]
    require((start,stop)==(START,END) and start<=XREF<stop,'decoded FDE extent')
    return {'source_file_offset':sf,'location_file_offset':loc,'relocation_file_offset':ro,'instruction_file_offset':xf,'fde_file_offset':fe,'cie_file_offset':ci,'start':start,'end':stop,'xref':XREF,'location':LOCATION,'source':SOURCE.decode(),'line':27,'column':18}
def verify(path=TARGET):
    b=path.read_bytes();require(len(b)==105896032 and hashlib.sha256(b).hexdigest()==DIGEST,'target size/SHA256')
    result=structural(b)
    command=['objdump','-d','-Mintel','--start-address='+hex(START),'--stop-address='+hex(END),str(path)]
    native=subprocess.check_output(command,text=True,timeout=20)
    require(re.search(r'^\s*283c6dc:\s+4c 8d 1d 3d f4 bf 03\s+lea',native,re.M) is not None,'instruction-aligned native LEA')
    result.update(target_sha256=DIGEST,target_size=len(b),objdump_command=command,observed_bindings=1,denominator=1,limitations='Coordinates only; no helper semantics, ownership, equivalence or completed gate. No target execution.')
    return result
if __name__=='__main__':print(json.dumps(verify(),indent=2))
