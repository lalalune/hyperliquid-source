#!/usr/bin/env python3
"""Independent read-only fixture/scalar and manual ELF slot audit; stdout JSON only."""
import gzip
import hashlib
import json
from pathlib import Path
import struct

PACKET=Path(__file__).resolve().parent.parent
ROOT=PACKET.parents[2]
MOD=1<<64
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def require(ok,reason):
    if not ok:raise ValueError(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()

def alternate(member,base,obj,incoming,length,image):
    if base+length>MOD:return None
    # Checked contiguous slice coordinates, no address map or ordered lambda list.
    def scalar(origin,displacement,width):
        address=(origin+displacement)%MOD
        first=address-base
        if first<0 or first+width>length or address+width>MOD:return None
        return sum(image[first+j]*(256**j) for j in range(width))
    if member==0:
        f=scalar(obj,650,1)
        if f is None:return None
        if f:return 1,incoming
        c=scalar(obj,652,4)
        if c is None:return None
        return (2 if c-1==0 else 0),incoming
    if member==1:
        pointer=scalar(obj,80,8)
        if pointer is None:return None
        if not pointer:return 0,0
        gate=scalar(pointer,32,1)
        if gate is None:return None
        if not gate:return 0,pointer
        value=scalar(obj,649,1)
        return None if value is None else (value,pointer)
    require(member==2,'member range')
    f=scalar(obj,650,1)
    if f is None:return None
    if f:return 0,incoming
    mode=scalar(obj,656,1)
    if mode is None:return None
    if mode:return mode,incoming
    enabled=scalar(obj,649,1)
    if enabled is None:return None
    if not enabled:return 0,incoming
    first=scalar(obj,152,4)
    if first is None:return None
    second=scalar(obj,156,4)
    if second is None:return None
    # Unbounded signed difference supplies unsigned-order result; quotient/remainder
    # reconstruction preserves the first integer's upper three bytes.
    result=256*(first//256)+int(second-first<0)
    return result,incoming


def main():
    inp=gzip.decompress((PACKET/'inputs.bin.gz').read_bytes())
    expected=gzip.decompress((PACKET/'expected.bin.gz').read_bytes())
    frozen=json.loads((PACKET/'frozen.json').read_text())
    require(len(inp)%808==0 and len(expected)==len(inp)//808*24,'fixture lengths')
    require(digest(inp)==frozen['inputs_sha256'] and digest(expected)==frozen['expected_sha256'],'frozen fixture hashes')
    require(digest((PACKET/'oracle.py').read_bytes())==frozen['oracle_sha256_at_freeze'],'frozen oracle identity')
    results=bytearray();admitted=[0,0,0];refused=0;partial=0;rawbytes=0
    for index in range(len(inp)//808):
        row=inp[index*808:(index+1)*808];member,base,obj,incoming,length=struct.unpack_from('<5Q',row)
        require(length<=768,'client length')
        got=alternate(member,base,obj,incoming,length,row[40:])
        encoded=bytes(24) if got is None else struct.pack('<3Q',1,*got)
        require(encoded==expected[index*24:(index+1)*24],f'fixture mismatch {index}')
        results.extend(encoded)
        if got is None:refused+=1
        else:
            admitted[member]+=1;partial+=member==2 and got[0]>255;rawbytes+=member in (1,2) and 1<got[0]<256
    require(admitted==frozen['admitted_per_member'] and refused==frozen['refusals'],'coverage identity')
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(digest(data)==TARGET and len(data)==91774280,'full target')
    require(data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<HH',data,16)==(3,62),'ELF64 LE x86-64 ET_DYN')
    shoff=struct.unpack_from('<Q',data,40)[0];shsize,shcount,shstr=struct.unpack_from('<HHH',data,58)
    require(shsize==64,'section size')
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*shsize) for i in range(shcount)]
    names=data[headers[shstr][4]:headers[shstr][4]+headers[shstr][5]]
    sections=[]
    for h in headers:
        name=names[h[0]:].split(b'\0',1)[0].decode();sections.append({'name':name,'type':h[1],'flags':h[2],'va':h[3],'offset':h[4],'size':h[5]})
    phoff=struct.unpack_from('<Q',data,32)[0];phsize,phcount=struct.unpack_from('<HH',data,54);require(phsize==56,'program header size')
    loads=[h for h in (struct.unpack_from('<IIQQQQQQ',data,phoff+i*phsize) for i in range(phcount)) if h[0]==1]
    def mapped(va,width):
        ss=[s for s in sections if s['type']!=8 and s['va']<=va and va+width<=s['va']+s['size']]
        ll=[h for h in loads if h[3]<=va and va+width<=h[3]+h[5]]
        require(len(ss)==1 and len(ll)==1,'unique section/PT_LOAD')
        offset=ss[0]['offset']+va-ss[0]['va'];require(offset==ll[0][2]+va-ll[0][3],'mapping correspondence')
        return data[offset:offset+width],offset,ss[0]['name']
    selected=((0x5382c90,0x5382caf),(0x5382d30,0x5382d4f),(0x5382d50,0x5382d8b))
    static=json.loads((PACKET/'static.json').read_text());body=[]
    for (start,end),record in zip(selected,static['members']):
        raw,offset,_=mapped(start,end-start);require(raw.hex()==record['hex'] and digest(raw)==record['body_sha256'],'full body bytes')
        fde=record['records']['fde'];va=fde['va'];prefix,_,_=mapped(va,4);length=struct.unpack('<I',prefix)[0]+4;encoded,_,_=mapped(va,length)
        require(encoded.hex()==fde['hex'],'FDE raw')
        require(va+8+struct.unpack_from('<i',encoded,8)[0]==start and struct.unpack_from('<I',encoded,12)[0]==end-start,'FDE PC and extent')
        cie=record['records']['cie'];require(va+4-struct.unpack_from('<I',encoded,4)[0]==cie['va'],'FDE CIE link')
        require(mapped(cie['va'],len(bytes.fromhex(cie['hex'])))[0].hex()==cie['hex'],'CIE raw')
        body.append({'start':hex(start),'end':hex(end),'sha256':digest(raw),'file_offset':offset,'fde_hex':encoded.hex()})
    relocations=[];naming=[];starts={a for a,b in selected}
    for s in sections:
        if s['type']!=4:continue
        require(s['size']%24==0,'RELA shape')
        for offset in range(s['offset'],s['offset']+s['size'],24):
            destination,info,addend=struct.unpack_from('<QQq',data,offset);record=(offset,destination,info,addend);relocations.append(record)
            if addend in starts:naming.append(record)
    require(len(relocations)==80300 and len(naming)==5,'complete relocation counts')
    slots=[]
    for file_offset,destination,info,addend in naming:
        raw,offset,name=mapped(destination,8);require(info==8 and raw==bytes(8),'RELATIVE zero-symbol slot')
        writers=[r for r in relocations if r[1]<destination+8 and destination<r[1]+8]
        require(writers==[(file_offset,destination,info,addend)],'unique full slot writer')
        slots.append({'va':hex(destination),'file_offset':offset,'section':name,'rela_offset':file_offset,'addend':hex(addend)})
    require(sorted(x['section'] for x in slots)==['.data.rel.ro']*3+['.got']*2,'actual section partition')
    require(sorted(naming)==sorted(tuple(x) for x in static['naming_relocations']),'retained naming closure')
    files={'source':ROOT/'src/node94-object-status-gates/lib.rs','driver':ROOT/'src/node94-object-status-gates/input_only_driver.rs','proof':PACKET/'PROOF.md','oracle':PACKET/'oracle.py','static':PACKET/'static.json','reviewer':Path(__file__)}
    result={'status':'PASS','cases':len(inp)//808,'admitted_per_member':admitted,'refusals':refused,'partial_upper_dword_cases':partial,'raw_nonboolean_flag_cases':rawbytes,'rederived_expected_sha256':digest(results),'inputs_sha256':digest(inp),'target_sha256':TARGET,'complete_bodies':body,'all_rela_records':len(relocations),'naming_slots':slots,'reviewed_sha256':{k:digest(v.read_bytes()) for k,v in files.items()},'method':'independent contiguous scalar reads; signed unbounded difference and quotient/remainder partial-AL preservation; manual ELF64 section/PT_LOAD/FDE/RELA parsing','oracle_imported':False,'captured_execution':False,'instruction_emulation':False,'native_rust_replayed':False,'blockers':[]}
    print(json.dumps(result,sort_keys=True,indent=2))
if __name__=='__main__':main()
