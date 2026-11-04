#!/usr/bin/env python3
"""Static node115 poll TLS-gate evidence; no target execution or emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
RANGES = [
 ('wrapper',0x5ce94c0,0x5ce95b7,'e1db2f2068ff64f842ccac3e4607101bd76d9d59eb5a0cc5a0218388f616fadf'),
 ('cleanup',0x5cf3190,0x5cf31e5,'34d8b3fa8b04ae18d39b546caca2f332063a4423e1578a0520bb38ba228abff8'),
 ('callback',0x5cdf410,0x5cdf457,'83808b635c9c4571afcf4b915c2803f2707f64b0a4fc4c43fd5cbe88465c302c'),
 ('registration-context',0x5ca0d20,0x5ca0e1f,'b41b5cc834002de4b875118dffe3ede7cd50f595dd8e5103a0f08a9cedae254e'),
]
SLOTS = {0x64e1358:0x5ce94c0,0x64e0858:0x5cf2d30,
         0x64e13b0:0x5cf3190,0x64e0510:0x5ca0d20,0x64efa28:0x5cad7b0}
ANCHORS = {
 0x2b7b077:'410fb6ff',0x2b7b07b:'83e701',0x2b7b07e:'488b742440',
 0x2b7b083:'4c89ea',0x2b7b086:'ff15cc629603',
 0x5ce94cf:'49c7c7d0eeffff',0x5ce94e2:'64410fb64748',
 0x5ce94e8:'83f801',0x5ce94eb:'7429',0x5ce94ed:'83f802',0x5ce94f0:'0f848d000000',
 0x5ce94f6:'488d35135fffff',0x5ce9505:'ff1505707f00',0x5ce9510:'6441c6474801',
 0x5ce9516:'4084ff',0x5ce9519:'7468',0x5ce951b:'6441807f4400',
 0x5ce9521:'7460',0x5ce9523:'6441807f4500',0x5ce9529:'7558',
 0x5ce952b:'6441c6474400',0x5ce9531:'66c744240e0100',
 0x5ce9538:'4c89f7',0x5ce953b:'4889d6',0x5ce953e:'ff1514737f00',
 0x5ce9544:'64410fb64f48',0x5ce954a:'83f901',0x5ce954d:'741f',
 0x5ce954f:'83f902',0x5ce9552:'7422',0x5ce9560:'ff15aa6f7f00',
 0x5ce9566:'6441c6474801',0x5ce956e:'646641c747440100',
 0x5ce9583:'4c89f7',0x5ce9586:'4889d6',0x5ce9595:'ff25bd727f00',
 0x5ce959b:'4889c3',0x5ce959e:'488d7c240e',0x5ce95a3:'ff15077e7f00',
 0x5ce95a9:'4889df',0x5ce95ac:'e89f747000',
 0x5cf3194:'0fb61f',0x5cf3197:'0fb66f01',0x5cf319b:'49c7c6d0eeffff',
 0x5cf31a2:'64410fb64648',0x5cf31a8:'83f801',0x5cf31ab:'7429',
 0x5cf31ad:'83f802',0x5cf31b0:'7505',0x5cf31b6:'c3',
 0x5cf31c3:'488d3546c2feff',0x5cf31ca:'ff1540d37e00',
 0x5cf31d0:'6441c6464801',0x5cf31d6:'6441885e44',0x5cf31db:'6441886e45',
 0x5cdf411:'c6474802',0x5ca0d35:'48833d73bc840000',
 0x5ca0d3d:'741f',0x5ca0d3f:'488d1502d78500',0x5ca0d46:'4889df',
 0x5ca0d49:'4c89f6',0x5ca0d58:'ff2552bc8400',0x63f0a50:'ff2522d70f00',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

class Image:
    def __init__(self,data,sections,fdes,cies):
        self.data,self.sections,self.fdes,self.cies=data,sections,fdes,cies
    def offset(self,va,length):
        spans=[s for s in self.sections if s['type']!=8 and s['address']<=va<va+length<=s['address']+s['size']]
        if len(spans)!=1:
            raise ValueError('Non-unique mapped bytes')
        return spans[0]['offset']+va-spans[0]['address']
    def read(self,va,length):
        off=self.offset(va,length)
        return self.data[off:off+length]
    def relocations(self):
        rows={}
        for s in self.sections:
            if s['type']==4:
                for slot,info,addend in struct.iter_unpack('<QQq',self.data[s['offset']:s['offset']+s['size']]):
                    rows.setdefault(slot,[]).append((info,addend))
        return rows
    def symbol(self,index):
        sym=next(s for s in self.sections if s['name']=='.dynsym')
        strings=next(s for s in self.sections if s['name']=='.dynstr')
        name=struct.unpack_from('<I',self.data,sym['offset']+index*24)[0]
        if name>=strings['size']:
            raise ValueError('Bad symbol name offset')
        start=strings['offset']+name
        return self.data[start:self.data.index(b'\0',start,strings['offset']+strings['size'])].decode('ascii')

def load(root):
    data=(root/'artifacts/node/115/hl-node').read_bytes()
    if len(data)!=105896032 or digest(data)!=TARGET:
        raise ValueError('Wrong target')
    sys.path.insert(0,str(root/'tools'))
    from elf_index import sections
    from fde_extents import eh_frame_records
    secs=sections(data);cies,fdes=eh_frame_records(data,secs)
    return Image(data,secs,fdes,cies)

def rip(image,pc,size,displacement):
    return pc+size+struct.unpack('<i',image.read(pc+displacement,4))[0]

def bind(image):
    for va,want in ANCHORS.items():
        if image.read(va,len(bytes.fromhex(want))).hex()!=want:
            raise ValueError(f'Changed instruction anchor {va:#x}')
    rels=image.relocations()
    for slot,target in SLOTS.items():
        if rels.get(slot)!=[(8,target)]:
            raise ValueError(f'Non-unique/changed relocation {slot:#x}')
    edges=[(0x2b7b086,0x64e1358),(0x5ce9505,0x64e0510),
           (0x5ce953e,0x64e0858),(0x5ce9560,0x64e0510),
           (0x5ce9595,0x64e0858),(0x5ce95a3,0x64e13b0),
           (0x5cf31ca,0x64e0510),(0x5ca0d58,0x64ec9b0),
           (0x63f0a50,0x64ee178)]
    for pc,slot in edges:
        if rip(image,pc,6,2)!=slot:
            raise ValueError('RIP edge mismatch')
    imports=[]
    for slot,kind,name in [(0x64ec9b0,6,'__cxa_thread_atexit_impl'),(0x64ee178,7,'_Unwind_Resume')]:
        entries=rels.get(slot,[])
        if len(entries)!=1 or entries[0][0]&0xffffffff!=kind or entries[0][1]!=0:
            raise ValueError('Dynamic import relocation mismatch')
        index=entries[0][0]>>32
        if image.symbol(index)!=name:
            raise ValueError('Dynamic import name mismatch')
        imports.append({'slot':hex(slot),'type':kind,'symbol_index':index,'name':name})
    if rip(image,0x5ce95ac,5,1)!=0x63f0a50:
        raise ValueError('Unwind PLT call mismatch')
    for pc in (0x5ce94f6,0x5ce9556,0x5cf31c3):
        if rip(image,pc,7,3)!=0x5cdf410:
            raise ValueError('Callback address mismatch')
    if rip(image,0x5ca0d3f,7,3)!=0x64fe448:
        raise ValueError('Registration third operand mismatch')
    caller=[f for f in image.fdes if f['start']==0x2b7a290 and f['end']==0x2b7b523]
    if len(caller)!=1:
        raise ValueError('Sender context FDE mismatch')
    return {'relative_slots':[{'slot':hex(s),'type':8,'symbol':0,'addend':hex(t)} for s,t in SLOTS.items()],
            'rip_edges':[{'pc':hex(p),'slot':hex(s)} for p,s in edges],
            'imports':imports,'sender_context_fde':caller[0],
            'sender_context_sha256':digest(image.read(0x2b7a290,0x1293)),
            'anchors':[{'va':hex(a),'bytes_hex':b} for a,b in ANCHORS.items()]}

def uleb(data,pos,end):
    value=shift=0
    while pos<end and shift<=63:
        byte=data[pos];pos+=1;value|=(byte&127)<<shift
        if byte<128:
            if value>=1<<64: break
            return value,pos
        shift+=7
    raise ValueError('Truncated/oversized LSDA ULEB')

def lsda_table(data,start,end):
    """Decode only the observed omitted-LPStart/ULEB call-site layout."""
    if len(data)<5 or data[:2]!=b'\xff\x9b':
        raise ValueError('Unsupported LSDA header')
    type_offset,pos=uleb(data,2,len(data));type_base=pos+type_offset
    if data[pos]!=1:
        raise ValueError('Unsupported call-site encoding')
    size,pos=uleb(data,pos+1,len(data));table_end=pos+size
    if table_end>len(data) or type_base<table_end or type_base>len(data):
        raise ValueError('Invalid LSDA table bound')
    rows=[];previous=0
    while pos<table_end:
        fields=[]
        for _ in range(4):
            value,pos=uleb(data,pos,table_end);fields.append(value)
        lo,length,landing,action=fields
        if not length or lo<previous or start+lo+length>end or landing and start+landing>=end:
            raise ValueError('Invalid call-site interval')
        previous=lo+length
        rows.append({'start':hex(start+lo),'end':hex(start+lo+length),
                     'landing':hex(start+landing) if landing else None,'action':action})
    return {'header':'ff9b','call_site_encoding':1,'call_site_table_end_offset':table_end,
            'type_table_base_offset':type_base,'rows':rows}

def unwind(image):
    fdes=[f for f in image.fdes if (f['start'],f['end'])==(0x5ce94c0,0x5ce95b7)]
    if len(fdes)!=1 or fdes[0]['lsda']!=0x40360c:
        raise ValueError('Wrapper LSDA pointer mismatch')
    cie=image.cies[fdes[0]['cie']]
    if cie['augmentation']!='zPLR' or cie['lsda_encoding']!=27 or cie['personality_slot']!=0x64efa28:
        raise ValueError('Wrapper CIE mismatch')
    # This bounded 52-byte context stops at the next referenced LSDA. It is
    # NOT asserted to be one complete LSDA object or type/action-table extent.
    window=image.read(0x40360c,52)
    parsed=lsda_table(window,0x5ce94c0,0x5ce95b7)
    expected=[('0x5ce94c0','0x5ce9538',None,0),
              ('0x5ce9538','0x5ce9544','0x5ce959b',0),
              ('0x5ce9544','0x5ce959e',None,0),
              ('0x5ce959e','0x5ce95a9','0x5ce95b1',1),
              ('0x5ce95a9','0x5ce95b7',None,0)]
    if [(r['start'],r['end'],r['landing'],r['action']) for r in parsed['rows']]!=expected:
        raise ValueError('Changed LSDA call-site mapping')
    covered=[r for r in parsed['rows'] if int(r['start'],16)<=0x5ce953e and 0x5ce9544<=int(r['end'],16)]
    if len(covered)!=1 or covered[0]['landing']!='0x5ce959b' or covered[0]['action']!=0:
        raise ValueError('Wrapped call cleanup mapping')
    return {'va':'0x40360c','raw_context_bytes':len(window),'raw_context_hex':window.hex(),
            'context_sha256':digest(window),'fde':fdes[0],'cie':cie,'call_site_table':parsed,
            'action_type_tables_interpreted':False,'personality_body_reconstructed':False}

def native_rows(raw,image,start,end):
    cursor=start;rows=[]
    for line in raw.decode().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)',line)
        if m:
            pc=int(m[1],16);chunk=bytes.fromhex(m[2])
            if pc!=cursor or pc+len(chunk)>end or chunk!=image.read(pc,len(chunk)):
                raise ValueError('Native byte gap/overlap/mismatch')
            rows.append((pc,chunk));cursor+=len(chunk)
    if cursor!=end:
        raise ValueError('Incomplete native interval')
    return rows

def join_lock(rows):
    """LLVM 18 prints these two LOCK prefixes as separate byte-exact rows."""
    result=[];joins=[];index=0
    while index<len(rows):
        pc,chunk=rows[index];index+=1
        if pc in (0x5cdf42b,0x5cdf43c) and chunk==b'\xf0':
            if index>=len(rows) or rows[index]!=(pc+1,bytes.fromhex('48ff08')):
                raise ValueError('Invalid explicit LOCK continuation')
            chunk+=rows[index][1];index+=1;joins.append(hex(pc))
        result.append((pc,chunk))
    return result,joins

def collect(root,packet):
    image=load(root);routes=bind(image);exceptions=unwind(image)
    import capstone
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    bodies=[]
    for name,start,end,want in RANGES:
        fdes=[f for f in image.fdes if (f['start'],f['end'])==(start,end)]
        if len(fdes)!=1 or not any(s['flags']&4 and s['address']<=start<end<=s['address']+s['size'] for s in image.sections):
            raise ValueError('Selected executable FDE mismatch')
        body=image.read(start,end-start)
        if digest(body)!=want:
            raise ValueError('Selected body hash mismatch')
        cap=[(i.address,i.bytes) for i in cs.disasm(body,start)]
        if b''.join(bytes(v) for _,v in cap)!=body:
            raise ValueError('Incomplete Capstone decode')
        native=[]
        for tool in ('gnu','llvm'):
            p=packet/'native'/f'{name}.{tool}.objdump';raw=p.read_bytes()
            raw_rows=native_rows(raw,image,start,end)
            rows,joins=join_lock(raw_rows)
            if rows!=cap:
                raise ValueError('Native/Capstone instruction partition mismatch')
            native.append({'path':f'native/{p.name}','sha256':digest(raw),'bytes':len(raw),
                           'raw_rows':len(raw_rows),'logical_instructions':len(rows),'lock_prefix_joins':joins})
        bodies.append({'name':name,'fde':fdes[0],'file_offset':image.offset(start,end-start),
                       'bytes':len(body),'sha256':digest(body),'instructions':len(cap),'native':native})
    caller_slices=[]
    for tool in ('gnu','llvm'):
        p=packet/'native'/f'sender-callsite.{tool}.objdump';raw=p.read_bytes()
        rows=native_rows(raw,image,0x2b7b071,0x2b7b090)
        cap=[(i.address,i.bytes) for i in cs.disasm(image.read(0x2b7b071,31),0x2b7b071)]
        if rows!=cap: raise ValueError('Caller slice instruction partition mismatch')
        caller_slices.append({'path':f'native/{p.name}','sha256':digest(raw),'bytes':len(raw),'rows':len(rows)})
    return {'schema_version':1,'target':{'release':115,'sha256':TARGET,'bytes':len(image.data)},
            'source_base':BASE,'coordinate_system':'ELF virtual address; half-open ranges',
            'tools':{'capstone':capstone.__version__},'bodies':bodies,'caller_slices':caller_slices,
            'bindings':routes,'unwind':exceptions,
            'scope':{'captured_execution':False,'emulation':False,'source_implementation':False,
                     'new_byte_comparison_credit':0,'acceptance_gates_changed':0,
                     'registration_fallback_interpreted':False,'wrapped_core_interpreted':False}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[3])
    p.add_argument('--check',action='store_true');a=p.parse_args();packet=Path(__file__).resolve().parent
    actual=collect(a.root,packet);result=packet/'records.json'
    if a.check:
        expected=json.loads(result.read_text())
        # Decoder patch versions are recorded as provenance, not proof of
        # instruction equality. Each execution still checks every boundary.
        expected['tools']['capstone']=actual['tools']['capstone']
        if actual!=expected: raise ValueError('Evidence record drift')
        print('Verified four complete FDEs, native partitions, routes and LSDA call-site table')
    else:
        result.write_text(json.dumps(actual,indent=2,sort_keys=True)+'\n')

if __name__=='__main__':
    main()
