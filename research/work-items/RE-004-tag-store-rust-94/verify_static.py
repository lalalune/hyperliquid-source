"""Bind complete tag-store code and its unread relocated address context."""
import argparse,hashlib,json,re,struct,sys
from pathlib import Path
import capstone
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START,END,POINT=0x5057700,0x505773d,0x57592a0
BODY='20b9c0991fb3c0cb30339df21612ac6562033a4a3fee606306fff618eedc775b'

def require(ok,message):
    if not ok:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def listing(path,image):
    rows=[];cursor=START
    for line in path.read_text().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if m:
            a,b=int(m[1],16),bytes.fromhex(m[2]);require(a==cursor and a+len(b)<=END,'listing extent')
            require(image.va_bytes(a,len(b),executable=True)[0]==b,'listing bytes');rows.append((a,b));cursor+=len(b)
    require(cursor==END,'complete listing');return rows

def unread_symbol(data,im):
    ss={s['name']:s for s in im.sections};ds,st,vs,vr,dyn=[ss[n] for n in ['.dynsym','.dynstr','.gnu.version','.gnu.version_r','.dynamic']]
    strings=data[st['offset']:st['offset']+st['size']]
    def name(at):
        require(0<=at<len(strings),'string offset');end=strings.find(b'\0',at);require(end>=at,'terminated string');return strings[at:end].decode('ascii')
    require(ds['entsize']==24 and ds['link']==st['index'],'dynsym shape')
    at=ds['offset']+260*24;sym=struct.unpack_from('<IBBHQQ',data,at)
    require(sym==(4026,17,0,0,0,0) and name(sym[0])=='_ZTVN10__cxxabiv117__class_type_infoE','unread symbol binding')
    v_at=vs['offset']+260*2;require(struct.unpack_from('<H',data,v_at)[0]==34,'symbol version index')
    found=[];cursor=vr['offset'];seen=set();end=cursor+vr['size']
    while True:
        require(cursor not in seen and vr['offset']<=cursor and cursor+16<=end,'version chain');seen.add(cursor)
        ver,count,file,aux,nxt=struct.unpack_from('<HHIII',data,cursor);require(ver==1,'version format');a=cursor+aux;seen_aux=set()
        for index in range(count):
            require(a not in seen_aux and vr['offset']<=a and a+16<=end,'aux bounds');seen_aux.add(a)
            h,flags,other,string,step=struct.unpack_from('<IHHII',data,a)
            if other==34:
                require(h==90943443 and flags==0 and name(file)=='libstdc++.so.6' and name(string)=='CXXABI_1.3','version requirement')
                found.append({'need_offset':cursor,'need_hex':data[cursor:cursor+16].hex(),'aux_offset':a,'aux_hex':data[a:a+16].hex(),'library':name(file),'version':name(string),'library_name_offset':st['offset']+file,'version_name_offset':st['offset']+string})
            if index+1<count:require(step!=0,'aux chain end')
            a+=step
        if nxt==0:break
        cursor+=nxt
    require(len(found)==1,'unique version requirement')
    needed=[];require(dyn['entsize']==16 and dyn['size']%16==0,'dynamic shape')
    for a in range(dyn['offset'],dyn['offset']+dyn['size'],16):
        tag,value=struct.unpack_from('<qQ',data,a)
        if tag==1 and name(value)=='libstdc++.so.6':needed.append({'file_offset':a,'hex':data[a:a+16].hex()})
    require(len(needed)==1,'libstdc++ DT_NEEDED')
    return {'index':260,'file_offset':at,'hex':data[at:at+24].hex(),'name':name(sym[0]),'name_offset':st['offset']+sym[0],'version_index_offset':v_at,'version_index':34,'requirement':found[0],'needed':needed[0],'semantic_dependency':False}

def inspect(data):
    im=Elf(data,3);cies,frames=eh_frame_records(data)
    def frame(a,b):
        fs=[f for f in frames if f['start']<b and a<f['end']];require(len(fs)==1 and (fs[0]['start'],fs[0]['end'])==(a,b),'unique complete FDE');f=fs[0];records={}
        for kind in ['fde','cie']:
            va=f[kind];size=int.from_bytes(im.va_bytes(va,4)[0],'little')+4;value,where=im.va_bytes(va,size);records[kind]={'va':va,'file_offset':where['file_offset'],'hex':value.hex()}
        return {'frame':f,'cie':cies[f['cie']],'records':records}
    raw,where=im.va_bytes(START,END-START,executable=True);require(sha(raw)==BODY,'complete body')
    rows=listing(PACKET/'window.gnu.txt',im);require(rows==listing(PACKET/'window.llvm.txt',im),'GNU/LLVM boundaries')
    dec=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);ins=list(dec.disasm(raw,START));require(rows==[(i.address,bytes(i.bytes)) for i in ins],'Capstone boundaries')
    require(not any(i.mnemonic=='call' for i in ins),'no calls')
    branches=[(i.address,i.mnemonic,int(i.op_str,16)) for i in ins if i.mnemonic.startswith('j')]
    require(branches==[(START+6,'je',START+48),(START+11,'jne',START+24),(START+27,'jne',START+16),(START+36,'jmp',START+16)],'branch closure')
    require([i.address for i in ins if i.mnemonic=='ret']==[START+18,END-1],'two returns')
    require(START+55+struct.unpack_from('<i',raw,51)[0]==POINT,'actual LEA destination')
    body={**frame(START,END),'begin':START,'end':END,'bytes':len(raw),'sha256':sha(raw),'hex':raw.hex(),'file_offset':where['file_offset'],'instructions':[{'address':i.address,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in ins]}
    neighbors=[frame(0x50576b0,START-12),frame(END+3,0x505774e)]
    require(im.va_bytes(START-12,12)[0]==b'\xcc'*12,'leading padding');require(im.va_bytes(END,3)[0]==b'\xcc'*3,'following padding')
    value,mapping=im.va_bytes(POINT,8);require(value==bytes(8) and mapping['section']['name']=='.data.rel.ro','unread target storage')
    rels=[];count=0
    for s in im.sections:
        require(s['type']!=9,'unsupported REL')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for at in range(s['offset'],s['offset']+s['size'],24):
            dest,info,addend=struct.unpack_from('<QQq',data,at);count+=1;require(info&0xffffffff in [1,6,7,8,18],'relocation width')
            require(addend!=START,'entry naming relocation');require(not (dest<END+3 and START-12<dest+8),'code relocation')
            if dest<POINT+8 and POINT<dest+8:
                require(dest==POINT and info==(260<<32)|1 and addend==16 and s['name']=='.rela.dyn','unread R_X86_64_64 context')
                rels.append({'file_offset':at,'hex':data[at:at+24].hex(),'destination':dest,'symbol':260,'type':1,'addend':16})
    require(len(rels)==1,'unique target word relocation');symbol=unread_symbol(data,im)
    tx=next(s for s in im.sections if s['name']=='.text');code=im.va_bytes(tx['address'],tx['size'],executable=True)[0];edges={}
    for op in [b'\xe8',b'\xe9']:
        hits=[];at=0
        while (at:=code.find(op,at))>=0:
            if at+5<=len(code) and tx['address']+at+5+struct.unpack_from('<i',code,at+1)[0]==START:hits.append(tx['address']+at)
            at+=1
        require(not hits,'direct edge census');edges[op.hex()]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':body,'neighbors':neighbors,'leading_padding_hex':'cc'*12,'following_padding_hex':'cc'*3,'branches':branches,'address_context':{'va':POINT,'file_hex':value.hex(),'mapping':mapping,'relocation':rels[0],'symbol':symbol,'contents_read_by_leaf':False},'rela_records_checked':count,'naming_relocations':[],'direct_encoding_candidates':edges,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}

def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');r=inspect(data);b=r['body'];c=r['address_context'];s=c['symbol']
    changes={f'body operand+{n}':b['file_offset']+n for n in [5,7,10,12,15,17,26,28,31,35,37,51,57,59]}
    changes.update({'FDE':b['records']['fde']['file_offset']+12,'CIE':b['records']['cie']['file_offset']+15,'previous FDE':r['neighbors'][0]['records']['fde']['file_offset']+12,'next FDE':r['neighbors'][1]['records']['fde']['file_offset']+12,'leading padding':b['file_offset']-1,'following padding':b['file_offset']+61,'unread target bytes':c['mapping']['file_offset'],'target relocation destination':c['relocation']['file_offset'],'target relocation symbol':c['relocation']['file_offset']+12,'target relocation addend':c['relocation']['file_offset']+16,'symbol type':s['file_offset']+4,'symbol name':s['name_offset'],'version index':s['version_index_offset'],'version name':s['requirement']['version_name_offset'],'version aux':s['requirement']['aux_offset'],'needed':s['needed']['file_offset']+8})
    rejected={}
    for label,at in changes.items():
        changed=bytearray(data);changed[at]^=1
        try:
            other=inspect(bytes(changed));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in r.items() if k!='target_sha256'},'structural drift')
        except (ValueError,UnicodeError) as e:rejected[label]=str(e)
        else:raise ValueError('accepted corruption '+label)
    r['corruption_controls']=rejected;return r

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');a=ap.parse_args();r=validate()
    if a.freeze:
        with (PACKET/'static.json').open('xb') as f:f.write(encoded(r))
    else:require((PACKET/'static.json').read_bytes()==encoded(r),'static drift')
    print(json.dumps({'instructions':len(r['body']['instructions']),'controls':len(r['corruption_controls']),'unread_symbol':r['address_context']['symbol']['name']}))
if __name__=='__main__':main()
