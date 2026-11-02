"""Bind four complete cursor leaves, separate padding and all naming slot writers."""
import argparse,json,re,struct,sys
from oracle import ROOT,PACKET,require,sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 86797904, 'end': 86797924, 'body_sha256': 'f79e609f4ed53098d355f37fd69b0b478ee97f54dda887d31829a7f94ca537ef', 'padding': 12, 'instructions': 6, 'returns': [86797923], 'edges': [], 'frame': {'fde': 16306568, 'cie': 13505816, 'start': 86797904, 'end': 86797924, 'lsda': None}, 'naming': [{'file_offset': 1675952, 'destination': 91624784, 'info': 8, 'addend': 86797904, 'raw_hex': '0000000000000000', 'mapping': {'va': 91624784, 'file_offset': 91616592, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}, {'index': 1, 'begin': 86797936, 'end': 86797948, 'body_sha256': '0a0189a288561acefa67f89d95990882a6b37fd5e34cbc3a7e8fe0403d90bb60', 'padding': 4, 'instructions': 4, 'returns': [86797947], 'edges': [], 'frame': {'fde': 16306588, 'cie': 13505816, 'start': 86797936, 'end': 86797948, 'lsda': None}, 'naming': [{'file_offset': 1676240, 'destination': 91624888, 'info': 8, 'addend': 86797936, 'raw_hex': '0000000000000000', 'mapping': {'va': 91624888, 'file_offset': 91616696, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}, {'index': 2, 'begin': 86797952, 'end': 86797979, 'body_sha256': '4e43b3166e85dda6fc4ce23db4fa51ffb9cda645bc5e48a8ab92d60aeee0c9ac', 'padding': 5, 'instructions': 8, 'returns': [86797978], 'edges': [[86797968, 86797978]], 'frame': {'fde': 16306608, 'cie': 13505816, 'start': 86797952, 'end': 86797979, 'lsda': None}, 'naming': [{'file_offset': 1676264, 'destination': 91624896, 'info': 8, 'addend': 86797952, 'raw_hex': '0000000000000000', 'mapping': {'va': 91624896, 'file_offset': 91616704, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}, {'index': 3, 'begin': 86797984, 'end': 86798025, 'body_sha256': 'cb860eb0c4cbde0f0ab2a2b8603bd2ca95807beadff7b2a2c670ab990498212b', 'padding': 7, 'instructions': 12, 'returns': [86798009, 86798024], 'edges': [[86797999, 86798016]], 'frame': {'fde': 16306628, 'cie': 13505816, 'start': 86797984, 'end': 86798025, 'lsda': None}, 'naming': [{'file_offset': 1676288, 'destination': 91624904, 'info': 8, 'addend': 86797984, 'raw_hex': '0000000000000000', 'mapping': {'va': 91624904, 'file_offset': 91616712, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}]
def listing(path,image,begin,end):
    rows,cursor=[],begin
    for line in path.read_text().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if match:
            address,raw=int(match[1],16),bytes.fromhex(match[2])
            require(address==cursor and address+len(raw)<=end,'listing extent')
            require(image.va_bytes(address,len(raw),executable=True)[0]==raw,'listing bytes')
            rows.append((address,raw));cursor+=len(raw)
    require(cursor==end,'complete listing')
    return rows


def inspect(data):
    im=Elf(data,3);_,frames=eh_frame_records(data);dec=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);members=[]
    for m in MEMBERS:
        a,b=m['begin'],m['end'];raw,where=im.va_bytes(a,b-a,executable=True)
        require(sha(raw)==m['body_sha256'],'complete member body')
        overlaps=[f for f in frames if f['start']<b and a<f['end']]
        require(len(overlaps)==1 and (overlaps[0]['start'],overlaps[0]['end'])==(a,b),'unique complete FDE')
        f=overlaps[0];records={}
        for kind in ('fde','cie'):
            va=f[kind];size=int.from_bytes(im.va_bytes(va,4)[0],'little')+4;val,loc=im.va_bytes(va,size);records[kind]={'va':va,'file_offset':loc['file_offset'],'hex':val.hex()}
        name='member'+str(m['index']);gnu=listing(PACKET/(name+'.gnu.txt'),im,a,b);llvm=listing(PACKET/(name+'.llvm.txt'),im,a,b);decoded=list(dec.disasm(raw,a))
        require(gnu==llvm==[(i.address,bytes(i.bytes)) for i in decoded],'three decoder bytes/boundaries')
        require(len(decoded)==m['instructions'],'complete instruction count')
        edges=[(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic.startswith('j')]
        require(edges==[tuple(x) for x in m['edges']],'all branch edges closed')
        require(not any(i.mnemonic=='call' for i in decoded),'no called helper')
        require([i.address for i in decoded if i.mnemonic=='ret']==m['returns'],'all return boundaries')
        require(not any('rip' in i.op_str for i in decoded),'no static data dependency')
        require(im.va_bytes(b,m['padding'])[0]==b'\xcc'*m['padding'],'separately bounded padding')
        naming=[]
        for n in m['naming']:
            raw_slot,slot_mapping=im.va_bytes(n['destination'],8)
            require(raw_slot==bytes(8) and slot_mapping==n['mapping'],'raw slot and mapping')
            sections=[s for s in im.sections if s['address']<=n['destination'] and n['destination']+8<=s['address']+s['size'] and s['flags']&2]
            require(len(sections)==1 and sections[0]['name']=='.data.rel.ro','entry slot section')
            require(struct.unpack_from('<QQq',data,n['file_offset'])==(n['destination'],8,a),'exact symbol-zero RELATIVE record')
            naming.append(n)
        members.append({**m,'file_offset':where['file_offset'],'hex':raw.hex(),'frame':f,'records':records,'instructions':len(decoded)})
    starts={m['begin'] for m in MEMBERS};protected=[(m['begin'],m['end']+m['padding']) for m in MEMBERS];count=0
    slots={n['destination']:[] for m in MEMBERS for n in m['naming']};seen=[]
    for s in im.sections:
        require(s['type']!=9,'unsupported REL')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for o in range(s['offset'],s['offset']+s['size'],24):
            dst,info,add=struct.unpack_from('<QQq',data,o);count+=1
            require(info&0xffffffff in (1,6,7,8,18),'relocation width')
            if add in starts:seen.append((o,dst,info,add))
            for slot in slots:
                if dst<slot+8 and slot<dst+8:slots[slot].append((o,dst,info,add))
            require(not any(dst<b and a<dst+8 for a,b in protected),'code relocation')
    expected=sorted((n['file_offset'],n['destination'],n['info'],n['addend']) for m in MEMBERS for n in m['naming'])
    require(sorted(seen)==expected,'all naming records')
    for n in [n for m in MEMBERS for n in m['naming']]:require(slots[n['destination']]==[(n['file_offset'],n['destination'],n['info'],n['addend'])],'single complete relocation writer')
    tx=next(s for s in im.sections if s['name']=='.text');code=im.va_bytes(tx['address'],tx['size'],executable=True)[0];census={}
    for op,name in [(b'\xe8','E8'),(b'\xe9','E9')]:
        pos=0;hits=[]
        while (pos:=code.find(op,pos))>=0:
            if pos+5<=len(code) and tx['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0] in starts:hits.append(tx['address']+pos)
            pos+=1
        require(not hits,'direct '+name+' candidate census');census[name]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'rela_records_checked':count,'naming_relocations':expected,'slot_writers':slots,'direct_candidates':census,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args();data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');record=inspect(data);locations={}
    for m in record['members']:
        n=str(m['index']);locations['FDE extent '+n]=m['records']['fde']['file_offset']+12
        offsets={0:[4,7,8,11,12,15,18,19,20],1:[4,7,8,10,11,12],2:[4,7,11,12,15,16,18,21,22,25,26,27],3:[4,7,11,12,14,15,17,20,21,24,25,26,32,35,36,39,40,41]}[m['index']]
        for o in offsets:locations['semantic/padding '+n+' '+str(o)]=m['file_offset']+o
        for q in m['naming']:
            locations['slot '+n]=q['mapping']['file_offset'];locations['relocation '+n]=q['file_offset']+8;locations['destination '+n]=q['file_offset']
    locations['CIE encoding']=record['members'][0]['records']['cie']['file_offset']+15;rejected={}
    for label,offset in locations.items():
        changed=bytearray(data);changed[offset]^=1
        try:
            other=inspect(bytes(changed));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural drift')
        except ValueError as e:rejected[label]=str(e)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected;text=json.dumps(record,indent=2,sort_keys=True)+'\n'
    if args.write:
        with (PACKET/'static.json').open('x') as f:f.write(text)
    else:require((PACKET/'static.json').read_text()==text,'retained static drift')
    print(json.dumps({'members':len(record['members']),'controls':len(rejected),'rela_records':record['rela_records_checked']}))
if __name__=='__main__':main()
