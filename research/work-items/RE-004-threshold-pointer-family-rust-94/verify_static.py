"""Bind three threshold pointer leaves and runtime-global mapping, with exact ordered access closure."""
import argparse,json,re,struct,sys
from oracle import ROOT,PACKET,require,sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 88962784, 'end': 88962809, 'body_sha256': 'd2e1366f59867e89e5bec319d8b2568f0dc35e9e96bbdfea80ac502f722df019', 'frame': {'fde': 16395380, 'cie': 13505816, 'start': 88962784, 'end': 88962809, 'lsda': None}, 'padding': 7, 'file_offset': 88958688, 'instructions': 6, 'naming': [{'file_offset': 1759328, 'destination': 91661992, 'info': 8, 'addend': 88962784, 'raw_hex': '0000000000000000', 'mapping': {'va': 91661992, 'file_offset': 91653800, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}, {'index': 1, 'begin': 88962816, 'end': 88962867, 'body_sha256': 'dac2c6124d5c41b287f459201155ebd6e3a72e6df1d318bdc36fa07d7dd1a3b4', 'frame': {'fde': 16395400, 'cie': 13505816, 'start': 88962816, 'end': 88962867, 'lsda': None}, 'padding': 13, 'file_offset': 88958720, 'instructions': 14, 'naming': [{'file_offset': 1767800, 'destination': 91669400, 'info': 8, 'addend': 88962816, 'raw_hex': '0000000000000000', 'mapping': {'va': 91669400, 'file_offset': 91661208, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}, {'index': 2, 'begin': 88962880, 'end': 88962931, 'body_sha256': '4fc56fe843139c31872a242d12b2ee3a6368769b3913aef425176b69a4ffab32', 'frame': {'fde': 16395420, 'cie': 13505816, 'start': 88962880, 'end': 88962931, 'lsda': None}, 'padding': 13, 'file_offset': 88958784, 'instructions': 14, 'naming': [{'file_offset': 1767632, 'destination': 91669240, 'info': 8, 'addend': 88962880, 'raw_hex': '0000000000000000', 'mapping': {'va': 91669240, 'file_offset': 91661048, 'bytes': 8, 'section': {'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}, 'PT_LOAD': {'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}}}]}]
CONTEXTS=[{'address': 93961030, 'sections': [{'type': 8, 'flags': 3, 'address': 91783936, 'offset': 91771632, 'size': 2263936, 'link': 0, 'info': 0, 'align': 64, 'entsize': 0, 'index': 30, 'name': '.bss'}], 'loads': [{'type': 1, 'flags': 6, 'offset': 91715152, 'address': 91727440, 'paddr': 91727440, 'filesz': 56480, 'memsz': 2320432, 'align': 4096}], 'overlapping_rela': []}, {'address': 93977552, 'sections': [{'type': 8, 'flags': 3, 'address': 91783936, 'offset': 91771632, 'size': 2263936, 'link': 0, 'info': 0, 'align': 64, 'entsize': 0, 'index': 30, 'name': '.bss'}], 'loads': [{'type': 1, 'flags': 6, 'offset': 91715152, 'address': 91727440, 'paddr': 91727440, 'filesz': 56480, 'memsz': 2320432, 'align': 4096}], 'overlapping_rela': []}, {'address': 91662016, 'sections': [{'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}], 'loads': [{'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}], 'overlapping_rela': []}, {'address': 91669408, 'sections': [{'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}], 'loads': [{'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}], 'overlapping_rela': []}, {'address': 91669248, 'sections': [{'type': 1, 'flags': 3, 'address': 90583712, 'offset': 90575520, 'size': 1092304, 'link': 0, 'info': 0, 'align': 32, 'entsize': 0, 'index': 23, 'name': '.data.rel.ro'}], 'loads': [{'type': 1, 'flags': 6, 'offset': 90571344, 'address': 90579536, 'paddr': 90579536, 'filesz': 1143808, 'memsz': 1146288, 'align': 4096}], 'overlapping_rela': []}]
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
        want=[] if m['index']==0 else [(a+14,a+48),(a+26,a+48),(a+(32 if m['index']==1 else 35),a+48)]
        require(edges==want,'all branch edges closed')
        require(not any(i.mnemonic=='call' for i in decoded),'no called helper')
        require([i.address for i in decoded if i.mnemonic=='ret']==([b-1] if m['index']==0 else [a+(41 if m['index']==1 else 44),b-1]),'all return boundaries')
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
    context_writers={c['address']:[] for c in CONTEXTS}
    for s in im.sections:
        require(s['type']!=9,'unsupported REL')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for o in range(s['offset'],s['offset']+s['size'],24):
            dst,info,add=struct.unpack_from('<QQq',data,o);count+=1
            require(info&0xffffffff in (1,6,7,8,18),'relocation width')
            if add in starts:seen.append((o,dst,info,add))
            for address in context_writers:
                if dst<=address<dst+8:context_writers[address].append((o,dst,info,add))
            for slot in slots:
                if dst<slot+8 and slot<dst+8:slots[slot].append((o,dst,info,add))
            require(not any(dst<b and a<dst+8 for a,b in protected),'code relocation')
    expected=sorted((n['file_offset'],n['destination'],n['info'],n['addend']) for m in MEMBERS for n in m['naming'])
    require(sorted(seen)==expected,'all naming records')
    for n in [n for m in MEMBERS for n in m['naming']]:require(slots[n['destination']]==[(n['file_offset'],n['destination'],n['info'],n['addend'])],'single complete relocation writer')
    for c in CONTEXTS:
        a=c['address'];sections=[s for s in im.sections if s['address']<=a<s['address']+s['size'] and s['flags']&2]
        segments=[s for s in im.segments if s['type']==1 and s['address']<=a<s['address']+s['memsz']]
        require(sections==c['sections'] and segments==c['loads'],'complete mapped context')
        require(not context_writers[a],'no relocation writer to global/address byte')
        if a in (0x599bb46,0x599fbd0):
            require(len(sections)==len(segments)==1 and sections[0]['type']==8 and sections[0]['name']=='.bss','NOBITS globals')
            require(a>=segments[0]['address']+segments[0]['filesz'] and segments[0]['flags']&2,'writable zero-fill mapping, not file byte value')
        else:require(len(sections)==len(segments)==1 and sections[0]['name']=='.data.rel.ro','address-only result mapping')
    tx=next(s for s in im.sections if s['name']=='.text');code=im.va_bytes(tx['address'],tx['size'],executable=True)[0];census={}
    for op,name in [(b'\xe8','E8'),(b'\xe9','E9')]:
        pos=0;hits=[]
        while (pos:=code.find(op,pos))>=0:
            if pos+5<=len(code) and tx['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0] in starts:hits.append(tx['address']+pos)
            pos+=1
        require(not hits,'direct '+name+' candidate census');census[name]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'rela_records_checked':count,'naming_relocations':expected,'slot_writers':slots,'contexts':CONTEXTS,'context_writers':context_writers,'direct_candidates':census,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args();data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');record=inspect(data);locations={}
    for m in record['members']:
        n=str(m['index']);locations['body '+n]=m['file_offset']+4;locations['padding '+n]=m['file_offset']+m['end']-m['begin']
        locations['FDE extent '+n]=m['records']['fde']['file_offset']+12
        for i in (8,13,20) if m['index']==0 else (11,14,17,23,26,29,35,38,48,50):locations['semantic '+n+' '+str(i)]=m['file_offset']+i
        for q in m['naming']:
            locations['slot '+n]=q['mapping']['file_offset'];locations['relocation '+n]=q['file_offset']+8;locations['destination '+n]=q['file_offset']
    shoff=struct.unpack_from('<Q',data,40)[0];phoff=struct.unpack_from('<Q',data,32)[0]
    locations['bss extent']=shoff+64*CONTEXTS[0]['sections'][0]['index']+32
    locations['load memory size']=phoff+56*next(i for i,s in enumerate(Elf(data,3).segments) if s==CONTEXTS[0]['loads'][0])+40
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
