"""Bind the complete flag-set/conditional-clear leaf and caller contexts."""
import argparse,json,re,struct,sys
from oracle import ROOT,PACKET,require,sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 87881056, 'end': 87881086, 'body_sha256': '2650c17ced285d5240ac9cfc738269c0df94bbccdd9c9fc901da0ba032fb2c10', 'padding': 2, 'instructions': 7, 'returns': [87881085], 'edges': [(87881080, 87881085)], 'calls': [], 'frame': {'fde': 16350296, 'cie': 13505816, 'start': 87881056, 'end': 87881086, 'lsda': None}, 'naming': []}]
CALLERS=[{'index': 0, 'begin': 85588544, 'end': 85591133, 'body_sha256': '2c4f691e6e65de9b138e2db0a67e985ed25fd2aebed8d469cf00533578f76769', 'instructions': 577, 'frame': {'fde': 20025240, 'cie': 19929832, 'start': 85588544, 'end': 85591133, 'lsda': 12427227}, 'sites': [85590412]}, {'index': 1, 'begin': 85600592, 'end': 85605593, 'body_sha256': '747be80b2d988cbc711704767d2bf43e3dfdab8f05870a4e7cef4fe64dde88c8', 'instructions': 1076, 'frame': {'fde': 20025964, 'cie': 19929832, 'start': 85600592, 'end': 85605593, 'lsda': 12427615}, 'sites': [85605328]}, {'index': 2, 'begin': 85798288, 'end': 85802409, 'body_sha256': 'a5d6ca338246398258ffe4c31cb4d298abe833f0e964aaadf61468aa27d32dfd', 'instructions': 826, 'frame': {'fde': 20032528, 'cie': 19929832, 'start': 85798288, 'end': 85802409, 'lsda': 12432426}, 'sites': [85802062]}, {'index': 3, 'begin': 85847376, 'end': 85851065, 'body_sha256': 'ad9c5773a3a0994307149fd5e0918bfc59cf9aae5b22c6843107c58abbf0e176', 'instructions': 716, 'frame': {'fde': 20034468, 'cie': 19929832, 'start': 85847376, 'end': 85851065, 'lsda': 12433444}, 'sites': [85848717]}, {'index': 4, 'begin': 87464656, 'end': 87472808, 'body_sha256': '1ee5cc957136409caf7892262e17fc83954737f9af7b4962eacce1dccb621c49', 'instructions': 1541, 'frame': {'fde': 20140088, 'cie': 19929832, 'start': 87464656, 'end': 87472808, 'lsda': 12489190}, 'sites': [87471372]}, {'index': 5, 'begin': 87531184, 'end': 87547233, 'body_sha256': '0e3b2ad652bb2efc5a477a25d4f494512fb7fef9b03d735261c5d6e03ebc7654', 'instructions': 3053, 'frame': {'fde': 20142172, 'cie': 19929832, 'start': 87531184, 'end': 87547233, 'lsda': 12490967}, 'sites': [87544224]}, {'index': 6, 'begin': 87884688, 'end': 87884877, 'body_sha256': '29a7b36ea5e16dc0ca247d5c8ac1ee8f9b3d6c592cbe236438ce6b8d7fa1a0e5', 'instructions': 50, 'frame': {'fde': 20157660, 'cie': 19929832, 'start': 87884688, 'end': 87884877, 'lsda': 12500098}, 'sites': [87884851]}]
HITS=[{'kind': 'E8', 'site': 85590412, 'target': 87881056}, {'kind': 'E8', 'site': 85605328, 'target': 87881056}, {'kind': 'E8', 'site': 85802062, 'target': 87881056}, {'kind': 'E8', 'site': 85848717, 'target': 87881056}, {'kind': 'E8', 'site': 87471372, 'target': 87881056}, {'kind': 'E8', 'site': 87544224, 'target': 87881056}, {'kind': 'E8', 'site': 87884851, 'target': 87881056}]
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
    if path.name.endswith('.llvm.txt'):
        # Exact observed display splits only; the raw exports remain unchanged.
        locks={0x51d344d:bytes.fromhex('f04881407000040000'),0x536a51a:bytes.fromhex('f00fab1481'),0x537b600:bytes.fromhex('f00fab1481')}
        joined=[];index=0
        while index<len(rows):
            address,raw=rows[index]
            if address in locks:
                require(raw==b'\xf0' and index+1<len(rows),'exact LLVM LOCK prefix')
                nxt,tail=rows[index+1]
                require(nxt==address+1 and raw+tail==locks[address],'exact LLVM LOCK tail')
                joined.append((address,raw+tail));index+=2
            else:joined.append((address,raw));index+=1
        rows=joined
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
        require([(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic=='call']==[tuple(x) for x in m['calls']],'all helper calls closed')
        require([i.address for i in decoded if i.mnemonic=='ret']==m['returns'],'all return boundaries')
        require(not any('rip' in i.op_str for i in decoded),'no static data dependency')
        require((not m['padding'] or im.va_bytes(b,m['padding'])[0]==b'\xcc'*m['padding']),'separately bounded padding')
        naming=[]
        for n in m['naming']:
            raw_slot,slot_mapping=im.va_bytes(n['destination'],8)
            require(raw_slot==bytes(8) and slot_mapping==n['mapping'],'raw slot and mapping')
            sections=[s for s in im.sections if s['address']<=n['destination'] and n['destination']+8<=s['address']+s['size'] and s['flags']&2]
            require(len(sections)==1 and sections[0]==n['mapping']['section'],'entry slot section')
            require(struct.unpack_from('<QQq',data,n['file_offset'])==(n['destination'],8,a),'exact symbol-zero RELATIVE record')
            naming.append(n)
        members.append({**m,'file_offset':where['file_offset'],'hex':raw.hex(),'frame':f,'records':records,'instructions':len(decoded)})
    caller_records=[]
    for c in CALLERS:
        a,b=c['begin'],c['end'];raw,loc=im.va_bytes(a,b-a,executable=True)
        require(sha(raw)==c['body_sha256'],'full caller body')
        overlaps=[f for f in frames if f['start']<b and a<f['end']]
        require(len(overlaps)==1 and overlaps[0]==c['frame'],'unique caller FDE')
        gnu=listing(PACKET/('caller'+str(c['index'])+'.gnu.txt'),im,a,b)
        llvm=listing(PACKET/('caller'+str(c['index'])+'.llvm.txt'),im,a,b)
        decoded=list(dec.disasm(raw,a))
        require(gnu==llvm==[(i.address,bytes(i.bytes)) for i in decoded],'complete caller three-decoder boundaries')
        require(len(decoded)==c['instructions'],'caller instruction count')
        lookup={i.address:i for i in decoded}
        for site in c['sites']:
            match=next(h for h in HITS if h['kind']=='E8' and h['site']==site)
            require(site in lookup and lookup[site].mnemonic=='call' and int(lookup[site].op_str,16)==match['target'],'caller boundary and actual target')
        records={}
        for kind in ('fde','cie'):
            va=c['frame'][kind];size=int.from_bytes(im.va_bytes(va,4)[0],'little')+4;val,where=im.va_bytes(va,size);records[kind]={'va':va,'file_offset':where['file_offset'],'hex':val.hex()}
        caller_records.append({**c,'file_offset':loc['file_offset'],'records':records})
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
        require(hits==[h['site'] for h in HITS if h['kind']==name],'direct '+name+' candidate census');census[name]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'callers':caller_records,'rela_records_checked':count,'naming_relocations':expected,'slot_writers':slots,'direct_candidates':census,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args();data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity');record=inspect(data);locations={}
    for m in record['members']:
        n=str(m['index']);locations['FDE extent '+n]=m['records']['fde']['file_offset']+12
        offsets=sorted(set([x.address-m['begin'] for x in capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64).disasm(bytes.fromhex(m['hex']),m['begin'])]+([m['end']-m['begin']] if m['padding'] else [])))
        for o in offsets:locations['semantic/padding '+n+' '+str(o)]=m['file_offset']+o
        for q in m['naming']:
            locations['slot '+hex(q['destination'])]=q['mapping']['file_offset'];locations['relocation '+hex(q['destination'])]=q['file_offset']+8;locations['destination '+hex(q['destination'])]=q['file_offset']
    for c in record['callers']:
        locations['caller FDE '+str(c['index'])]=c['records']['fde']['file_offset']+12
        for site in c['sites']:locations['caller edge '+str(site)]=c['file_offset']+site-c['begin']+1
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
