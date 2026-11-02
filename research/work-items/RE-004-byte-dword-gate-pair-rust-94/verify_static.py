"""Bind signed byte/dword gate and its full tail-caller closure, separate padding and all naming slot writers."""
import argparse,json,re,struct,sys
from oracle import ROOT,PACKET,require,sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 85404784, 'end': 85404810, 'body_sha256': '45c3aa33bfd44e405b1f718694476353b9c676d60b7557bf2ac4affa88e66a1e', 'padding': 6, 'instructions': 10, 'returns': [85404809], 'edges': [(85404797, 85404803), (85404801, 85404809)], 'frame': {'fde': 16243064, 'cie': 13505816, 'start': 85404784, 'end': 85404810, 'lsda': None}, 'naming': []}, {'index': 1, 'begin': 85404816, 'end': 85404853, 'body_sha256': 'cda08a36489812ded33ca840e91679f12c68a82a4b0f3316979488adaf67d84c', 'padding': 1, 'instructions': 9, 'returns': [85404839], 'edges': [(85404832, 85404848), (85404848, 85404784)], 'frame': {'fde': 16243084, 'cie': 13505816, 'start': 85404816, 'end': 85404853, 'lsda': None}, 'naming': []}]
CALLERS=[{'index': 0, 'begin': 84125680, 'end': 84126576, 'body_sha256': 'f7b754a7928a4143926fce5670d0161782feb69ee616cc8b90076f1f17c2a4a1', 'instructions': 217, 'frame': {'fde': 19967220, 'cie': 19929832, 'start': 84125680, 'end': 84126576, 'lsda': 12387464}, 'sites': [84126135]}, {'index': 1, 'begin': 84179920, 'end': 84186036, 'body_sha256': '66513bed292f4bf072f50f3135b70c748e423bb2124d78c3140c0a6be96fa533', 'instructions': 1219, 'frame': {'fde': 19968780, 'cie': 19929832, 'start': 84179920, 'end': 84186036, 'lsda': 12388680}, 'sites': [84180958]}, {'index': 2, 'begin': 84855440, 'end': 84857859, 'body_sha256': '5e0dafc940f3f34ef4dfdddcd29bb49e67a8d9ed7230dd72fa99ffeac2c437af', 'instructions': 442, 'frame': {'fde': 19994592, 'cie': 19929832, 'start': 84855440, 'end': 84857859, 'lsda': 12408097}, 'sites': [84855734]}, {'index': 3, 'begin': 85241392, 'end': 85241432, 'body_sha256': 'edccc20b7e55d78684df3abda3b3aaa87183838e8db10dfca5efd74791af3f5f', 'instructions': 11, 'frame': {'fde': 16234380, 'cie': 13505816, 'start': 85241392, 'end': 85241432, 'lsda': None}, 'sites': [85241414]}]
HITS=[{'kind': 'E8', 'site': 84126135, 'target': 85404784, 'frames': [{'fde': 19967220, 'cie': 19929832, 'start': 84125680, 'end': 84126576, 'lsda': 12387464}]}, {'kind': 'E8', 'site': 84180958, 'target': 85404784, 'frames': [{'fde': 19968780, 'cie': 19929832, 'start': 84179920, 'end': 84186036, 'lsda': 12388680}]}, {'kind': 'E8', 'site': 84855734, 'target': 85404816, 'frames': [{'fde': 19994592, 'cie': 19929832, 'start': 84855440, 'end': 84857859, 'lsda': 12408097}]}, {'kind': 'E8', 'site': 85241414, 'target': 85404784, 'frames': [{'fde': 16234380, 'cie': 13505816, 'start': 85241392, 'end': 85241432, 'lsda': None}]}, {'kind': 'E9', 'site': 85404848, 'target': 85404784, 'frames': [{'fde': 16243084, 'cie': 13505816, 'start': 85404816, 'end': 85404853, 'lsda': None}]}]
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
        split={0x503a84c:bytes.fromhex('f083423801'),0x503a9c4:bytes.fromhex('f083453801'),0x50ecdb7:bytes.fromhex('f04183453801')}
        joined=[];index=0
        while index<len(rows):
            address,raw=rows[index]
            if address in split:
                require(raw==b'\xf0' and index+1<len(rows),'exact split LOCK prefix')
                following,value=rows[index+1]
                require(following==address+1 and raw+value==split[address],'exact LOCK ADD display pair')
                joined.append((address,raw+value));index+=2
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
        offsets={0:[4,7,8,10,11,13,14,15,17,18,19,21,22,24,25,26],1:[4,7,8,11,12,15,16,17,18,19,23,24,32,33,36,37]}[m['index']]
        for o in offsets:locations['semantic/padding '+n+' '+str(o)]=m['file_offset']+o
        for q in m['naming']:
            locations['slot '+n]=q['mapping']['file_offset'];locations['relocation '+n]=q['file_offset']+8;locations['destination '+n]=q['file_offset']
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
