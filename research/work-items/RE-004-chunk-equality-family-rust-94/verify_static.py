"""Bind twelve complete chunk-comparison functions, constants and relocation slots."""
import argparse,json,re,struct,sys
from oracle import ROOT, PACKET, require, sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 21713584, 'end': 21713617, 'body_sha256': '144441a09d34c95917862103ef8752f34e7970796b0827f4c2d67c0a3a07bc62', 'constant_va': 2130688, 'constant_hex': 'f86e515c5a0d0918c20ac95e03583e31', 'naming': [{'file_offset': 92648, 'destination': 90629656, 'info': 8, 'addend': 21713584, 'hex': '18e66605000000000800000000000000b0524b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 1, 'begin': 21713632, 'end': 21713665, 'body_sha256': 'f08e9008db06b9c16f8753f5bcb80490e06568a7298ae553056e2520e103b61f', 'constant_va': 2126560, 'constant_hex': 'e73d5da0de0730902196b280937e3b5b', 'naming': [{'file_offset': 91064, 'destination': 90629128, 'info': 8, 'addend': 21713632, 'hex': '08e46605000000000800000000000000e0524b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 2, 'begin': 21713680, 'end': 21713713, 'body_sha256': '1a7374fd14fee203bf880b79638b438120ec2415b05b0d4e1d411d158d6b5e1b', 'constant_va': 2119552, 'constant_hex': '18978bb257d5dc38a39d9626eef330cd', 'naming': [{'file_offset': 92072, 'destination': 90629464, 'info': 8, 'addend': 21713680, 'hex': '58e5660500000000080000000000000010534b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 3, 'begin': 21713728, 'end': 21713761, 'body_sha256': '8296b84a8aad0edfefdd9e76a4bb8939b025ecacc77d5579847264f657cfc77a', 'constant_va': 2119568, 'constant_hex': '9302580864d761d51371d3c634606ffb', 'naming': [{'file_offset': 91352, 'destination': 90629224, 'info': 8, 'addend': 21713728, 'hex': '68e4660500000000080000000000000040534b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 4, 'begin': 21713776, 'end': 21713809, 'body_sha256': 'ae28650e2fc6ff8a208155c149288ff61b64b25ab68935de3ff396e846b92f90', 'constant_va': 2118832, 'constant_hex': 'b76d6b683e7e14f2af3e8f0bd8ebb83a', 'naming': [{'file_offset': 92216, 'destination': 90629512, 'info': 8, 'addend': 21713776, 'hex': '88e5660500000000080000000000000070534b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 5, 'begin': 21713824, 'end': 21713857, 'body_sha256': '480a67638c4528ea677b4c6e2b8efc7fc1c8b82fa607f042ac5f36a0cfb3892a', 'constant_va': 2131536, 'constant_hex': 'e4fb4a93c0ee9c44ea0b5a5f63e0800e', 'naming': [{'file_offset': 91640, 'destination': 90629320, 'info': 8, 'addend': 21713824, 'hex': 'c8e46605000000000800000000000000a0534b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 6, 'begin': 21713872, 'end': 21713905, 'body_sha256': '43975aebf0b5be048593b9341445269e3bdd173ac79ec1b928494b19163c3a37', 'constant_va': 2112288, 'constant_hex': '2876156f612a7361ccade60e375e726e', 'naming': [{'file_offset': 91784, 'destination': 90629368, 'info': 8, 'addend': 21713872, 'hex': 'f8e46605000000000800000000000000d0534b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 7, 'begin': 21713920, 'end': 21713953, 'body_sha256': 'fa581760ac06c95cf153d60a0c54806c0490f12a4e8eba0d4f1ef6bd68df45d4', 'constant_va': 2126576, 'constant_hex': '4b77fd3bb270b80a74bae40bda048937', 'naming': [{'file_offset': 92504, 'destination': 90629608, 'info': 8, 'addend': 21713920, 'hex': 'e8e5660500000000080000000000000000544b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 8, 'begin': 21713968, 'end': 21714001, 'body_sha256': '6c3582c025dd3500cee41ea61d27dc8786b449958780f8b56d58f79df11bf4d1', 'constant_va': 2109712, 'constant_hex': '6d5dcbd62c50eb637841a657711b8bb9', 'naming': [{'file_offset': 91208, 'destination': 90629176, 'info': 8, 'addend': 21713968, 'hex': '38e4660500000000080000000000000030544b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 9, 'begin': 21714016, 'end': 21714049, 'body_sha256': 'ebf9a146cf8c40453a125fda36071afb92870339a15697f1f9b11eb04fb93269', 'constant_va': 2123808, 'constant_hex': '507e85b2bc09f7468f129a7c0cbd7c63', 'naming': [{'file_offset': 91496, 'destination': 90629272, 'info': 8, 'addend': 21714016, 'hex': '98e4660500000000080000000000000060544b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 10, 'begin': 21714064, 'end': 21714097, 'body_sha256': '6d905f0d81c8ac73ee417505671a56090f179b3f021e2689bb35e3fd6aefc39b', 'constant_va': 2111504, 'constant_hex': 'd16caa81efab68379d4c146fcca68d2b', 'naming': [{'file_offset': 92360, 'destination': 90629560, 'info': 8, 'addend': 21714064, 'hex': 'b8e5660500000000080000000000000090544b0100000000', 'slot_hex': '0000000000000000'}]}, {'index': 11, 'begin': 21714112, 'end': 21714145, 'body_sha256': 'f0569246c5addb31b74ee928631d4a195df994ecde802540e3e16635c519bde5', 'constant_va': 2111520, 'constant_hex': 'e50b9db6f49bdddfff66a665d539d4bf', 'naming': [{'file_offset': 91928, 'destination': 90629416, 'info': 8, 'addend': 21714112, 'hex': '28e56605000000000800000000000000c0544b0100000000', 'slot_hex': '0000000000000000'}]}]

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
    im=Elf(data,3);_,frames=eh_frame_records(data)
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
    members=[];protected=[]
    for m in MEMBERS:
        a,b=m['begin'],m['end'];raw,where=im.va_bytes(a,b-a,executable=True)
        require(sha(raw)==m['body_sha256'],'complete member body')
        overlaps=[f for f in frames if f['start']<b and a<f['end']]
        require(len(overlaps)==1 and (overlaps[0]['start'],overlaps[0]['end'])==(a,b),'unique complete FDE')
        frame=overlaps[0];records={}
        for kind in ('fde','cie'):
            va=frame[kind];size=int.from_bytes(im.va_bytes(va,4)[0],'little')+4
            value,loc=im.va_bytes(va,size);records[kind]={'va':va,'file_offset':loc['file_offset'],'hex':value.hex()}
        name='member'+str(m['index']);gnu=listing(PACKET/(name+'.gnu.txt'),im,a,b);llvm=listing(PACKET/(name+'.llvm.txt'),im,a,b)
        decoded=list(decoder.disasm(raw,a));require(gnu==llvm==[(i.address,bytes(i.bytes)) for i in decoded],'three decoder byte/boundary agreement')
        require(len(decoded)==8 and [i.address for i in decoded if i.mnemonic=='ret']==[b-1],'complete eight-instruction return')
        require(not any(i.mnemonic=='call' or i.mnemonic.startswith('j') for i in decoded),'no outgoing control dependency')
        require(im.va_bytes(b,15)[0]==b'\xcc'*15,'member padding')
        constant_va=a+12+struct.unpack_from('<i',raw,8)[0]
        require(constant_va==m['constant_va'],'actual RIP constant')
        constant,cm=im.va_bytes(constant_va,16);require(constant.hex()==m['constant_hex'],'complete comparand bytes')
        require(cm['section']['name']=='.rodata' and not cm['section']['flags']&1,'readonly constant section')
        name_record=[]
        for n in m['naming']:
            require(data[n['file_offset']:n['file_offset']+24].hex()==n['hex'],'complete RELATIVE record')
            slot,sm=im.va_bytes(n['destination'],8);require(slot.hex()==n['slot_hex']=='00'*8,'pre-relocation slot bytes')
            require(sm['section']['name']=='.data.rel.ro','slot section')
            require(n['info']==8 and n['addend']==a,'RELATIVE symbol zero entry addend')
            name_record.append({**n,'mapping':sm})
        members.append({**m,'hex':raw.hex(),'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(decoded),'constant_mapping':cm,'naming':name_record})
        protected += [(a,b+15),(constant_va,constant_va+16)]
    entries={m['begin'] for m in MEMBERS};seen=[];count=0
    for s in im.sections:
        require(s['type']!=9,'unsupported REL table')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for o in range(s['offset'],s['offset']+s['size'],24):
            dst,info,add=struct.unpack_from('<QQq',data,o);count+=1
            require((info&0xffffffff) in (1,6,7,8,18),'known relocation width')
            require(not any(dst<b and a<dst+8 for a,b in protected),'protected code/constant relocation')
            if add in entries:seen.append((o,dst,info,add))
    expected=sorted((n['file_offset'],n['destination'],n['info'],n['addend']) for m in MEMBERS for n in m['naming'])
    require(sorted(seen)==expected,'all naming relocations')
    tx=next(s for s in im.sections if s['name']=='.text');code=im.va_bytes(tx['address'],tx['size'],executable=True)[0];census={}
    for op,label in [(b'\xe8','E8'),(b'\xe9','E9')]:
        hits=[];pos=0
        while (pos:=code.find(op,pos))>=0:
            if pos+5<=len(code):
                dest=tx['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
                if dest in entries:hits.append((tx['address']+pos,dest))
            pos+=1
        require(not hits,'unexpected '+label+' candidate');census[label]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'rela_records_checked':count,'direct_candidates':census,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity')
    record=inspect(data);locations={}
    for m in record['members']:
        tag=str(m['index']);locations.update({tag+' body':m['file_offset']+16,tag+' constant':m['constant_mapping']['file_offset'],tag+' FDE':m['records']['fde']['file_offset']+12,tag+' padding':m['file_offset']+33,tag+' slot':m['naming'][0]['mapping']['file_offset'],tag+' relocation':m['naming'][0]['file_offset']+8})
    locations['CIE encoding']=record['members'][0]['records']['cie']['file_offset']+15
    rejected={}
    for label,offset in locations.items():
        changed=bytearray(data);changed[offset]^=1
        try:
            other=inspect(bytes(changed));require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural record drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected;text=json.dumps(record,indent=2,sort_keys=True)+'\n'
    if args.write:
        with (PACKET/'static.json').open('x') as f:f.write(text)
    else:require((PACKET/'static.json').read_text()==text,'retained static drift')
    print(json.dumps({'members':len(record['members']),'instructions':sum(m['instructions'] for m in record['members']),'controls':len(rejected),'naming_records':sum(len(m['naming']) for m in record['members'])}))
if __name__=='__main__':main()
