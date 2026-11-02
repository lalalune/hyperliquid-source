"""Bind three complete indexed-OR functions, full read windows and relocation slots."""
import argparse,json,re,struct,sys
from oracle import ROOT, PACKET, require, sha
sys.path.insert(0,str(ROOT/'tools'))
from libcore_fmt_correspondence import Elf
from fde_extents import eh_frame_records
import capstone
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MEMBERS=[{'index': 0, 'begin': 22423008, 'end': 22423029, 'body_sha256': 'c48b9983005a58f1c858edc6a302c0222147d2d005a697d636fb111b70eefa37', 'body_hex': '400fb6c6488d0d01f1cefe8b04810987a0010000c3', 'table_va': 2430700, 'table_hex': '01000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400006c4a3101fe493101274a3101334a3101154a3101454a3101514a3101394a3101634a3101214a31015d4a31010f4a31011b4a31014b4a3101094a31012d4a3101034a31013f4a3101574a3101694a310101000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400007c7431010e74310137743101437431012574310155743101617431014974310173743101317431016d7431011f7431012b7431015b743101197431013d743101137431014f7431016774310179743101466174616c20696e7465726e616c206572726f722e20506c6561736520636f6e73696465722066696c696e67206120627567207265706f72742061742068747470733a2f2f6769746875622e636f6d2f636c61702d72732f636c61702f6973737565732e2e2e000001000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400006120446973706c617920696d706c656d656e746174696f6e2072657475726e656420616e206572726f7220756e65787065637465646c796572726f723a2d2d68656c702c2061736572656f6e65206f72206d6f7265206f6620746865206f746865722073706563696669656420617267756d656e747355534147453a4572726f726465736372697074696f6e282920697320646570726563617465643b2075736520446973706c617900ff0009000f00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00010203040506070809ffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4d6310117d8310147d7310165d7310129d7310135d8310153d83101d9d73101417263496e76616c6964617263417263546f6f426967426173653132384469676974457870656374656461637475616c456d7074794c656e', 'table_sha256': 'e7c45148a1ade79bd697fd8396f24eee58055d644dccda04c363f0049658a06f', 'table_section': '.rodata', 'field_offset': 416, 'naming': [{'file_offset': 109616, 'destination': 90646120, 'info': 8, 'addend': 22423008, 'hex': '68266705000000000800000000000000e025560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 114176, 'destination': 90648688, 'info': 8, 'addend': 22423008, 'hex': '70306705000000000800000000000000e025560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 118232, 'destination': 90650672, 'info': 8, 'addend': 22423008, 'hex': '30386705000000000800000000000000e025560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 119024, 'destination': 90650968, 'info': 8, 'addend': 22423008, 'hex': '58396705000000000800000000000000e025560100000000', 'slot_hex': '0000000000000000'}]}, {'index': 1, 'begin': 22438144, 'end': 22438165, 'body_sha256': '029a3aea51345649a09b264fd76ce3484d9bbfbf2d2d42982ab1ae87e83b4252', 'body_hex': '400fb6c6488d0d81b6cefe8b04810987a8000000c3', 'table_va': 2430860, 'table_hex': '01000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400007c7431010e74310137743101437431012574310155743101617431014974310173743101317431016d7431011f7431012b7431015b743101197431013d743101137431014f7431016774310179743101466174616c20696e7465726e616c206572726f722e20506c6561736520636f6e73696465722066696c696e67206120627567207265706f72742061742068747470733a2f2f6769746875622e636f6d2f636c61702d72732f636c61702f6973737565732e2e2e000001000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400006120446973706c617920696d706c656d656e746174696f6e2072657475726e656420616e206572726f7220756e65787065637465646c796572726f723a2d2d68656c702c2061736572656f6e65206f72206d6f7265206f6620746865206f746865722073706563696669656420617267756d656e747355534147453a4572726f726465736372697074696f6e282920697320646570726563617465643b2075736520446973706c617900ff0009000f00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00010203040506070809ffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4d6310117d8310147d7310165d7310129d7310135d8310153d83101d9d73101417263496e76616c6964617263417263546f6f426967426173653132384469676974457870656374656461637475616c456d7074794c656e6774684e6f74456e6f75676841726373547261696c696e67446f742e4f4944206d616c666f726d656400000042f7310193f7310179f731017df7310146f7310147fb31019afb31017efb310183fb31014cfb310163fe3101b4fe31019afe31019efe310167fe31019d0c32010c0c3201a10c32010c0c3201fb0e3201e10e3201ff0e3201e10e3201491c32016e1c3201721c3201491c32010089320119893201', 'table_sha256': 'cfa657b8134a5a7ff130e28c55e87a2a3d9242175b8e8d30c9b73c3a9bfb9911', 'table_section': '.rodata', 'field_offset': 168, 'naming': [{'file_offset': 108920, 'destination': 90645872, 'info': 8, 'addend': 22438144, 'hex': '702567050000000008000000000000000061560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 114872, 'destination': 90648936, 'info': 8, 'addend': 22438144, 'hex': '683167050000000008000000000000000061560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 117416, 'destination': 90650368, 'info': 8, 'addend': 22438144, 'hex': '003767050000000008000000000000000061560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 120416, 'destination': 90651464, 'info': 8, 'addend': 22438144, 'hex': '483b67050000000008000000000000000061560100000000', 'slot_hex': '0000000000000000'}]}, {'index': 2, 'begin': 22449072, 'end': 22449093, 'body_sha256': '75b65a4de4daffb7adfd977bcc8e0a7e471505caf137c7890fe3d2601a9717a9', 'body_hex': '400fb6c6488d0dd98ccefe8b04810987a0010000c3', 'table_va': 2431124, 'table_hex': '01000000020000000400000008000000100000002000000040000000800000000002000000080000001000000020000000400000008000000000010000000200000004000000080000010000000400006120446973706c617920696d706c656d656e746174696f6e2072657475726e656420616e206572726f7220756e65787065637465646c796572726f723a2d2d68656c702c2061736572656f6e65206f72206d6f7265206f6620746865206f746865722073706563696669656420617267756d656e747355534147453a4572726f726465736372697074696f6e282920697320646570726563617465643b2075736520446973706c617900ff0009000f00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00010203040506070809ffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffff0a0b0c0d0e0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4d6310117d8310147d7310165d7310129d7310135d8310153d83101d9d73101417263496e76616c6964617263417263546f6f426967426173653132384469676974457870656374656461637475616c456d7074794c656e6774684e6f74456e6f75676841726373547261696c696e67446f742e4f4944206d616c666f726d656400000042f7310193f7310179f731017df7310146f7310147fb31019afb31017efb310183fb31014cfb310163fe3101b4fe31019afe31019efe310167fe31019d0c32010c0c3201a10c32010c0c3201fb0e3201e10e3201ff0e3201e10e3201491c32016e1c3201721c3201491c3201008932011989320119893201198932011989320119893201198932011989320119893201048a3201de8932011989320119893201fa89320119893201198932011989320119893201198932011989320119893201198932011989320119893201198932011989320119893201198932011989320119893201198932011989320119893201198932010e8a320119893201198932011989320119893201e8893201eca1320112a2320117a23201eca13201aa010a0104010517011f0100040c0e050701010156011d1201020204010106010103010101140153018b08a6012602010629270e0101010201020101081b04041d0b053801070e660108040804030a03020110300d6518210902040105180213', 'table_sha256': 'a87399bcdef06d7cdb5a467bf7c0ded616c5c1e78b7841cd867feb2bd9b685e3', 'table_section': '.rodata', 'field_offset': 416, 'naming': [{'file_offset': 110312, 'destination': 90646368, 'info': 8, 'addend': 22449072, 'hex': '60276705000000000800000000000000b08b560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 113480, 'destination': 90648440, 'info': 8, 'addend': 22449072, 'hex': '782f6705000000000800000000000000b08b560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 116600, 'destination': 90650064, 'info': 8, 'addend': 22449072, 'hex': 'd0356705000000000800000000000000b08b560100000000', 'slot_hex': '0000000000000000'}, {'file_offset': 119720, 'destination': 90651216, 'info': 8, 'addend': 22449072, 'hex': '503a6705000000000800000000000000b08b560100000000', 'slot_hex': '0000000000000000'}]}]

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
        require(len(decoded)==5 and [i.address for i in decoded if i.mnemonic=='ret']==[b-1],'complete five-instruction return')
        require(not any(i.mnemonic=='call' or i.mnemonic.startswith('j') for i in decoded),'no outgoing control dependency')
        require(im.va_bytes(b,11)[0]==b'\xcc'*11,'member padding')
        table_va=a+11+struct.unpack_from('<i',raw,7)[0]
        require(table_va==m['table_va'],'actual RIP constant')
        constant,cm=im.va_bytes(table_va,1024);require(constant.hex()==m['table_hex'],'complete reachable table window')
        require(cm['section']['name']=='.rodata' and not cm['section']['flags']&1,'readonly constant section')
        name_record=[]
        for n in m['naming']:
            require(data[n['file_offset']:n['file_offset']+24].hex()==n['hex'],'complete RELATIVE record')
            slot,sm=im.va_bytes(n['destination'],8);require(slot.hex()==n['slot_hex']=='00'*8,'pre-relocation slot bytes')
            require(sm['section']['name']=='.data.rel.ro','slot section')
            require(n['info']==8 and n['addend']==a,'RELATIVE symbol zero entry addend')
            name_record.append({**n,'mapping':sm})
        members.append({**m,'hex':raw.hex(),'file_offset':where['file_offset'],'frame':frame,'records':records,'instructions':len(decoded),'table_mapping':cm,'naming':name_record})
        protected += [(a,b+11),(table_va,table_va+1024)]
        require(struct.unpack_from('<I',raw,16)[0]==m['field_offset'],'actual field displacement')
    entries={m['begin'] for m in MEMBERS};seen=[];count=0
    slots=[n for m in MEMBERS for n in m['naming']];writers={n['destination']:[] for n in slots}
    for s in im.sections:
        require(s['type']!=9,'unsupported REL table')
        if s['type']!=4:continue
        require(s['entsize']==24 and s['size']%24==0,'RELA shape')
        for o in range(s['offset'],s['offset']+s['size'],24):
            dst,info,add=struct.unpack_from('<QQq',data,o);count+=1
            require((info&0xffffffff) in (1,6,7,8,18),'known relocation width')
            require(not any(dst<b and a<dst+8 for a,b in protected),'protected code/constant relocation')
            if add in entries:seen.append((o,dst,info,add))
            for slot in writers:
                if dst<slot+8 and slot<dst+8:writers[slot].append((o,dst,info,add))
    expected=sorted((n['file_offset'],n['destination'],n['info'],n['addend']) for m in MEMBERS for n in m['naming'])
    require(sorted(seen)==expected,'all naming relocations')
    for n in slots:require(writers[n['destination']]==[(n['file_offset'],n['destination'],n['info'],n['addend'])],'unique complete slot writer')
    union,union_mapping=im.va_bytes(0x2516ec,1448)
    for m in MEMBERS:
        offset=m['table_va']-0x2516ec
        require(union[offset:offset+1024].hex()==m['table_hex'],'overlapping read windows')
    tx=next(s for s in im.sections if s['name']=='.text');code=im.va_bytes(tx['address'],tx['size'],executable=True)[0];census={}
    for op,label in [(b'\xe8','E8'),(b'\xe9','E9')]:
        hits=[];pos=0
        while (pos:=code.find(op,pos))>=0:
            if pos+5<=len(code):
                dest=tx['address']+pos+5+struct.unpack_from('<i',code,pos+1)[0]
                if dest in entries:hits.append((tx['address']+pos,dest))
            pos+=1
        require(not hits,'unexpected '+label+' candidate');census[label]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'members':members,'read_union':{'begin':0x2516ec,'end':0x251c94,'bytes':1448,'words':362,'hex':union.hex(),'sha256':sha(union),'mapping':union_mapping},'unique_slot_writers':writers,'rela_records_checked':count,'direct_candidates':census,'complete_xref_census':False,'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(len(data)==91774280 and sha(data)==TARGET,'target identity')
    record=inspect(data);locations={}
    for m in record['members']:
        tag=str(m['index']);locations.update({tag+' field displacement':m['file_offset']+16,tag+' table first':m['table_mapping']['file_offset'],tag+' table last':m['table_mapping']['file_offset']+1023,tag+' FDE':m['records']['fde']['file_offset']+12,tag+' padding':m['file_offset']+21})
        for i,n in enumerate(m['naming']):
            locations[tag+' slot '+str(i)]=n['mapping']['file_offset']
            locations[tag+' relocation '+str(i)]=n['file_offset']+8
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
