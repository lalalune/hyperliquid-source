#!/usr/bin/env python3
"""RE-001/storage: node94 DB label table, home key and global-byte construction gate."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
CONSUMERS={
    0x358cea0:'0f56c7054473fe5390c48eaddc0e812748bd8f802279e29146c237764d664a89',
    0x358d2e0:'503ee5e4e51421fa41dafe02181aa4c038add7c1fc99be62d377a912cecd4d09',
    0x358d720:'e981c8dd199139315cc7e47601567c2e09315ed087074936b7ca469e391e4255',
    0x459c6b0:'e988e7128264ac79102c359a6ebb1d0c0233b5285195b770b3662c9f4685b2e8',
    0x459caf0:'6746d5fe9acf95df1cdb81b584a89d2f70a00fd95afd6f7014ee7b94a76f77f4',
    0x459cf30:'c03e31508a750c3e8c961ed9364bedd9bbeb4246c4f8bc28a2fb0db5bef66caf',
}
TABLES={0x56f1920:0x594ff2,0x572d7e0:0x6f7394}
CALLS=[(0x3269c5c,0x358cea0,24),(0x3269e77,0x358d720,25),(0x326a086,0x358d2e0,26),
       (0x47f2670,0x459caf0,23),(0x47f2682,0x459c6b0,21),(0x47f2697,0x459cf30,22)]


def require(value,message):
    if not value:raise ValueError(message)


def construction_arm(code,global_byte,mask):
    """The observed byte operations; does not assert the branch's Rust type."""
    require(0<=code<28 and 0<=global_byte<256,'Outside observed table/byte domain')
    delta=(code-21)&255
    shifted=(global_byte-10)&255
    if shifted>=22:return delta<=2
    al=(mask>>(shifted&31))&255
    cl=int(delta>=3)
    return ((al|cl)&1)==0


def home_key(code,primary,auxiliary):
    require(0<=code<28,'Outside observed table span')
    return 0 if (primary>>code)&1 else (1 if (auxiliary>>code)&1 else 2)


def observe(data):
    secs=sections(data)

    def read(va,size):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(matches)==1,'Expected one file-backed mapping')
        off=matches[0]['offset']+va-matches[0]['address']
        require(off+size<=len(data),'Truncated file mapping')
        return data[off:off+size]

    def code(va,prefix,size):
        raw=read(va,size);require(raw.startswith(bytes.fromhex(prefix)),f'Instruction changed at {va:#x}')
        return raw

    _,frames=eh_frame_records(data,secs)
    relsec=next(s for s in secs if s['name']=='.rela.dyn')
    relocs={}
    for slot,info,addend in struct.iter_unpack('<QQq',read(relsec['address'],relsec['size'])):
        if info==8:
            require(slot not in relocs,'Duplicate RELATIVE relocation')
            relocs[slot]=addend
    tables=[]
    for table,pool in TABLES.items():
        entries=[]
        for index in range(28):
            slot=table+8*index;pointer=relocs.get(slot)
            require(pointer==pool+2*index,'DB label pointer/stride changed')
            label=read(pointer,2).decode('ascii')
            entries.append({'index':index,'slot_va':hex(slot),'addend_va':hex(pointer),'label':label})
        tables.append({'table_va':hex(table),'pool_va':hex(pool),'entries':entries})
    labels=[[e['label'] for e in t['entries']] for t in tables]
    require(labels[0]==labels[1] and labels[0][4]=='Ps' and labels[0][27]=='ps','DB label bytes changed')
    require(relocs.get(0x576e928)==0x577b288,'Global-state slot binding changed')
    consumers=[]
    masks=None
    for start,expected_hash in CONSUMERS.items():
        fs=[f for f in frames if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==start+1081,'DB wrapper FDE changed')
        require(read(start+0x11,3)==bytes.fromhex('4189f6') and
                read(start+0x19,4)==bytes.fromhex('450fb6e6'),'Input code-byte source changed')
        primary=struct.unpack_from('<I',code(start+0x25,'b8',5),1)[0]
        auxiliary=struct.unpack_from('<I',code(start+0x53,'b8',5),1)[0]
        state_mask=struct.unpack_from('<I',code(start+0x1e9,'b8',5),1)[0]
        require((primary,auxiliary,state_mask)==(0x081ffeff,0x00e00100,0x0020ff01),'DB routing masks changed')
        require(read(start+0x2a,6)==bytes.fromhex('440fa3e07323') and
                read(start+0x58,4)==bytes.fromhex('440fa3e0'),'Home-key bit test changed')
        require(read(start+0x1d,2)==bytes.fromhex('31ed') and
                read(start+0x62,3)==bytes.fromhex('40b501') and
                read(start+0x322,3)==bytes.fromhex('40b502'),'Home-key byte values changed')
        raw=code(start+0xe0,'488d05',7);table=start+0xe7+struct.unpack_from('<i',raw,3)[0]
        require(table in TABLES,'Label table LEA changed')
        require(read(start+0xe7,9)==bytes.fromhex('4e8b2ce0bf02000000'),'Label indexed load/allocation length changed')
        require(read(start+0x102,10)==bytes.fromhex('410fb745006641890424'),'Two-byte label copy changed')
        global_load=code(start+0x1c9,'4c8b35',7)
        global_slot=start+0x1d0+struct.unpack_from('<i',global_load,3)[0]
        require(global_slot==0x576e928,'Global-state load target changed')
        require(read(start+0x3a,4)==bytes.fromhex('418d46eb'),'Input code subtraction changed')
        gate=read(start+0x1dc,35)
        expected_gate=bytes.fromhex('410fb64e4880c1f680f9167325b801ff2000d3e8807c240c030f93c108c1f6c1017416')
        require(gate==expected_gate,'Global-byte/code construction gate changed')
        require(read(start+0x20e,7)==bytes.fromhex('807c240c0277ea'),'Outside-window construction gate changed')
        require(read(start+0x1ff,10)==bytes.fromhex('49bc0000000000000080'),'Bypass sentinel changed')
        loc_lea=code(start+0x3b5,'488d15',7)
        loc=start+0x3bc+struct.unpack_from('<i',loc_lea,3)[0]
        require(loc in relocs,'DB source Location relocation missing')
        length,line,column=struct.unpack('<QII',read(loc+8,16))
        path=read(relocs[loc],length).decode('utf8')
        require(path=='/home/ubuntu/hl/code_Mainnet/db/src/db_hub.rs' and (line,column)==(60,18),
                'DB source Location changed')
        require(hashlib.sha256(read(start,1081)).hexdigest()==expected_hash,'Enclosing DB wrapper body changed')
        consumers.append({'start_va':hex(start),'end_va_exclusive':hex(start+1081),'bytes':1081,
                          'body_sha256':expected_hash,'fde_va':hex(fs[0]['fde']),'cie_va':hex(fs[0]['cie']),
                          'table_va':hex(table),'source_location_va':hex(loc),'source_line':line,'source_column':column})
        masks=(primary,auxiliary,state_mask)
    textsec=next(s for s in secs if s['name']=='.text')
    text=read(textsec['address'],textsec['size'])
    needle=bytes.fromhex('b8fffe1f08440fa3e0')
    hits=[textsec['address']+m.start() for m in re.finditer(re.escape(needle),text)]
    require(hits==[s+0x25 for s in CONSUMERS],'Exact primary-mask shape census changed')
    calls=[]
    for site,target,value in CALLS:
        raw=code(site-8,'be',5);actual=struct.unpack_from('<I',raw,1)[0]
        require(actual==value,'Caller code immediate changed')
        require(read(site-3,3) in (bytes.fromhex('4c89ea'),bytes.fromhex('4c89f2')),'Caller RDX setup changed')
        raw=code(site,'e8',5)
        require(site+5+struct.unpack_from('<i',raw,1)[0]==target,'DB wrapper caller retargeted')
        calls.append({'code_load_va':hex(site-8),'call_va':hex(site),'target_va':hex(target),'code':value,
                      'window_hex':read(site-8,13).hex()})
    primary,auxiliary,state_mask=masks
    excluded=[10+i for i in range(22) if (state_mask>>i)&1]
    matrix=[(c,g,construction_arm(c,g,state_mask)) for c in range(28) for g in range(256)]
    mismatches=sum(result!=(c in (21,22,23) and g not in excluded) for c,g,result in matrix)
    require(mismatches==0,'Instruction predicate differs from independent set form')
    rows=[{'index':c,'label':labels[0][c],'home_key':home_key(c,primary,auxiliary),
           'construction_globals':sum(construction_arm(c,g,state_mask) for g in range(256))} for c in range(28)]
    return {'target_sha256':SHA256,'observed_label_span':28,'tables':tables,'consumers':consumers,
            'mask_values':{'primary':hex(primary),'auxiliary':hex(auxiliary),'global_state':hex(state_mask)},
            'global_state_binding':{'slot_va':'0x576e928','addend_va':'0x577b288','byte_offset':'0x48'},
            'construction_excluded_global_bytes':excluded,'code_rows':rows,'direct_call_windows':calls,
            'gate_comparison':{'pairs':len(matrix),'construction_pairs':sum(r for _,_,r in matrix),'mismatches':mismatches},
            'captured_binaries_executed':False,
            'limits':'Observed 28-entry table span and raw branch predicates only; no complete enum validity, '
                     'index-27 reachability, global-byte meaning, optional-state Rust type, BTreeMap/filesystem '
                     'contract, helper closure, runtime equivalence or progress gate.'}


def build(data):
    require(hashlib.sha256(data).hexdigest()==SHA256,'Wrong node94 SHA-256')
    return observe(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    p.add_argument('--out',type=Path,default=ROOT/'work/db-code-routing-94.json')
    args=p.parse_args();record=build(args.binary.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(record,indent=2)+'\n',encoding='utf8',newline='\n')
    print(json.dumps(record['gate_comparison']))


if __name__=='__main__':main()
