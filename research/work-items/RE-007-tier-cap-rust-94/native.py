"""Authenticate saved full-FDE evidence, selected data and byte-identity controls.

This parser does not execute or interpret instructions. Semantic proof is the
separately reviewed native/NATIVE.md. Coordinate controls are identity controls.
"""
from pathlib import Path
import hashlib,json,re,struct,sys
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tools'))
from info_request_path import Elf
from elf_index import sections
from fde_extents import eh_frame_records

def digest(raw):return hashlib.sha256(raw).hexdigest()
def need(ok,msg):
    if not ok:raise ValueError(msg)
def rows(raw):
    result=[]
    for line in raw.decode().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
        if m:result.append((int(m[1],16),bytes.fromhex(m[2])))
    return result

def authenticate(raw):
    frozen=json.loads((HERE/'native/NATIVE-FREEZE.json').read_text())
    need(len(raw)==frozen['target_bytes'] and digest(raw)==frozen['target_sha256'],'target identity')
    elf=Elf(raw);_,fs=eh_frame_records(raw,sections(raw));fs={f['start']:f for f in fs}
    for record in frozen['functions']:
        start,end=int(record['start'],16),int(record['end'],16);f=fs[start]
        need(f['end']==end and f['fde']==int(record['fde'],16) and f['cie']==int(record['cie'],16) and f['lsda']==(None if record['lsda'] is None else int(record['lsda'],16)),'complete FDE boundary/LSDA')
        need(digest(elf.read(start,end-start))==record['body_sha256'],'body identity')
        for kind in ['fde','cie']:
            need(elf.read(int(record[kind],16),len(bytes.fromhex(record[kind+'_hex']))).hex()==record[kind+'_hex'],kind+' record')
        need(elf.read(int(record['header_pair_va'],16),8).hex()==record['header_pair_hex'],'header pair')
        decoded=[]
        for kind in ['gnu','llvm']:
            export=(HERE/'native'/f'{record["start"]}.{kind}.txt').read_bytes()
            # Text hash binds the full retained export; rows independently bind
            # the partition to native bytes and the FDE end.
            need(digest(export)==record[kind+'_sha256'],'saved '+kind+' export')
            parsed=rows(export);need(len(parsed)==record['instructions'],'instruction partition count')
            at=start
            for va,b in parsed:
                need(va==at and elf.read(va,len(b))==b,'native export bytes/gap');at+=len(b)
            need(at==end,'native export final byte');decoded.append(parsed)
        need(decoded[0]==decoded[1],'decoder partitions')
    for t in frozen['jump_tables']:
        va=int(t['va'],16);b=elf.read(va,16);need(b.hex()==t['hex'],'jump-table bytes')
        need([hex(va+struct.unpack_from('<i',b,i*4)[0]) for i in range(4)]==t['targets'],'jump-table destinations')
    for c in frozen['coordinate_controls']:need(elf.read(int(c['va'],16),len(bytes.fromhex(c['hex']))).hex()==c['hex'],'coordinate '+c['name'])
    rva,_,n=elf.section('.rela.dyn');rel=elf.read(rva,n)
    for expected in frozen['relocations']:
        matches=[]
        for at in range(0,n,24):
            slot,info,addend=struct.unpack_from('<QQq',rel,at)
            if slot==int(expected['slot'],16):matches.append((info,addend,rel[at:at+24].hex()))
        need(matches==[(8,int(expected['target'],16),expected['hex'])],'unique cap relocation')
    call=elf.read(0x3709ef9,6);need(call.hex()=='ff1599ba0602','actual caller slot instruction')
    need(0x3709eff+struct.unpack_from('<i',call,2)[0]==0x5775998,'actual caller RIP slot')
    return {'functions':len(frozen['functions']),'context_instructions':sum(f['instructions'] for f in frozen['functions']),'new_cap_plus_selected_helper_instructions':421,'identity_windows':len(frozen['coordinate_controls']),'caller_site':'0x3709ef9','captured_execution':False}

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path,default=ROOT/'artifacts/node/94/hl-node');a=p.parse_args()
    print(json.dumps(authenticate(a.target.read_bytes()),sort_keys=True))
