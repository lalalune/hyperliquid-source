"""Authenticate accepted native clone/decrease evidence; no evaluator."""
from pathlib import Path
import hashlib,json,re,struct,sys
HERE=Path(__file__).resolve().parent;PRE=HERE/'pre-source';ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from info_request_path import Elf
from elf_index import sections
from fde_extents import eh_frame_records
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def rows(raw):
    result=[]
    for line in raw.decode().splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
        if m:result.append((int(m[1],16),bytes.fromhex(m[2])))
    return result
def authenticate(raw):
    freeze=json.loads((PRE/'NATIVE-FREEZE.json').read_text());need(len(raw)==freeze['target_bytes'] and sha(raw)==freeze['target_sha256'],'whole target identity');elf=Elf(raw);_,fdes=eh_frame_records(raw,sections(raw));fdes={f['start']:f for f in fdes};total=0;instructions=0
    for record in freeze['functions']:
        start=int(record['start'],16);end=int(record['end'],16);f=fdes[start]
        for k in ['start','end','fde','cie','lsda']:need((None if f[k] is None else hex(f[k]))==record[k],'complete FDE '+k)
        need(end-start==record['bytes'] and sha(elf.read(start,end-start))==record['body_sha256'],'body bytes')
        for k in ['fde','cie']:
            data=bytes.fromhex(record[k+'_hex']);need(elf.read(int(record[k],16),len(data))==data,'raw unwind '+k)
        va=int(record['header_pair_va'],16);b=bytes.fromhex(record['header_pair_hex']);need(elf.read(va,len(b))==b,'header pair bytes');hva,_,_=elf.section('.eh_frame_hdr');a,z=struct.unpack('<ii',b);need(hva+a==start and hva+z==f['fde'],'header coordinate binding')
        parsed=[]
        for kind in ['gnu','llvm']:
            export=(PRE/record[kind+'_file']).read_bytes();need(sha(export)==record[kind+'_sha256'],'export identity');seq=rows(export);at=start
            for address,b in seq:need(address==at and elf.read(address,len(b))==b,'complete byte partition');at+=len(b)
            need(at==end and len(seq)==record['instructions'],'partition denominator');parsed.append(seq)
        need(parsed[0]==parsed[1],'dual decoder partition');total+=record['bytes'];instructions+=record['instructions']
    for c in freeze['coordinate_controls']:
        b=bytes.fromhex(c['hex']);need(elf.read(int(c['va'],16),len(b))==b,'coordinate identity '+c['name'])
    rva,_,size=elf.section('.rela.dyn');rb=elf.read(rva,size)
    for r in freeze['relocations']:
        slot=int(r['slot'],16);found=[rb[i:i+24] for i in range(0,size,24) if struct.unpack_from('<Q',rb,i)[0]==slot];need(len(found)==1 and found[0].hex()==r['hex'],'unique RELA bytes');_,info,addend=struct.unpack('<QQq',found[0]);need(info==8 and addend==int(r['target'],16),'RELA target')
    t=freeze['mode_jump_table'];va=int(t['va'],16);b=bytes.fromhex(t['hex']);need(elf.read(va,len(b))==b,'mode table bytes');need([hex(va+struct.unpack_from('<i',b,4*i)[0]) for i in range(5)]==t['targets'],'mode targets')
    for va,target in [(0x370a09e,0x33ed7f0),(0x370a0bb,0x33ed610),(0x370a28a,0x3761d10),(0x370a300,0x3761d10)]:
        b=elf.read(va,5);need(b[0]==0xe8 and va+5+struct.unpack_from('<i',b,1)[0]==target,'caller direct call')
    b=elf.read(0x370a28f,5);need(b[0]==0xe9 and 0x370a294+struct.unpack_from('<i',b,1)[0]==0x3709cfa,'EnterCommit cleanup branch')
    return {'functions':len(freeze['functions']),'body_bytes':total,'dual_decoder_instructions':instructions,'coordinate_byte_identity_controls':len(freeze['coordinate_controls']),'relocations':len(freeze['relocations']),'mode_targets':5,'caller_calls':4,'captured_execution':False,'runtime_admission_claimed':False,'EnterCommit_is_not_success':True}
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path,default=ROOT/'artifacts/node/94/hl-node');a=p.parse_args();print(json.dumps(authenticate(a.target.read_bytes()),sort_keys=True))
