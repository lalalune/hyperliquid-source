"""Post-source independent review; not the pre-Rust oracle."""
import gzip,hashlib,json,re,struct
from pathlib import Path
root=Path(__file__).resolve().parents[3]
p=root/'research/work-items/RE-004-chunk-equality-family-rust-94'
source=(root/'src/node94-chunk-equality-family/lib.rs').read_bytes()
image=(root/'artifacts/node/94/hl-node').read_bytes()
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,message):
    if not ok:raise ValueError(message)
need(sha(image)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','image identity')
need(image[:6]==b'\x7fELF\x02\x01','ELF64 little endian')
phoff,shoff=struct.unpack_from('<QQ',image,32)
phsize,phcount,shsize,shcount=struct.unpack_from('<HHHH',image,54)
need(phsize==56 and shsize==64,'ELF entry sizes')
ph=[struct.unpack_from('<IIQQQQQQ',image,phoff+i*phsize) for i in range(phcount)]
sh=[struct.unpack_from('<IIQQQQIIQQ',image,shoff+i*shsize) for i in range(shcount)]
def vbytes(va,length):
    loc=[x[2]+va-x[3] for x in ph if x[0]==1 and x[3]<=va and va+length<=x[3]+x[5]]
    need(len(loc)==1,'unique file backed VA')
    return image[loc[0]:loc[0]+length]
static=json.loads((p/'static.json').read_text())
source_constants=re.search(rb'const COMPARANDS:.*?= \[(.*?)\n\];',source,re.S).group(1)
flat=bytes(int(x,16) for x in re.findall(rb'0x([0-9a-f]{2})',source_constants))
need(len(flat)==192,'source constant count')
constants=[];slot_records=[]
for i,m in enumerate(static['members']):
    a=0x14b52b0+48*i
    need(m['begin']==a and m['end']==a+33,'family intervals')
    body=vbytes(a,33)
    need(body[:8]==bytes.fromhex('f30f6f06660f7405'),'body load/compare prefix')
    need(body[12:]==bytes.fromhex('660fd7c8488d573831c081f9ffff0000480f44c2c3'),'full register instruction relation')
    cva=a+12+struct.unpack_from('<i',body,8)[0]
    c=vbytes(cva,16);constants.append(int.from_bytes(c,'little'))
    need(c==flat[16*i:16*i+16]==bytes.fromhex(m['constant_hex']),'actual/source/frozen constant agreement')
    need(cva==m['constant_va'],'constant VA')
    need(vbytes(a+33,15)==b'\xcc'*15,'padding')
    need(len(m['naming'])==1,'one declared record')
    n=m['naming'][0]
    need(vbytes(n['destination'],8)==bytes(8),'unrelocated slot zero')
    slot_records.append({'index':i,'entry':a,'slot':n['destination'],'declared_file_offset':n['file_offset'],'writers':[]})
count=0;types={}
for s in sh:
    need(s[1]!=9,'no unhandled REL section')
    if s[1]!=4:continue
    need(s[9]==24 and s[5]%24==0,'RELA shape')
    for off in range(s[4],s[4]+s[5],24):
        dst,info,add=struct.unpack_from('<QQq',image,off)
        typ=info&0xffffffff
        need(typ in (1,6,7,8,18),'observed 64-bit relocation type')
        types[typ]=types.get(typ,0)+1;count+=1
        for r in slot_records:
            if dst<r['slot']+8 and r['slot']<dst+8:
                r['writers'].append({'file_offset':off,'destination':dst,'info':info,'addend':add,'record_hex':image[off:off+24].hex()})
for r in slot_records:
    need(len(r['writers'])==1,'exactly one overlapping writer')
    w=r['writers'][0]
    need((w['file_offset'],w['destination'],w['info'],w['addend'])==(r['declared_file_offset'],r['slot'],8,r['entry']),'unique writer exact RELATIVE symbol0 identity')
    need(w['record_hex']==static['members'][r['index']]['naming'][0]['hex'],'writer exact original record')
inputs=gzip.decompress((p/'inputs.bin.gz').read_bytes());expected=gzip.decompress((p/'expected.bin.gz').read_bytes())
need(len(inputs)%32==0 and len(expected)==len(inputs)//32*24,'fixture framing')
recomputed=bytearray();mismatches=[];masks=set();matches=wraps=zero_matches=0
for row in range(len(inputs)//32):
    i,address=struct.unpack_from('<QQ',inputs,32*row)
    x=int.from_bytes(inputs[32*row+16:32*row+32],'little')
    difference=x^constants[i]
    unequal_positions=[j for j in range(16) if (difference//(256**j))%256]
    mask=65535-sum(2**j for j in unequal_positions)
    dest=(address+56)&((1<<64)-1)
    result=(dest if difference==0 else 0,dest,mask)
    packed=struct.pack('<QQQ',*result);recomputed+=packed
    if packed!=expected[24*row:24*row+24]:mismatches.append(row)
    if i==0:masks.add(mask)
    matches+=difference==0;wraps+=address+56>=2**64;zero_matches+=difference==0 and dest==0
need(not mismatches,'independent fixture mismatch')
need(len(masks)==65536,'all masks member0')
frozen=json.loads((p/'frozen.json').read_text())
need(sha(inputs)==frozen['inputs_sha256'] and sha(expected)==frozen['expected_sha256'],'frozen stream binding')
need(sha((p/'oracle.py').read_bytes())==frozen['oracle_sha256_at_freeze'],'frozen oracle binding')
need(sha((p/'static.json').read_bytes())==frozen['static_sha256_at_freeze'],'frozen static binding')
record={'source_sha256':sha(source),'target_sha256':sha(image),'independent_method':'manual ELF64 PT_LOAD and SHT_RELA parsing; raw exact instruction template; 128-bit XOR positional quotient nonzero bits complemented from 65535; whole-word equality and masked address addition','members':12,'body_bytes':396,'constant_bytes':192,'all_slot_writers':slot_records,'rela_count':count,'rela_types':types,'cases':len(inputs)//32,'mismatches':len(mismatches),'recomputed_expected_sha256':sha(recomputed),'complete_member0_masks':len(masks),'full_matches':matches,'wrapped_destinations':wraps,'full_match_zero_returns':zero_matches,'captured_code_executed':False,'root_files_edited':False}
print(json.dumps(record,indent=2))
