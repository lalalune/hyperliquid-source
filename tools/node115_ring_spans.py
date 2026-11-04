#!/usr/bin/env python3
"""Static, digest-bound RE-001 ring-span leaf evidence. Python 3.10+, stdlib only."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import shutil
import struct

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-ring-spans'
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, SIZE, FDE, CIE = 0x4561f70, 102, 0xed2d50, 0xca6ed8
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
# Exact supported encodings and decoded instructions. Branch displacements are
# independently sign-extended and checked against instruction boundaries.
OPS = [
 ('4889f8','mov rax,rdi'),('4c8b4618','mov r8,[rsi+0x18]'),('4d85c0','test r8,r8'),
 ('742b','je 0x4561fa7'),('488b16','mov rdx,[rsi]'),('488b4e10','mov rcx,[rsi+0x10]'),
 ('31ff','xor edi,edi'),('4839d1','cmp rcx,rdx'),('480f43fa','cmovae rdi,rdx'),
 ('4829f9','sub rcx,rdi'),('4989d1','mov r9,rdx'),('4929c9','sub r9,rcx'),
 ('4c89c7','mov rdi,r8'),('4c29cf','sub rdi,r9'),('7710','ja 0x4561fad'),
 ('4901c8','add r8,rcx'),('31ff','xor edi,edi'),('4c89c2','mov rdx,r8'),
 ('eb06','jmp 0x4561fad'),('31c9','xor ecx,ecx'),('31d2','xor edx,edx'),
 ('31ff','xor edi,edi'),('488b7608','mov rsi,[rsi+0x08]'),('486bc938','imul rcx,rcx,56'),
 ('4801f1','add rcx,rsi'),('486bd238','imul rdx,rdx,56'),('4801f2','add rdx,rsi'),
 ('486bff38','imul rdi,rdi,56'),('4801f7','add rdi,rsi'),('488908','mov [rax],rcx'),
 ('48895008','mov [rax+0x08],rdx'),('48897010','mov [rax+0x10],rsi'),
 ('48897818','mov [rax+0x18],rdi'),('c3','ret')]


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode(body):
    """Strictly decode this supported instruction stream; reject any other encoding."""
    need(len(body) == SIZE, 'body extent changed')
    rows, pos, branches = [], 0, []
    for raw, text in OPS:
        expected = bytes.fromhex(raw)
        actual = body[pos:pos+len(expected)]
        need(actual == expected, 'unsupported or changed instruction at %#x' % (START+pos))
        if actual[0] in (0x74, 0x77, 0xeb):
            dest = START+pos+2+struct.unpack('<b', actual[1:2])[0]
            need(dest == int(text.split()[-1], 16), 'branch destination changed')
            branches.append(dest)
        rows.append({'address': START+pos, 'bytes': actual.hex(), 'instruction': text})
        pos += len(expected)
    need(pos == SIZE and all(b in {r['address'] for r in rows} for b in branches),
         'instruction coverage or branch boundary changed')
    return rows


def frame(raw, cie):
    need(len(raw) == 20 and raw[:8] == bytes.fromhex('100000007cbe2200'), 'FDE header changed')
    begin, length = struct.unpack_from('<iI', raw, 8)
    need(FDE+8+begin == START and length == SIZE, 'FDE start/extent changed')
    need(raw[16:] == b'\0'*4, 'FDE augmentation/unwind changed')
    need(cie == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'CIE changed')
    need(FDE+4-struct.unpack_from('<I',raw,4)[0] == CIE, 'CIE pointer changed')
    return {'fde_va': FDE, 'fde_file_offset': FDE, 'fde_hex': raw.hex(), 'cie_va': CIE,
            'cie_file_offset': CIE, 'cie_hex': cie.hex(), 'augmentation': 'zR', 'lsda': None}


def decode_call(raw, site, target):
    need(len(raw) == 5 and raw[0] in (0xe8, 0xe9), 'invalid direct relative transfer')
    actual = site+5+struct.unpack_from('<i',raw,1)[0]
    need(actual == target, 'direct transfer target changed')
    return actual


def model(x, base, index, count):
    """Register-level rule, including all unsigned 64-bit wraparound."""
    mask = (1 << 64)-1
    if not all(isinstance(v,int) and 0 <= v <= mask for v in (x,base,index,count)):
        raise ValueError('expected four u64 words')
    if count == 0:
        first = end = wrap = 0
    else:
        first = (index - (x if index >= x else 0)) & mask
        remaining = (x-first) & mask
        if count > remaining:
            end, wrap = x, (count-remaining) & mask
        else:
            end, wrap = (count+first) & mask, 0
    return tuple((base+56*v) & mask for v in (first,end,0,wrap))


def collect(m):
    need(len(m) == 105896032 and sha(m) == DIGEST, 'node #115 size or SHA-256 mismatch')
    need(m[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H',m,18)[0] == 62,
         'expected ELF64 little-endian x86-64')
    body = m[START-0x1000:START-0x1000+SIZE]
    instructions = decode(body)
    fr = frame(m[FDE:FDE+20],m[CIE:CIE+24])
    # The authenticated header's sorted table must bind the same start and FDE.
    hdr=0xb9ea40
    need(m[hdr:hdr+4] == bytes.fromhex('011b033b'), 'unwind header encoding changed')
    n=struct.unpack_from('<I',m,hdr+8)[0]
    lo,hi=0,n
    while lo<hi:
        mid=(lo+hi)//2
        st=hdr+struct.unpack_from('<i',m,hdr+12+8*mid)[0]
        if st<START: lo=mid+1
        else: hi=mid
    need(lo+1<n, 'unwind index entry missing')
    st, fde=struct.unpack_from('<ii',m,hdr+12+8*lo)
    next_st=hdr+struct.unpack_from('<i',m,hdr+12+8*(lo+1))[0]
    need(hdr+st==START and hdr+fde==FDE and next_st==0x4561fe0, 'unwind index changed')
    padding=m[START-0x1000+SIZE:next_st-0x1000]
    need(padding==b'\xcc'*10, 'padding changed')
    # Search every byte, including bytes inside other instructions and data-in-code.
    candidates=[]
    for opcode in (0xe8,0xe9):
        p=TEXT_START-0x1000; end=TEXT_END-0x1000
        while True:
            p=m.find(bytes((opcode,)),p,end-4)
            if p<0: break
            site=p+0x1000
            if site+5+struct.unpack_from('<i',m,p+1)[0]==START:
                candidates.append({'site':site,'opcode':opcode,'bytes':m[p:p+5].hex()})
            p+=1
    candidates.sort(key=lambda row:row['site'])
    need(len(candidates)==1 and candidates[0]['site']==0x3c15671, 'rel32 census changed')
    decode_call(bytes.fromhex(candidates[0]['bytes']),0x3c15671,START)
    # Independently bind the selected parent FDE and the local call setup.
    parent=0x3c154d0
    l,r=0,n
    while l<r:
        mid=(l+r)//2
        st=hdr+struct.unpack_from('<i',m,hdr+12+8*mid)[0]
        if st<parent: l=mid+1
        else: r=mid
    need(l<n, 'parent missing from unwind index')
    ps,pf=struct.unpack_from('<ii',m,hdr+12+8*l)
    parent_fde=hdr+pf
    need(hdr+ps==parent and parent_fde+8+struct.unpack_from('<i',m,parent_fde+8)[0]==parent
         and struct.unpack_from('<I',m,parent_fde+12)[0]==0x332, 'parent FDE changed')
    branch=m[0x3c1560f-0x1000:0x3c15611-0x1000]
    need(branch[:1]==b'\x71' and 0x3c15611+struct.unpack('<b',branch[1:])[0]==0x3c15665,
         'caller branch target changed')
    setup=m[0x3c15665-0x1000:0x3c15671-0x1000]
    need(setup==bytes.fromhex('4881c6a0000000488d7c2410'), 'caller instruction setup changed')
    # Supporting first-party association only, not a claimed semantic type.
    lea=m[0x3c15756-0x1000:0x3c1575d-0x1000]
    need(lea[:3]==bytes.fromhex('488d35') and 0x3c1575d+struct.unpack_from('<i',lea,3)[0]==0x646e990,
         'source-location LEA changed')
    slot=0x646e990; location=m[slot-0x2000:slot-0x2000+24]
    need(location==bytes.fromhex('00000000000000001700000000000000aa02000001000000'), 'location changed')
    hits=[]
    for p in range(0x6be8,0x6be8+0x163cc8,24):
        addr, info, addend=struct.unpack_from('<QQq',m,p)
        if addr==slot: hits.append((info,addend,p))
    need(len(hits)==1 and hits[0][0]==8, 'location relocation changed')
    pathaddr=hits[0][1]; path=m[pathaddr:pathaddr+23]
    need(path==b'l1/src/qtys/impl_ntl.rs', 'location source path changed')
    return {'target_sha256':DIGEST, 'coordinate_system':'original ELF virtual addresses',
      'body':{'start':START,'end':START+SIZE,'size':SIZE,'file_offset':START-0x1000,
              'sha256':sha(body),'padding_end':next_st,'padding_hex':padding.hex(), 'frame':fr},
      'instructions':instructions, 'callees':[],
      'direct_rel32_scan':{'range_start':TEXT_START,'range_end':TEXT_END,
                           'method':'every byte; e8/e9 signed rel32, complete instruction contained in range',
                           'candidates':candidates},
      'source_context':{'caller_fde_start':0x3c154d0,'caller_fde_end':0x3c15802,
                        'caller_fde_va':parent_fde,'branch_site':0x3c1560f,'branch_hex':branch.hex(),
                        'call_setup_hex':setup.hex(),
                        'call_site':0x3c15671,'location_lea_site':0x3c15756,'location_va':slot,
                        'location_hex':location.hex(),'relocation_file_offset':hits[0][2],
                        'path_va':pathaddr,'path':path.decode(),'line':682,'column':1}}


def emit(out, record):
    out.mkdir(parents=True, exist_ok=True)
    (out/'records.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    for name in ('README.md','verify.py'):
        src=PACKET/name
        if src.resolve() != (out/name).resolve(): shutil.copyfile(src,out/name)
    names=('README.md','records.json','verify.py')
    (out/'MANIFEST.sha256').write_text(''.join(sha((out/n).read_bytes())+'  '+n+'\n' for n in names),encoding='utf-8')


def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,default=TARGET);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    with a.binary.open('rb') as f:
        if not f.seek(0,2): raise ValueError('empty binary')
        f.seek(0)
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as m: record=collect(m)
    emit(a.out,record)

if __name__=='__main__': main()
