#!/usr/bin/env python3
"""Static, digest-pinned RE-001 binding for one node #115 leaf (Python 3.10+)."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x55ff970, 0x55ff9d4
TEXT_START, TEXT_END, TEXT_OFFSET = 0x1419300, 0x63f0a00, 0x1418300
SIZE = 105896032

# Narrow instruction decoder: each opcode/operand form is independently checked.
# Relative branch destinations are calculated from signed encoded displacements.
FORMS = [
 ('8b4760','mov eax, dword [rdi+0x60]'), ('488b4f28','mov rcx, qword [rdi+0x28]'),
 ('3b87044e0000','cmp eax, dword [rdi+0x4e04]'), ('0f9cc0','setl al'),
 ('75..','jne'), ('8b4764','mov eax, dword [rdi+0x64]'),
 ('3b87084e0000','cmp eax, dword [rdi+0x4e08]'), ('0f92c0','setb al'),
 ('75..','jne'), ('8b4768','mov eax, dword [rdi+0x68]'),
 ('3b870c4e0000','cmp eax, dword [rdi+0x4e0c]'), ('73..','jae'), ('eb..','jmp'),
 ('84c0','test al, al'), ('75..','jne'), ('b002','mov al, 2'),
 ('483b8f984d0000','cmp rcx, qword [rdi+0x4d98]'), ('73..','jae'),
 ('488b4710','mov rax, qword [rdi+0x10]'), ('4889c2','mov rdx, rax'),
 ('4881ea78ecffff','sub rdx, sign-extended 0xffffec78'), ('72..','jb'),
 ('480588130000','add rax, 5000'), ('48c7c2ffffffff','mov rdx, -1'),
 ('480f43d0','cmovae rdx, rax'), ('4839d1','cmp rcx, rdx'),
 ('0f93c0','setae al'), ('c3','ret')]
BRANCHES = {0x55ff980:0x55ff99d, 0x55ff98e:0x55ff99d, 0x55ff999:0x55ff9a1,
            0x55ff99b:0x55ff9ac, 0x55ff99f:0x55ff9ac, 0x55ff9aa:0x55ff9d3,
            0x55ff9ba:0x55ff9cd}


def need(value, msg):
    if not value:
        raise ValueError(msg)


def decode(body):
    rows, pos = [], 0
    for pattern, mnemonic in FORMS:
        tokens = [pattern[i:i+2] for i in range(0, len(pattern), 2)]
        part = body[pos:pos+len(tokens)]
        need(len(part) == len(tokens), 'truncated instruction')
        need(all(t == '..' or int(t,16) == b for t,b in zip(tokens,part)), 'unexpected instruction encoding')
        pc = START + pos
        row = {'address':hex(pc), 'bytes':part.hex(), 'operation':mnemonic}
        if '..' in tokens:
            dest = pc + len(part) + struct.unpack('b',part[-1:])[0]
            need(BRANCHES.get(pc) == dest, 'unexpected branch target')
            row['target'] = hex(dest)
        rows.append(row)
        pos += len(part)
    need(pos == len(body), 'unconsumed body bytes')
    need(set(int(r['address'],16) for r in rows) >= set(BRANCHES.values()), 'branch into instruction interior')
    return rows


def frame(data):
    # .eh_frame_hdr uses data-relative sdata4 pairs; .eh_frame uses pcrel sdata4.
    hdr, end = 0xb9ea40, 0xca6ed4
    need(data[hdr:hdr+4] == bytes.fromhex('011b033b'), 'unwind encoding changed')
    n = struct.unpack_from('<I',data,hdr+8)[0]
    need(hdr+12+8*n <= end, 'bad unwind header size')
    lo, hi = 0, n
    while lo < hi:
        m = (lo+hi)//2
        a = hdr+struct.unpack_from('<i',data,hdr+12+8*m)[0]
        if a < START: lo = m+1
        else: hi = m
    need(0 < lo < n-1, 'missing selected FDE')
    entry = hdr+12+8*lo
    begin, delta = struct.unpack_from('<ii',data,entry)
    need(hdr+begin == START, 'shifted FDE start')
    prev = hdr+struct.unpack_from('<i',data,entry-8)[0]
    following = hdr+struct.unpack_from('<i',data,entry+8)[0]
    need(prev < START < following and following == 0x55ff9e0, 'index neighbors changed')
    fde = hdr+delta
    need(0xca6ed8 <= fde < 0x1418254, 'FDE outside frame section')
    length, cp, displacement, extent = struct.unpack_from('<IIiI',data,fde)
    need(length == 16 and fde+8+displacement == START and extent == END-START, 'FDE start or extent changed')
    need(data[fde+16] == 0, 'unexpected FDE augmentation')
    cie = fde+4-cp
    need(data[cie:cie+24] == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'unexpected CIE')
    return {'fde_va':hex(fde), 'fde_file_offset':hex(fde), 'fde_hex':data[fde:fde+length+4].hex(),
            'cie_va':hex(cie), 'cie_file_offset':hex(cie), 'cie_hex':data[cie:cie+24].hex(),
            'unwind_index_entry_offset':hex(entry), 'next_index_start':hex(following), 'lsda':None}


def caller_scan(data):
    # Exhaustive byte-aligned candidate scan, including potential embedded opcodes.
    start = TEXT_OFFSET
    end = start + TEXT_END-TEXT_START
    result = []
    for opcode in (0xe8, 0xe9):
        p = data.find(bytes([opcode]),start,end-4)
        while p != -1:
            va = TEXT_START+p-start
            target = va+5+struct.unpack_from('<i',data,p+1)[0]
            if target == START:
                result.append({'site':hex(va), 'kind':'call' if opcode == 0xe8 else 'jmp',
                               'bytes':data[p:p+5].hex()})
            p = data.find(bytes([opcode]),p+1,end-4)
    return sorted(result,key=lambda x:int(x['site'],16))


def source_context(data):
    # Confirm the selected call and source Location reference in the same indexed FDE.
    fde = 0x13278b0
    length, cie_delta, delta, size = struct.unpack_from('<IIiI',data,fde)
    need(length == 80 and fde+8+delta == 0x517b760 and size == 0x8dd,
         'caller FDE changed')
    site, location = 0x517bd8f, 0x64768a8
    lea = data[site-0x1000:site-0x1000+7]
    need(lea[:3] == bytes.fromhex('488d3d') and site+7+struct.unpack_from('<i',lea,3)[0] == location,
         'caller Location reference changed')
    relocation = data[0xa29d8:0xa29d8+24]
    need(struct.unpack('<QQq',relocation) == (location,8,0x437df7), 'Location relocation changed')
    need(data[0x437df7:0x437df7+19] == b'l1/src/perp_meta.rs', 'Location path changed')
    loc = data[0x64748a8:0x64748a8+24]
    need(struct.unpack('<QQII',loc) == (0,19,163,38), 'Location data changed')
    return {'caller_fde_start':'0x517b760', 'caller_fde_end':'0x517c03d',
            'caller_fde_offset':hex(fde), 'caller_fde_hex':data[fde:fde+length+4].hex(),
            'lea_site':hex(site), 'lea_bytes':lea.hex(), 'location_va':hex(location),
            'location_file_offset':'0x64748a8', 'location_hex':loc.hex(),
            'relocation_file_offset':'0xa29d8', 'relocation_hex':relocation.hex(),
            'path':'l1/src/perp_meta.rs', 'line':163, 'column':38, 'call_site':'0x517beb5'}


def derive(data):
    fde = frame(data)
    off = TEXT_OFFSET+START-TEXT_START
    body = data[off:off+END-START]
    instructions = decode(body)
    padding = data[off+len(body):off+len(body)+12]
    need(padding == b'\xcc'*12, 'padding changed')
    callers = caller_scan(data)
    need(any(x['site'] == '0x517beb5' and x['kind'] == 'call' for x in callers), 'source-associated caller absent')
    return {'target_sha256':SHA, 'window':{'start':hex(START), 'end':hex(END), 'size':len(body),
            'file_offset':hex(off), 'sha256':hashlib.sha256(body).hexdigest(), 'padding_hex':padding.hex()},
            'frame':fde, 'caller_source_context':source_context(data), 'instructions':instructions, 'callees':[], 'direct_transfer_candidates':callers,
            'scan':{'start':hex(TEXT_START), 'end':hex(TEXT_END), 'opcodes':['e8','e9'],
                    'candidate_count':len(callers)}, 'instruction_count':len(instructions)}


def authenticate(data):
    need(len(data)==SIZE and hashlib.sha256(data).hexdigest()==SHA, 'node #115 digest/size mismatch')


def analyze(path):
    with path.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
        authenticate(data)
        return derive(data)


def model(a0,a1,a2,b0,b1,b2,current,other,base):
    """Raw inputs: 32-bit lexicographic limbs and three unsigned 64-bit words."""
    for n in (a0,a1,a2,b0,b1,b2):
        need(0<=n<2**32,'limb out of range')
    for n in (current,other,base):
        need(0<=n<2**64,'word out of range')
    signed = lambda n: n if n < 2**31 else n-2**32
    less = (signed(a0),a1,a2) < (signed(b0),b1,b2)
    if not less and current >= other:
        return 2
    return int(current >= min(2**64-1,base+5000))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,default=TARGET)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    records=analyze(args.binary)
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')

if __name__ == '__main__':
    main()
