#!/usr/bin/env python3
"""Authenticate selected #115 sender instructions without executing them."""
import argparse,copy,hashlib,json
from pathlib import Path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def check(rows,facts):
    for address,expected in facts.items():
        if rows.get(address)!=expected: raise ValueError('instruction '+address)
def verify(target):
    p=json.loads((HERE/'records.json').read_text())
    data=target.read_bytes()
    if hashlib.sha256(data).hexdigest()!=p['target_sha256'] or p['target_sha256']!='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301': raise ValueError('target digest')
    if capstone.__version__!='5.0.7': raise ValueError('Capstone version')
    with target.open('rb') as f:
        elf=ELFFile(f)
        sections=[(s['sh_addr'],s['sh_offset'],s['sh_size']) for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS']
        fdes={(e['initial_location'],e['initial_location']+e['address_range']) for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e,FDE)}
    if tuple(int(v,16) for v in p['fde']) not in fdes: raise ValueError('FDE')
    def read(a,n):
        for start,off,size in sections:
            if start<=a and a+n<=start+size: return data[off+a-start:off+a-start+n]
        raise ValueError('unmapped')
    dis=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows={};count=0
    for w in p['windows']:
        a,z=int(w['start'],16),int(w['end'],16);raw=read(a,z-a)
        if hashlib.sha256(raw).hexdigest()!=w['sha256']: raise ValueError('window hash')
        got=[[hex(i.address),i.bytes.hex(),(i.mnemonic+' '+i.op_str).rstrip()] for i in dis.disasm(raw,a)]
        if got!=w['rows'] or sum(len(bytes.fromhex(v[1])) for v in got)!=len(raw): raise ValueError('transcript')
        rows.update({v[0]:v[2] for v in got});count+=len(got)
    check(rows,p['facts'])
    controls=[('0x2b7a726','mov qword ptr [rbx + 0x88], rdx'),('0x2b7b2cb','mov qword ptr [rbx + 0xf8], rdx'),('0x2b7afda','call 0x5cdfa50'),('0x2b7b008','add rcx, rdx'),('0x2b7b032','mov byte ptr [r12], 1'),('0x2b7b35f','mov rdi, qword ptr [rbx + 0x70]')]
    for address,value in controls:
        mutated=copy.copy(rows);mutated[address]=value
        try: check(mutated,p['facts'])
        except ValueError: continue
        raise ValueError('control accepted '+address)
    print(f"PASS: {len(p['windows'])} windows, {count} instructions, {len(p['facts'])} facts, {len(controls)} controls")
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');verify(ap.parse_args().target)
