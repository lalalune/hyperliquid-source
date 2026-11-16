#!/usr/bin/env python3
"""Check selected support-gate instructions, without target execution."""
import argparse,copy,hashlib,json
from pathlib import Path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def check(rows,facts):
    for a,v in facts.items():
        if rows.get(a)!=v: raise ValueError('instruction '+a)
def verify(target):
    p=json.loads((HERE/'records.json').read_text()); data=target.read_bytes()
    if hashlib.sha256(data).hexdigest()!=p['target_sha256'] or p['target_sha256']!='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301': raise ValueError('digest')
    if capstone.__version__!='5.0.7': raise ValueError('capstone version')
    with target.open('rb') as f:
        elf=ELFFile(f)
        sections=[(s['sh_addr'],s['sh_offset'],s['sh_size']) for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS']
        fdes={(e['initial_location'],e['initial_location']+e['address_range']) for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e,FDE)}
        names={}
        for sec in elf.iter_sections():
            if sec['sh_type']=='SHT_RELA':
                sym=elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    if r['r_offset']==0x64dfb50:names[r['r_offset']]=sym.get_symbol(r['r_info_sym']).name
    if names.get(0x64dfb50)!='memcmp': raise ValueError('memcmp relocation')
    def read(a,n):
        for va,off,size in sections:
            if va<=a and a+n<=va+size:return data[off+a-va:off+a-va+n]
        raise ValueError('unmapped')
    for address, expected in ((0x451210, '0000304300003045'), (0x450170, '00000000000030430000000000003045')):
        if read(address, len(bytes.fromhex(expected))).hex() != expected: raise ValueError('conversion constant '+hex(address))
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows={};count=0
    for w in p['windows']:
        a,z=int(w['start'],16),int(w['end'],16)
        if (a,z) not in fdes: raise ValueError('FDE')
        raw=read(a,z-a)
        if hashlib.sha256(raw).hexdigest()!=w['sha256']:raise ValueError('window digest')
        got=[[hex(i.address),i.bytes.hex(),(i.mnemonic+' '+i.op_str).rstrip()] for i in decoder.disasm(raw,a)]
        if got!=w['rows'] or sum(len(bytes.fromhex(v[1])) for v in got)!=len(raw):raise ValueError('transcript')
        rows.update({v[0]:v[2] for v in got});count+=len(got)
    check(rows,p['facts'])
    controls=[('0x28a9eae','jne 0x28a9ee7'),('0x2738ca1','jp 0x2738e60'),('0x2738d99','mov edx, 0x13'),('0x2738dc6','jne 0x2738df0'),('0x2738e5d','setae al'),('0x28a9f99','call 0x36c7f70')]
    for a,v in controls:
        x=copy.copy(rows);x[a]=v
        try:check(x,p['facts'])
        except ValueError:continue
        raise ValueError('control accepted '+a)
    print(f"PASS: {len(p['windows'])} FDEs, {count} instructions, {len(p['facts'])} facts, memcmp binding, 2 conversion constants, {len(controls)} controls")
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');verify(ap.parse_args().target)
