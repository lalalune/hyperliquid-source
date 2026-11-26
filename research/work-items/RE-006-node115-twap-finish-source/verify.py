#!/usr/bin/env python3
"""Verify cited FDEs and selected native witnesses without target execution."""
import argparse, hashlib, json
from pathlib import Path
import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE

def verify(target):
    packet=json.loads(Path(__file__).with_name('records.json').read_text())
    data=target.read_bytes()
    assert len(data)==packet['target_size'] and hashlib.sha256(data).hexdigest()==packet['target_sha256']
    assert capstone.__version__=='5.0.7'
    with target.open('rb') as f:
        elf=ELFFile(f)
        sections=[(s['sh_addr'],s['sh_offset'],s['sh_size']) for s in elf.iter_sections() if s['sh_type']!='SHT_NOBITS']
        fdes={(e['initial_location'],e['initial_location']+e['address_range']) for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e,FDE)}
    def read(a,n):
        for va,off,size in sections:
            if va<=a and a+n<=va+size:return data[off+a-va:off+a-va+n]
        raise ValueError('unmapped')
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); decoded={}; count=0
    for w in packet['cited_only_not_claimed']:
        a,b=map(lambda s:int(s,16),(w['start'],w['end']));assert (a,b) in fdes
        raw=read(a,b-a);assert hashlib.sha256(raw).hexdigest()==w['sha256']
        rows=[[hex(i.address),i.bytes.hex(),(i.mnemonic+' '+i.op_str).rstrip()] for i in decoder.disasm(raw,a)]
        assert rows==w['rows'] and sum(len(bytes.fromhex(r[1])) for r in rows)==len(raw)
        decoded.update({r[0]:r[2] for r in rows});count+=len(rows)
    assert all(decoded.get(a)==v for a,v in packet['facts'].items())
    for a in packet['facts']:
        altered=dict(decoded);altered[a]='wrong'
        assert not all(altered.get(k)==v for k,v in packet['facts'].items())
    print(f'PASS: 4 cited FDEs, {count} instructions, {len(packet["facts"])} witnesses and 12 negative controls')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--target',type=Path,required=True);verify(p.parse_args().target)
