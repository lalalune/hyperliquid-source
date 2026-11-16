#!/usr/bin/env python3
"""Check static #115 bytes and decoded instruction witnesses; no code executes."""
import argparse
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--target', type=Path, default=ROOT/'artifacts/node/115/hl-node')
args = parser.parse_args()
records = json.loads((HERE/'records.json').read_text())
data = args.target.read_bytes()
assert hashlib.sha256(data).hexdigest() == records['target_sha256'] == 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
with args.target.open('rb') as f:
    elf = ELFFile(f)
    sections = [(s['sh_addr'],s['sh_offset'],s['sh_size']) for s in elf.iter_sections()]
def read(addr,n):
    for va,offset,size in sections:
        if va <= addr and addr+n <= va+size:
            return data[offset+addr-va:offset+addr-va+n]
    raise ValueError(hex(addr))
for window in records['windows']:
    start,end=int(window['start'],16),int(window['end'],16)
    assert hashlib.sha256(read(start,end-start)).hexdigest()==window['sha256']
decoder=Cs(CS_ARCH_X86,CS_MODE_64)
for fact in records['facts']:
    addr=int(fact['address'],16)
    expected=bytes.fromhex(fact['hex'])
    assert read(addr,len(expected))==expected
    ins=next(decoder.disasm(expected,addr,count=1))
    assert ins.mnemonic+' '+ins.op_str == fact['instruction']
    mutated=bytes([expected[0]^1])+expected[1:]
    # Exercise the instruction pin against a modified in-memory copy, without
    # relying on the whole-file or window digest to reject it.
    def matches(raw):
        decoded = list(decoder.disasm(raw, addr, count=1))
        return raw == expected and len(decoded) == 1 and decoded[0].mnemonic+' '+decoded[0].op_str == fact['instruction']
    assert matches(expected) and not matches(mutated)
print(f"verified digest, {len(records['windows'])} windows and {len(records['facts'])} instruction pins; single-byte pin controls rejected")
