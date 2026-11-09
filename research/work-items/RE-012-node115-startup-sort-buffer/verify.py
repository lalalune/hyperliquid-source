#!/usr/bin/env python3
"""Check static x86 bytes and data only; never execute the captured target."""
import hashlib
import struct
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {
    0x15b58c0: (0x15b59d2, '2ef96a47dd066f516b5b755ad95dbe90629181b6344e6a0a60881caa6d1492b1'),
    0x15b59e0: (0x15b5af2, '1ab9981059cdad2c11e60ea4f9bfa3faaa2e294323161759ec291dc377629d01'),
    0x152d390: (0x152d4af, '4a4b1d7448ba782f2a9f06278a3072d5960fbcda97781dde7fff4d3731e83555'),
}
# Key arithmetic, selection, allocation and normal-return instructions.
PINS = {
    0x15b5987:'4983fe15', 0x15b598b:'731a', 0x15b59af:'4c89f6', 0x15b59b2:'ff15a0b4f204',
    0x15b5aa7:'4983fe15', 0x15b5aab:'731a', 0x15b5acf:'4c89f6', 0x15b5ad2:'ff1580b3f204',
    0x152d3b0:'4889f1', 0x152d3b3:'48d1e9', 0x152d3b6:'4889f0', 0x152d3b9:'4829c8',
    0x152d3bc:'4881fe15160500', 0x152d3c3:'41bc15160500', 0x152d3c9:'4c0f42e6',
    0x152d3cd:'4939c4', 0x152d3d0:'4c0f46e0', 0x152d3d4:'4981fcab000000',
    0x152d3db:'7226', 0x152d3dd:'4a8d0ce500000000', 0x152d3e5:'4c8d3c49',
    0x152d3e9:'48b95555555555555505', 0x152d3f3:'4839c8', 0x152d3f6:'7617',
    0x152d3fd:'ff159520fb04', 0x152d403:'4c8d742418', 0x152d408:'b9aa000000',
    0x152d418:'ff156220fb04', 0x152d421:'7462', 0x152d438:'4c89e1',
    0x152d444:'4883fe41', 0x152d448:'410f92c0', 0x152d44c:'4c89f2',
    0x152d452:'e8e961fcff', 0x152d457:'4981fcaa000000', 0x152d45e:'7613',
    0x152d460:'49c1e403', 0x152d464:'4b8d3464', 0x152d46d:'ff152d20fb04',
}

data = Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(data).hexdigest() == SHA
sections, hdr = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
indexed = {(r['start'],r['fde']) for r in hdr}
def read(va,size):
    s = next(s for s in sections if s['address'] <= va and va+size <= s['address']+s['size'])
    p = s['offset'] + va-s['address']
    return data[p:p+size]
for a,(end,digest) in BODIES.items():
    assert any(r['start']==a and r['end']==end and (a,r['fde']) in indexed for r in fdes)
    assert hashlib.sha256(read(a,end-a)).hexdigest()==digest

def verify_pins(spans):
    for va,expected in PINS.items():
        assert spans[va] == bytes.fromhex(expected), hex(va)
spans = {va:read(va,len(bytes.fromhex(raw))) for va,raw in PINS.items()}
verify_pins(spans)
for va in (0x15b59b2,0x15b5ad2):
    raw=spans[va]
    assert va+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0] == 0x64e0e58
raw=spans[0x152d452]
assert 0x152d452+len(raw)+struct.unpack_from('<i',raw,1)[0] == 0x14f3640
s=next(x for x in sections if x['name']=='.rela.dyn')
rel={a:(b,c) for a,b,c in struct.iter_unpack('<QQq',data[s['offset']:s['offset']+s['size']])}
for slot,target in [(0x64e0e58,0x152d390),(0x64df480,0x6355830),(0x64df498,0x141e264),(0x64df4a0,0x635de30)]:
    assert rel[slot]==(8,target)
# Model the observed unsigned operations only; no target instruction is run.
def capacity(n):
    assert 0 <= n < 1<<64
    return max(min(n,0x51615), n-(n>>1))
for n,want in [(21,21),(64,64),(65,65),(170,170),(171,171),
               (333333,333333),(333334,333333),(666666,333333),(666667,333334)]:
    assert capacity(n)==want
assert 170*24 == 4080 and 171*24 == 4104
# Reject changes to the actual entry threshold and stack/heap threshold separately.
for va in (0x15b5987,0x152d3d4):
    altered=dict(spans); altered[va]=altered[va][:-1]+bytes([altered[va][-1]^1])
    try: verify_pins(altered)
    except AssertionError: pass
    else: raise AssertionError('mutation accepted at '+hex(va))
print(f'{len(BODIES)} indexed FDEs, {len(PINS)} exact instruction spans, 4 relocations, 9 arithmetic cases, 2 mutation controls: OK')
