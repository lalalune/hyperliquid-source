"""Second file-mapping method and bounded transform-helper attribution.

This is an independent parser cross-check by the same author, not peer review.
"""
import hashlib
import struct
from collect import need,RANGES,SHA,SIZE


def verify_context(data,record):
    need(len(data)==SIZE and hashlib.sha256(data).hexdigest()==SHA,'context identity mismatch')
    need(data[:6]==b'\x7fELF\x02\x01','expected ELF64 little endian')
    off=struct.unpack_from('<Q',data,32)[0];entry,n=struct.unpack_from('<HH',data,54)
    need(entry==56,'unexpected ELF program-header stride')
    segments=[]
    for i in range(n):
        kind,flags,file_off,va,_,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,off+i*entry)
        if kind==1:segments.append((file_off,va,filesz,memsz,flags))
    def read(a,n):
        hits=[s for s in segments if s[1]<=a and a+n<=s[1]+s[2]];need(len(hits)==1,'ambiguous file-backed PT_LOAD')
        s=hits[0];o=s[0]+a-s[1];return data[o:o+n]
    bindings=[]
    for (a,b),owner in zip(RANGES,record['owners']):
        body=read(a,b-a);need(hashlib.sha256(body).hexdigest()==owner['sha256'],'section/program-header owner mappings differ')
        bindings.append({'start':hex(a),'bytes':b-a,'sha256':owner['sha256']})
    slot=0x64e7790
    matches=[r for r in record['relocations'] if r['slot']==hex(slot)]
    need(len(matches)==1 and matches[0]['info']==8 and matches[0]['addend']=='0x477f8c0','selected transform binding changed')
    a=0x4780179;raw=read(a,7)
    need(raw[:3]==bytes.fromhex('488d05') and a+7+struct.unpack_from('<i',raw,3)[0]==0x7e1aea,'transform diagnostic RIP reference changed')
    literal=read(0x7e1aea,20);need(literal==b'lz4 bytes over limit','transform diagnostic changed')
    # The stable two-body evidence deliberately does not claim full decoder closure.
    return {'method':'ELF64 program-header PT_LOAD file mapping; no section parser used for these reads','owners':bindings,
            'transform_slot':hex(slot),'relative_target':'0x477f8c0','diagnostic_lea':hex(a),'diagnostic_instruction':raw.hex(),'diagnostic_va':'0x7e1aea','diagnostic':literal.decode(),
            'attribution':'The selected post-read helper has the LZ4 over-limit diagnostic; decompression is an inferred label, not a recovered implementation.',
            'limits':'No codec correctness, output length, error ABI, helper effects or native type identity is established.'}
