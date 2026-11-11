#!/usr/bin/env python3
"""Reproduce the long-path call boundary from bytes; no instruction execution."""
import hashlib
import struct
from pathlib import Path
from elf_index import unwind_index
from fde_extents import eh_frame_records

SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES={
 0x5c9ca30:(0x5c9ccdb,'d57ce0be1140e9a1a84decb130b9c43b48cb3a353803b5c4edd5c0baf6c712ba'),
 0x5c78e40:(0x5c78ec1,'0312fdc397f490eca406f84784ca9ed0f5f37e12f6ec7c3a05464f0ea2d4c212'),
 0x1501290:(0x150135b,'5f36b066d69858b964e0a83d102069670bde7a5ef3b30f6373505a277523bb13'),
 0x15021d0:(0x150229b,'8a9e6cb5818d9aab6e6bb2d741d472d03c26a04f6d6892620388c3425754aaaa'),
}
PINS={
 0x5c9ca4d:'4881fa7f010000', 0x5c9ca54:'0f8725020000',
 0x5c9cb77:'4c39f1', 0x5c9cb7a:'751c', 0x5c9cb83:'ff156ffa8400',
 0x5c9cb98:'b901000000', 0x5c9cb9d:'488d0514648200',
 0x5c9cbb0:'4885c0', 0x5c9cbb3:'7431', 0x5c9cbe6:'ff15dc338400', 0x5c9cbec:'8b00', 0x5c9cbee:'48c1e020', 0x5c9cbf2:'4883c802',
 0x5c9cc63:'488903', 0x5c9cc66:'44886308', 0x5c9cc85:'e8b6c1fdff', 0x5c9cc8a:'4889c1', 0x5c9cc8d:'4889d0',
 0x5c9cc90:'41b402', 0x5c9cc93:'f6c101', 0x5c9cc96:'0f8414ffffff',
 0x5c78e59:'ff15b9688600', 0x5c78e5f:'488b75c0', 0x5c78e66:'48f7d8', 0x5c78e69:'7128',
 0x5c78e6b:'4c8b7dc8', 0x5c78e6f:'4c8b65d0', 0x5c78e76:'ff157c378700',
 0x5c78e7c:'4889c3', 0x5c78e7f:'41c60700', 0x5c78e83:'4531f6',
 0x5c78e86:'4d85e4', 0x5c78e89:'7423', 0x5c78e8e:'4c89e6',
 0x5c78e93:'488d1d1ea18400', 0x5c78e9a:'41be01000000', 0x5c78ea0:'730c',
 0x5c78ea2:'488b7dc8', 0x5c78ea8:'ff15f2658600', 0x5c78eae:'4c89f0', 0x5c78eb1:'4889da',
 0x15012a5:'ff15c5f6fd04', 0x15012b4:'3c02', 0x15021e5:'ff1585e7fd04', 0x15021f4:'3c02',
}
b=Path('artifacts/node/115/hl-node').read_bytes()
assert hashlib.sha256(b).hexdigest()==SHA
secs,hdr=unwind_index(b); _,fdes=eh_frame_records(b,secs)
idx={(x['start'],x['fde']) for x in hdr}
def read(a,n):
 s=next(x for x in secs if x['address']<=a and a+n<=x['address']+x['size'])
 p=s['offset']+a-s['address']; return b[p:p+n]
for start,(end,digest) in BODIES.items():
 assert any(x['start']==start and x['end']==end and (start,x['fde']) in idx for x in fdes)
 assert hashlib.sha256(read(start,end-start)).hexdigest()==digest
spans={a:read(a,len(bytes.fromhex(raw))) for a,raw in PINS.items()}
def check(rows):
 for a,raw in PINS.items(): assert rows[a]==bytes.fromhex(raw),hex(a)
check(spans)
def rip(a):
 raw=spans[a]; return a+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]
for a,target in [(0x5c9cc85,0x5c78e40),(0x5c78e59,0x64df718),(0x5c78e76,0x64ec5f8),
                 (0x5c78ea8,0x64df4a0),(0x5c9cb83,0x64ec5f8),(0x5c9cbe6,0x64dffc8),
                 (0x15012a5,0x64e0970),(0x15021e5,0x64e0970),
                 (0x5c9cb9d,0x64c2fb8),(0x5c78e93,0x64c2fb8)]: assert rip(a)==target
r=next(x for x in secs if x['name']=='.rela.dyn')
rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
for slot,target in [(0x64e0970,0x5c9ca30),(0x64df718,0x141e960),(0x64df4a0,0x635de30)]: assert rel[slot]==(8,target)
dynsym=next(x for x in secs if x['name']=='.dynsym'); dynstr=next(x for x in secs if x['name']=='.dynstr')
strings=b[dynstr['offset']:dynstr['offset']+dynstr['size']]
for slot,name in [(0x64ec5f8,b'opendir'),(0x64dffc8,b'__errno_location')]:
 info,addend=rel[slot]; assert info & 0xffffffff==6 and addend==0
 stname=struct.unpack_from('<I',b,dynsym['offset']+(info>>32)*24)[0]
 assert strings[stname:strings.index(b'\0',stname)]==name
for a in (0x5c9ca4d,0x5c78e69,0x5c78e7f):
 changed=dict(spans); changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try: check(changed)
 except AssertionError: pass
 else: raise AssertionError('mutation accepted '+hex(a))
print(f'{len(BODIES)} indexed FDEs, {len(PINS)} instruction spans, 10 targets, 3 relative relocations, 2 imports, 3 corruption controls: OK')
