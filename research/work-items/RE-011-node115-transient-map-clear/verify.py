#!/usr/bin/env python3
"""Static evidence checks, without executing or emulating target instructions."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(name,a,n):
 t=next(x for x in s if x['name']==name);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x2970360:(0x297074c,'8a6f2824cab5500dcaaa5d29764d0d6470441d06e555987c166c199ad4a0d937'),0x5be3400:(0x5be3b49,'4a8b4fea6a81a6f5df1b3d20db194fe346694ff6f59cea63c9a1663069e2202a'),0x2962aa0:(0x296754d,'880fe617eb64670749f2bbc2eec999ff26e0649d7ef58289af0af7af366ca9ec'),0x29a1290:(0x29a5fca,'aff83c384b12d1d6aab814d03a5c80cdef82b626dacd49830bb223f416c83bde')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(i.size for i in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-011-node115-transient-map-clear/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read('.text',a,len(raw))==raw
  rows[a]=raw
pins={0x2970371:'4989fd',0x2970374:'488d5718',0x297037f:'488b7f20',0x2970383:'498b4528',0x2970387:'49c7452800000000',0x297038f:'486bc858',0x29703b4:'4885c0',0x29703bb:'0f84ab000000',0x29703db:'4983c5a8',0x29703e8:'4c8b357969b703',0x29703f0:'410fb64500',0x29703f5:'3c0c',0x29703f7:'746a',0x2970443:'88442440',0x2970447:'4c89ff',0x297044a:'488b742410',0x297044f:'31d2',0x2970451:'41ffd6',0x2970454:'4983c5a8',0x2970458:'4883c358',0x297045c:'7592',0x297046c:'4d8bbd08010000',0x2970473:'4d85ff',0x2970476:'0f84e6000000',0x297047c:'4d8bb5f0000000',0x2970483:'66410f6f06',0x297048c:'660fd7c0',0x2970490:'f7d0',0x29704a5:'49ffcf',0x29704a8:'7466',0x29704b0:'66410f6f0424',0x29704b6:'4881c500fcffff',0x29704bd:'4983c410',0x29704ce:'f30fbccb',0x29704d2:'c1e106',0x29704db:'488b70e0',0x29704df:'4885f6',0x29704e2:'74bc',0x29704e7:'48c1e106',0x29704eb:'4801ce',0x29704ee:'4883c651',0x29704f4:'488b78d8',0x29704f8:'4829cf',0x29704fb:'4883c7c0',0x2970501:'4883fe10',0x2970505:'0f92c2',0x2970508:'c1e202',0x297050b:'41ffd5',0x2970514:'498b9df8000000',0x297051b:'4885db',0x297051e:'742e',0x2970520:'488d5311',0x2970524:'4c89f7',0x2970527:'beff000000',0x297052c:'ff151ef2b603',0x2970532:'488d4301',0x2970536:'4889c1',0x2970539:'48c1e903',0x297053d:'4883e0f8',0x2970541:'4829c8',0x2970544:'4883fb08',0x2970548:'480f42c3',0x297054e:'31c0',0x2970550:'49c7850801000000000000',0x297055b:'49898500010000',0x2970562:'49c7851801000000000000',0x5be3414:'0fb607',0x5be3417:'488d352aeed5fa',0x5be376f:'4885d2',0x5be3772:'0f846c020000',0x2963f6f:'488dbc2460120000',0x2963f77:'e8e4c30000',0x29a2846:'488dbc24800d0000',0x29a284e:'e80ddbfcff'}
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x29703bb,0x297046c),(0x29703e8,0x64e6d68),(0x2970476,0x2970562),(0x297052c,0x64df750),(0x5be3417,0x942248),(0x5be3772,0x5be39e4),(0x2963f77,0x2970360),(0x29a284e,0x2970360)]:assert target(a)==t
base=0x942248;assert base+struct.unpack('<i',read('.rodata',base+10*4,4))[0]==0x5be372b
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])}
assert rel[0x64e6d68]==(8,0x5be3400) and rel[0x64df750]==((10<<32)|6,0)
dyn=next(x for x in s if x['name']=='.dynsym');st=next(x for x in s if x['name']=='.dynstr');n=struct.unpack_from('<I',b,dyn['offset']+10*24)[0];p=st['offset']+n;assert b[p:b.index(b'\0',p)]==b'memset'
for mask,want in [(0,0),(1,1),(3,3),(7,7),(15,14),(31,28),(63,56)]:
 actual=mask if mask<8 else ((mask+1)&~7)-((mask+1)>>3);assert actual==want
for a in (0x297044f,0x2970476,0x2970527,0x2970539,0x2970550,0x5be3772,0x2963f77):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 8 edges, 2 relocations, 1 import, 1 table entry, 7 arithmetic cases and 7 controls: OK')
