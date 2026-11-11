#!/usr/bin/env python3
"""Static target evidence only; no target instruction execution or emulation."""
import csv,hashlib,struct
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from elf_index import unwind_index
from fde_extents import eh_frame_records
b=Path('artifacts/node/115/hl-node').read_bytes();assert hashlib.sha256(b).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
s,h=unwind_index(b);_,f=eh_frame_records(b,s);idx={(x['start'],x['fde']) for x in h}
def read(name,a,n):
 t=next(x for x in s if x['name']==name);assert t['address']<=a and a+n<=t['address']+t['size'];p=t['offset']+a-t['address'];return b[p:p+n]
bodies={0x2972390:(0x2972c20,'f47ba29ca1c91c4bb21e63de7cfa7f860f5ad05a2cd8ab9fb4d58a16165b8bcf'),0x29710e0:(0x29712bc,'9efc06c602ba274a085ae45dc96fd27f0dafadab9da77ac0db7fd1015cb8c661'),0x5be3400:(0x5be3b49,'4a8b4fea6a81a6f5df1b3d20db194fe346694ff6f59cea63c9a1663069e2202a'),0x5be1e70:(0x5be1fc5,'8e60a30b018c6384e4d43e174211ae5a076355ad35336507d7830af8e5b9275c'),0x5be1fd0:(0x5be222b,'d23f2e8885c58d61ae87d89d35e0d30caf3a5b9a0231d0f539cdf1162e64c1e5')}
starts=set()
for a,(z,d) in bodies.items():
 assert any(x['start']==a and x['end']==z and (a,x['fde']) in idx for x in f)
 raw=read('.text',a,z-a);assert hashlib.sha256(raw).hexdigest()==d
 ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(raw,a));assert sum(i.size for i in ins)==len(raw);starts.update(i.address for i in ins)
rows={}
with Path('research/work-items/RE-011-node115-transient-journal-restore/instructions.tsv').open() as fp:
 for x in csv.DictReader(fp,delimiter='\t'):
  a=int(x['va'],16);lo=int(x['fde_start'],16);hi=int(x['fde_end'],16);raw=bytes.fromhex(x['bytes'])
  assert a not in rows and a in starts and lo in bodies and bodies[lo][0]==hi and lo<=a<a+len(raw)<=hi and read('.text',a,len(raw))==raw
  rows[a]=raw
pins={0x2972960:'486bcb58',0x2972964:'c604080a',0x297296b:'89540811',0x2972972:'0f11440801',0x2972981:'0f11440815',0x2972986:'0f114c0825',0x297298f:'89540834',0x29729a3:'0f11440838',0x29729a8:'0f114c0848',0x2971136:'498b4e08',0x297113a:'488b4328',0x297113e:'4839c1',0x2971141:'0f83bc000000',0x2971147:'4c8db3c8000000',0x297114e:'4c8dbbf0000000',0x2971159:'48894b28',0x2971161:'4c6be158',0x2971186:'486bc058',0x297118e:'4983c5a8',0x2971195:'488b1dcc5bb703',0x29711a0:'410fb64500',0x29711a5:'3c0c',0x29711a7:'745a',0x29711c4:'410f104501',0x29711c9:'410f104d11',0x29711ce:'410f105521',0x29711d3:'410f105d31',0x29711e8:'88442430',0x29711ec:'488d7c2430',0x29711f1:'4c89f6',0x29711f4:'4c89fa',0x29711f7:'ffd3',0x29711f9:'4983c5a8',0x29711fd:'4983c458',0x2971201:'759d',0x5be3414:'0fb607',0x5be3417:'488d352aeed5fa',0x5be341e:'48630486',0x5be3422:'4801f0',0x5be3425:'ffe0',0x5be372b:'8b4711',0x5be3732:'0f104701',0x5be373b:'0f104718',0x5be373f:'0f104f28',0x5be3753:'f30f6f4738',0x5be3758:'f30f6f4f48',0x5be376f:'4885d2',0x5be3772:'0f846c020000',0x5be3798:'0f8458020000',0x5be379e:'4883c738',0x5be37a2:'f30f6f07',0x5be37a6:'f30f6f4f10',0x5be37c2:'4889d6',0x5be37c5:'4889c2',0x5be37c8:'e8a3e6ffff',0x5be37cd:'4c8b3424',0x5be37d4:'0f8439020000',0x5be3a0c:'e82ff9ffff',0x5be3a13:'488b742408',0x5be3a18:'4883c6d8',0x5be3a1f:'488d942490000000',0x5be3a27:'488d4c2430',0x5be3a2c:'e89fe5ffff',0x5be1f31:'742b',0x5be1f5e:'4c895308',0x5be1f62:'48897310',0x5be1f66:'48c70300000000',0x5be2074:'f3410f6f1e',0x5be2079:'f3410f6f6610',0x5be207f:'f3410f6f6c24c0',0x5be2086:'660f74eb',0x5be208a:'f3410f6f5c24d0',0x5be2091:'660f74dc',0x5be2095:'660fdbdd',0x5be2099:'660fd7eb',0x5be209d:'81fdffff0000',0x5be20a3:'745f',0x5be2104:'410f104424e0',0x5be210a:'410f104c24f0',0x5be2118:'0f1001',0x5be211b:'0f104910',0x5be211f:'410f114424e0',0x5be2125:'410f114c24f0'}
pins.update({0x29711b3:'498b5550',0x29711b7:'4889554f',0x29711bb:'410f104541',0x29711c0:'0f114540',0x29711d8:'0f115d30',0x29711dc:'0f115520',0x29711e0:'0f114d10',0x29711e4:'0f114500',0x5be3743:'0f29842490000000',0x5be374b:'0f298c24a0000000',0x5be3778:'660f6f8424b0000000',0x5be3781:'660feb8424c0000000',0x5be378a:'660fefc9',0x5be378e:'660f76c8',0x5be3792:'0f50c1',0x5be3795:'83f00f',0x5be37ab:'660f7f4c2440',0x5be37b1:'660f7f442430',0x5be37ba:'488d442460',0x5be3a06:'4889d6',0x5be3a09:'4889c2',0x5be1f08:'f3410f6f26',0x5be1f0d:'660f74e3',0x5be1f11:'66410f6e5ad0',0x5be1f17:'66410f6e6e10',0x5be1f1d:'660f74eb',0x5be1f21:'660fdbec',0x5be1f25:'66440fd7dd',0x5be1f2a:'4181fbffff0000'})
def check(r):
 for a,v in pins.items():assert r[a]==bytes.fromhex(v),hex(a)
check(rows)
def target(a):
 x=rows[a];return a+len(x)+int.from_bytes(x[-4:],'little',signed=True)
for a,t in [(0x2971141,0x2971203),(0x2971195,0x64e6d68),(0x5be3417,0x942248),(0x5be3772,0x5be39e4),(0x5be3798,0x5be39f6),(0x5be37c8,0x5be1e70),(0x5be37d4,0x5be3a13),(0x5be3a0c,0x5be3340),(0x5be3a2c,0x5be1fd0)]:assert target(a)==t
assert 0x5be20a3+2+int.from_bytes(rows[0x5be20a3][1:],'little',signed=True)==0x5be2104
base=0x942248;assert base+struct.unpack('<i',read('.rodata',base+10*4,4))[0]==0x5be372b
r=next(x for x in s if x['name']=='.rela.dyn');rel={a:(i,d) for a,i,d in struct.iter_unpack('<QQq',b[r['offset']:r['offset']+r['size']])};assert rel[0x64e6d68]==(8,0x5be3400)
for a in (0x2972964,0x29729a3,0x297114e,0x5be3798,0x5be3a2c,0x5be20a3,0x5be211f):
 changed=dict(rows);changed[a]=changed[a][:-1]+bytes([changed[a][-1]^1])
 try:check(changed)
 except AssertionError:pass
 else:raise AssertionError('mutation accepted '+hex(a))
print(f'{len(bodies)} decoded FDEs, {len(rows)} spans, {len(pins)} pins, 10 edges, 1 table entry, 1 relocation and 7 corruption controls: OK')
