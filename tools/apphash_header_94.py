#!/usr/bin/env python3
"""Extract the two row-zero app-hash header serializers from node #94 bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
# FDE start and digest of its complete, unmasked bytes. Helper bodies are included
# so that neither the call target nor a later part of the helper can drift silently.
BODIES = {
 0x151f240:'172ac8d4c2317233fd93fa02ba0d7697c1d74d6ab8ce3609826bb3f86c510e48',
 0x15204a0:'c71c06feaa164107bb8e7771027403d8a318895e89494f59a0abda31df39aa7c',
 0x25a8f80:'03314d63423cd87d32a952a091906a1f33a112832b2ff2c16ed38101a52cd8a8',
 0x25aa7f0:'7959c723e690a8b949e794907dca4d9f4ca8808fa74ce7c86fe59adb26df4eed',
 0x25acc20:'97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa',
 0x1dfca40:'53404c658c477544f6921af8516b6d915760d0a5231b3e23a60fc690e656da20',
 0x1e4c9c0:'3dfff6f8edfa27f8ed9e61a69ed397ce9436ba651745f039d8af1f51f9dfc50f',
 0x1e4fc10:'275bd67ef2c03e171907f337f43cd15777b99f7317e68d0cfca4d82b19cb4242',
 0x25ac0d0:'b46f6ef6ae1413ce43646a2b4066f9caf0afa6a6eaeed1c36b3abf8a10fa56c2',
 0x25ac580:'480f0610e8d209ee7e3b320bcf963ebaa38a6d9bcccbeee00c9932e6f1560918',
 0x25ac7b0:'d80152d26196c1e4f564ae1e604f175accd09fcde7ad99650d87922fbd0dcf1d',
 0x25ac9e0:'498e55a96dd64edc78aa91384917f4fabfd4a8b6ac05f0fbde5a3f0fb40a0f07',
 0x2218e60:'2c19c80574be36a651d698186c582d0fa16f3b0110e3d1e0c0de4479ed189d2a',
 0x4c633b0:'e7181cb86f0f48eca2fbb458795e7e59abfe6e94f8c5025fe70d9b7921e8413b',
 0x22bd690:'8e75b972ef226afd004f2495c4a1d91da4c146b3db14048e0e1f502f0ae35721',
 0x22bdd40:'d0cf99663d810fbfe175abcda0c586528030937d9285d14dcab42052b48d1711',
 0x22bdee0:'5e1b59eff28aa086f5498c41b413ee00f3c5b4e218572711e71bed296ef17ed2',
 0x22bd720:'9b69d30193c9b9d340096e49e70d6751b6a7cb4505d70bba3655a49b90ade879',
 0x22bdfa0:'991c22ed429455745e4fb145bf1933b8f538ea3676ca713c3ab81329c7c937c0',
 0x4c82af0:'c1303abe4ded57e014532bad018efbd29e1bb61ecb4c9621ce37ae00415793fe',
 0x4c82b60:'1b4706955f7e64f9246312605d700bef950ef65a878881467f116a40eb8695a6',
 0x4c828d0:'d9b3e5d213d551d2d2dd33a671290eb2d9597483c7299fc3c41330125cdc6e6e',
 0x4c819d0:'9d35089ab4f2afe38e87f40828b1fe2a0f082a5e9aeb684afb0d50140db54e9e',
 0x4c815b0:'674064c3010c57b038a32f8045a232e1dfb9f41417efca4ae6c21d490332aaf7',
}
# Each tuple is (key RIP lea, length-immediate instruction, value load,
# value/helper call), in observed serialization order. Nested version/round
# are part of hardfork, not outer fields. system_nonce key is in its helper.
LOW = [
 (0x2218ee4,0x2218eeb,0x2218ed9,0x2218f0d),
 (0x2218f28,0x2218f2f,None,None),
 (0x2219028,0x221902f,0x221901d,0x2219051),
 (0x221906c,0x2219073,0x2219086,0x2219098),
 (0x2219106,0x221910d,0x2219124,0x2219130),
 (0x2219148,0x2219154,0x2219144,0x221915c),
 (0x2219170,0x221917c,0x221916c,0x2219184),
 (0x2219198,0x22191a4,0x2219194,0x22191ac),
 (0x22191c0,0x22191cc,0x22191bc,0x22191d4),
 (0x22191e8,0x22191f4,0x22191e4,0x22191fc),
 (0x22bdd5e,0x22bdd68,0x221920c,0x2219218),
 (0x221922c,0x2219238,0x2219228,0x2219240),
 (0x2219250,0x221925c,0x221924c,0x2219264),
]
HIGH = [
 (0x4c63434,0x4c6343b,0x4c63429,0x4c6345d),
 (0x4c63478,0x4c6347f,0x4c63496,0x4c634a2),
 (0x4c634bd,0x4c634c4,0x4c634b2,0x4c634e6),
 (0x4c63501,0x4c63508,0x4c6351b,0x4c6352d),
 (0x4c635b1,0x4c635b8,0x4c635cf,0x4c635db),
 (0x4c635f3,0x4c635ff,0x4c635ef,0x4c63607),
 (0x4c6361b,0x4c63627,0x4c63617,0x4c6362f),
 (0x4c63643,0x4c6364f,0x4c6363f,0x4c63657),
 (0x4c6366b,0x4c63677,0x4c63667,0x4c6367f),
 (0x4c63693,0x4c6369f,0x4c6368f,0x4c636a7),
 (0x4c828ee,0x4c828f8,0x4c636b7,0x4c636c3),
 (0x4c636d3,0x4c636df,0x4c636cf,0x4c636e7),
 (0x4c636f7,0x4c63703,0x4c636f3,0x4c6370b),
]
BRANCHES = [0x151f26b,0x151f283,0x15204fd,0x152061b,0x2218e84,0x2218ea1,0x2218ed7,0x2218ee2,0x2218efc,0x2218f1b,0x2218f26,0x2218f40,0x2218f4b,0x2218f68,0x2218f8a,0x2218f99,0x2218fb3,0x2218fdd,0x2218ff7,0x2219017,0x2219026,0x2219040,0x221905f,0x221906a,0x2219084,0x221908a,0x22190a6,0x22190f9,0x2219104,0x221911e,0x221913e,0x2219166,0x221918e,0x22191b6,0x22191de,0x2219206,0x2219222,0x221924a,0x221926e,
0x4c633d4,0x4c633f1,0x4c63427,0x4c63432,0x4c6344c,0x4c6346b,0x4c63476,0x4c63490,0x4c634ac,0x4c634bb,0x4c634d5,0x4c634f4,0x4c634ff,0x4c63519,0x4c6351f,0x4c6353b,0x4c635a8,0x4c635af,0x4c635c9,0x4c635e9,0x4c63611,0x4c63639,0x4c63661,0x4c63689,0x4c636b1,0x4c636cd,0x4c636f1,0x4c63715]

class Image:
 def __init__(self, data):
  self.data = data
  self.secs = sections(data)
 def read(self, va, n, executable=None):
  if n < 0 or va < 0: raise ValueError('invalid range')
  hits = [s for s in self.secs if s['type'] != 8 and s['address'] <= va and va+n <= s['address']+s['size'] and (executable is None or bool(s['flags'] & 4)==executable)]
  if len(hits)!=1: raise ValueError('unmapped or ambiguous range')
  s=hits[0]; p=s['offset']+va-s['address']; return self.data[p:p+n]
 def rip(self, va):
  b=self.read(va,7,True)
  if b[:3] not in (b'\x48\x8d\x35',b'\x48\x8d\x15',b'\x48\x8d\x05',b'\x48\x8d\x0d',b'\x4c\x8d\x05'): raise ValueError('bad RIP lea')
  return va+7+struct.unpack_from('<i',b,3)[0]
 def imm(self, va):
  b=self.read(va,5,True)
  if b[0] not in (0xba,0xb9): raise ValueError('bad immediate')
  return struct.unpack_from('<I',b,1)[0]
 def call(self, va):
  b=self.read(va,5,True)
  if b[0]!=0xe8: raise ValueError('bad call')
  return va+5+struct.unpack_from('<i',b,1)[0]
 def slot_call(self, va):
  b=self.read(va,6,True)
  if b[:2] != b'\xff\x15': raise ValueError('bad indirect call')
  return va+6+struct.unpack_from('<i',b,2)[0]
 def branch(self, va):
  b=self.read(va,6,True)
  if b[0] in (0x74,0x75): size=2; disp=struct.unpack_from('<b',b,1)[0]; condition={0x74:'eq',0x75:'ne'}[b[0]]
  elif b[:2] in (b'\x0f\x83',b'\x0f\x84',b'\x0f\x85',b'\x0f\x87'): size=6;disp=struct.unpack_from('<i',b,2)[0];condition={0x83:'ae',0x84:'eq',0x85:'ne',0x87:'a'}[b[1]]
  else: raise ValueError('bad branch')
  return {'va':hex(va),'bytes':b[:size].hex(),'condition':condition,'target':hex(va+size+disp),'fallthrough':hex(va+size)}

def load_offset(raw):
 if raw == bytes.fromhex('41833f01'): return 0
 if raw[:3] in (bytes.fromhex('4d8b67'),bytes.fromhex('498b57'),bytes.fromhex('4d8d47'),bytes.fromhex('4d8b47'),bytes.fromhex('458b47'),bytes.fromhex('498d77')): return raw[3]
 raise ValueError('unexpected field load')

def keccak256(message, round_constants, delimiter=1):
 # Independent scalar model of Keccak-f[1600], not an execution of target code.
 if len(round_constants) != 24: raise ValueError('round constant count')
 if delimiter not in (1,6): raise ValueError('unsupported delimiter')
 mask=(1<<64)-1
 def rotate(value,shift):
  shift %= 64
  return ((value<<shift)|(value>>(64-shift))) & mask if shift else value
 rotations=[0]*25
 x,y=1,0
 for t in range(24):
  rotations[x+5*y]=((t+1)*(t+2)//2)%64
  x,y=y,(2*x+3*y)%5
 state=[0]*25
 padded=bytearray(message);padded.append(delimiter)
 while len(padded)%136: padded.append(0)
 padded[-1] |= 128
 for at in range(0,len(padded),136):
  for i in range(17): state[i]^=int.from_bytes(padded[at+8*i:at+8*i+8],'little')
  for rc in round_constants:
   column=[state[x]^state[x+5]^state[x+10]^state[x+15]^state[x+20] for x in range(5)]
   d=[column[(x-1)%5]^rotate(column[(x+1)%5],1) for x in range(5)]
   for y in range(5):
    for x in range(5): state[x+5*y]^=d[x]
   b=[0]*25
   for y in range(5):
    for x in range(5): b[y+5*((2*x+3*y)%5)]=rotate(state[x+5*y],rotations[x+5*y])
   for y in range(5):
    for x in range(5): state[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
   state[0]^=rc
 return b''.join(v.to_bytes(8,'little') for v in state)[:32]

def check_digest(data):
 if hashlib.sha256(data).hexdigest()!=DIGEST: raise ValueError('node #94 digest mismatch')

def collect(data, verify_digest=True):
 if verify_digest: check_digest(data)
 im=Image(data); _, fdes=eh_frame_records(data, im.secs)
 ext={f['start']:f for f in fdes}; bodies=[]
 for start,want in BODIES.items():
  f=ext.get(start)
  if f is None or f['end']<=start: raise ValueError('missing FDE')
  raw=im.read(start,f['end']-start,True); digest=hashlib.sha256(raw).hexdigest()
  if digest!=want: raise ValueError('body mismatch')
  bodies.append({'start':hex(start),'end':hex(f['end']),'fde':hex(f['fde']),'sha256':digest,'bytes':raw.hex()})
 rows=[]
 for lane,spec in (('low',LOW),('shared',HIGH)):
  for i,(lea,length,load,call) in enumerate(spec):
   keyva=im.rip(lea); n=im.imm(length); key=im.read(keyva,n,False).decode('ascii')
   row={'lane':lane,'order':i,'key':key,'key_va':hex(keyva),'key_lea':hex(lea),'length_instruction':hex(length),'length':n}
   if load is not None:
    raw=im.read(load,4,True); row['value_instruction']=hex(load); row['value_bytes']=raw.hex(); row['value_offset']=load_offset(raw)
   if call is not None: row['call_site']=hex(call);row['call_target']=hex(im.call(call))
   rows.append(row)
 expected=['initial_height','hardfork','height','tx_index','round','time','prev_time','next_oid','next_lid','next_twap_id','system_nonce','use_system_nonce','mac']
 for lane in ('low','shared'):
  if [r['key'] for r in rows if r['lane']==lane]!=expected: raise ValueError('field sequence mismatch')
 # These are instruction-bound pins connecting old hash closures to new bodies.
 edges=[]
 for site,expected_target in ((0x28194d0,0x2218e60),(0x4ae5790,0x4c633b0)):
  target=im.call(site)
  if target!=expected_target: raise ValueError('closure edge mismatch')
  edges.append({'site':hex(site),'target':hex(target),'bytes':im.read(site,5,True).hex()})
 # Nested low hardfork keys; child of the shared copy is intentionally external.
 nested=[]
 for lea,length,load,call in ((0x2218f9b,0x2218fa2,0x2218f90,0x2218fc4),(0x2218fdf,0x2218fe6,0x2218ffd,0x2219009)):
  addr=im.rip(lea);n=im.imm(length)
  nested.append({'key':im.read(addr,n,False).decode('ascii'),'key_va':hex(addr),'key_lea':hex(lea),'length':n,'value_instruction':hex(load),'value_bytes':im.read(load,4,True).hex(),'value_offset':load_offset(im.read(load,4,True)),'call_site':hex(call),'call_target':hex(im.call(call))})
 if [x['key'] for x in nested]!=['version','round']: raise ValueError('nested fields mismatch')
 branches=[im.branch(va) for va in BRANCHES]
 # Fixed instruction pins, not a linear sweep or a generic x86 decoder.
 pins={0x1520620:'4169cf3961c268',0x1520627:'c1c906',0x152062a:'81f9c6100000',0x1520632:'4169cfd578e926',0x1520639:'c1c903',0x152063c:'81f937894100',0x15204d0:'81f900ca9a3b',0x2756b6e:'488b4c245048890b',0x2756b7d:'48894b08',0x2756fb1:'48c784245003000029000000',0x2819561:'48c78424f000000088000000',0x281956d:'66c78424f80000000100',0x1dfca99:'ff15c12a9703',0x1dfcab1:'be54000000',0x1dfcac9:'ff15992a9703',0x1dfcae8:'e803dd7a00',0x151f253:'41c1fd0d',0x151f25c:'c1eb03',0x151f25f:'81e3ff030000',0x151f271:'488d05fd13d3fe',0x151f389:'be2d000000',0x151f3d8:'be2d000000',0x15204ae:'8b07',0x15204b0:'8b4f04',0x1520562:'be3a000000',0x15205c1:'be3a000000',0x1520618:'4585ff',0x152061b:'7446',0x28194b5:'c744240800040001',0x4ae5775:'c744240800040001',0x2218e8e:'ba0d000000',0x2218f55:'ba02000000',0x25a8f9f:'bd80000000',0x25acc58:'4080e60f',0x25acc5c:'4080ce80',0x25aa806:'83fa20',0x25aa80b:'40b5a0',0x25acc49:'4080e61f',0x25acc4d:'4080cea0',0x25ac0e0:'4881fa00010000',0x25ac100:'84d2',0x25ac12f:'4881fa00000100',0x25ac15f:'48c1e820',0x25ac228:'c60430cc',0x25ac5a7:'c60401cd',0x25ac639:'66c1c608',0x25ac7d7:'c60401ce',0x25ac869:'0fce',0x25aca08:'c60401cf',0x25aca9c:'480fce',0x1e4c9f4:'c60431c0',0x22bd76a:'4080cdc2'}
 for va,expected in pins.items():
  if im.read(va,len(bytes.fromhex(expected)),True).hex()!=expected: raise ValueError('instruction pin mismatch')
 # The threshold and tags below are decoded from the pinned immediates.
 t8=struct.unpack_from('<I',im.read(0x25ac0e0,7,True),3)[0]
 t16=struct.unpack_from('<I',im.read(0x25ac12f,7,True),3)[0]
 shift=im.read(0x25ac15f,4,True)[3]
 tags=[im.read(x,4,True)[3] for x in (0x25ac228,0x25ac5a7,0x25ac7d7,0x25aca08)]
 def encode(n):
  if not 0 <= n < (1 << 64): raise ValueError('u64 outside range')
  if n < 128: return bytes([n])
  for limit,width,tag in ((t8,1,tags[0]),(t16,2,tags[1]),(1<<shift,4,tags[2]),(1<<64,8,tags[3])):
   if n < limit: return bytes([tag])+n.to_bytes(width,'big')
  raise ValueError('unreachable')
 values=(0,127,128,t8-1,t8,t16-1,t16,(1<<shift)-1,1<<shift,(1<<64)-1)
 vectors=[{'value':v,'encoded_hex':encode(v).hex()} for v in values]
 # Resolve the two formatter function slots from ELF RELA records.
 slots={0x576f560:0x151f240,0x576f568:0x15204a0,0x56bda50:0x21e3240,0x5744700:0x4c045a0,0x576e1d8:0x4f59a10,0x576e1e0:0x4f59e40,0x5777790:0x4f59480}
 found={}
 for sec in im.secs:
  if sec['type'] != 4: continue
  if sec['size'] % 24: raise ValueError('bad RELA extent')
  for pos in range(sec['offset'],sec['offset']+sec['size'],24):
   address,info,addend=struct.unpack_from('<QQq',data,pos)
   if address in slots:
    if address in found or info != 8 or addend != slots[address]: raise ValueError('relocation mismatch')
    found[address]=addend
 if found != slots: raise ValueError('missing relocation')
 row_links=[]
 for slot,site,closure in ((0x56bda50,0x21e3244,0x2819480),(0x5744700,0x4c045a4,0x4ae5740)):
  target=im.call(site)
  if target!=closure: raise ValueError('row thunk mismatch')
  row_links.append({'vtable_slot':hex(slot),'thunk':hex(found[slot]),'thunk_call_site':hex(site),'closure_body':hex(target),'bytes':im.read(site,5,True).hex()})
 hash_links=[]
 for site,slot in ((0x281957f,0x576e1d8),(0x28195ab,0x576e1e0),(0x4f59a37,0x5777790),(0x4f59f14,0x5777790)):
  if im.slot_call(site)!=slot: raise ValueError('hash slot mismatch')
  hash_links.append({'site':hex(site),'slot':hex(slot),'target':hex(found[slot]),'bytes':im.read(site,6,True).hex()})
 first_table=im.rip(0x2756b76)
 job_count=struct.unpack_from('<I',im.read(0x2756fb1,12,True),8)[0]
 if first_table!=0x56bda38 or job_count!=41: raise ValueError('builder row mismatch')
 table_ref=im.rip(0x4f598f0)
 if table_ref!=0x7d04c8: raise ValueError('hash table reference mismatch')
 # Symbolic successful prefix, not target execution; stops before time fields.
 mapbase=im.read(0x25a8f9f,5,True)[1]
 strbase=im.read(0x25aa80b,3,True)[2]
 outer_count=im.imm(0x2218e8e);inner_count=im.imm(0x2218f55)
 def name(value):
  raw=value.encode('ascii')
  if len(raw)>=32: raise ValueError('name too long for fixstr')
  return bytes([strbase | len(raw)])+raw
 prefix=(bytes([mapbase | outer_count])+name(rows[0]['key'])+encode(0)+name(rows[1]['key'])+
         bytes([mapbase | inner_count])+name(nested[0]['key'])+encode(1)+name(nested[1]['key'])+encode(2)+
         name(rows[2]['key'])+encode(3)+name(rows[3]['key'])+bytes([im.read(0x1e4c9f4,4,True)[3]])+name(rows[4]['key'])+encode(4))
 # Classify the formatter's three nonzero fractional branches using the
 # actual multiply/rotate/compare operands; descriptor output is not decoded.
 def word32(site,offset): return struct.unpack_from('<I',im.read(site,offset+4,True),offset)[0]
 mul3=word32(0x1520620,3);mul6=word32(0x1520632,3)
 rotate3=im.read(0x1520627,3,True)[2];rotate6=im.read(0x1520639,3,True)[2]
 limit3=word32(0x152062a,2);limit6=word32(0x152063c,2);nano_limit=word32(0x15204d0,2)
 def ror32(v,n): return ((v>>n)|(v<<(32-n))) & 0xffffffff
 descriptors=[]
 for site in (0x152068c,0x15206ba,0x152065a):
  addr=im.rip(site);raw=im.read(addr,10,False)
  if raw[:6]!=bytes.fromhex('012ec3200000'): raise ValueError('formatter descriptor mismatch')
  descriptors.append({'lea_site':hex(site),'va':hex(addr),'bytes':raw.hex(),'tag':struct.unpack_from('<I',raw,6)[0]})
 if [x['tag'] for x in descriptors]!=[0x369,0x669,0x969]: raise ValueError('formatter descriptor tags mismatch')
 fraction=[]
 for n in (0,1,999,1000,1000000,nano_limit-1):
  branch='zero' if n==0 else ('descriptor_3' if ror32((n*mul3)&0xffffffff,rotate3)<=limit3 else ('descriptor_6' if ror32((n*mul6)&0xffffffff,rotate6)<=limit6 else 'descriptor_9'))
  fraction.append({'nanosecond_word':n,'branch':branch})
 # One tightly bounded time example: raw date with year bits 1970 and
 # table index 2, followed by zero time words. This is a static model of the
 # inspected path, without claiming a valid source-language constructor.
 date_word=(1970<<13)|16; index=(date_word>>3)&0x3ff
 table=im.rip(0x151f271); correction=im.read(table+index,1,False)[0]
 adjusted=index+correction; year=date_word>>13
 timestamp=(f'{year:04d}-{adjusted>>6:02d}-{(adjusted & 63)>>1:02d}T00:00:00').encode('ascii')
 if timestamp != b'1970-01-01T00:00:00' or index!=2 or correction!=64: raise ValueError('unexpected time example')
 # Complete example follows the same successful named-mode low lane. Its
 # selected time words are zero and its scalar inputs are explicitly stated.
 complete=(prefix+name(rows[5]['key'])+name(timestamp.decode('ascii'))+
           name(rows[6]['key'])+name(timestamp.decode('ascii'))+
           b''.join(name(rows[i]['key'])+encode(0) for i in range(7,11))+
           name(rows[11]['key'])+bytes([im.read(0x22bd76a,4,True)[3]])+
           name(rows[12]['key'])+encode(0))
 rc_bytes=im.read(0x7d04c8,192,False)
 if hashlib.sha256(rc_bytes).hexdigest()!='f8e6964adffc257265537256d21e93496a17b9271dc5d64f40869eeeaaff6fbb': raise ValueError('round constant table mismatch')
 rc=list(struct.unpack('<24Q',rc_bytes))
 if rc[0]!=1 or rc[1]!=0x8082 or rc[-1]!=0x8000000080008008: raise ValueError('round constants mismatch')
 symbolic_digest=keccak256(complete,rc).hex()
 absent=name(rows[3]['key'])+im.read(0x1e4c9f4,4,True)[3:4]
 false_bool=name(rows[11]['key'])+bytes([im.read(0x22bd76a,4,True)[3]])
 if complete.count(absent)!=1 or complete.count(false_bool)!=1: raise ValueError('fixture substitution ambiguity')
 present=complete.replace(absent,name(rows[3]['key'])+encode(5),1)
 present=present.replace(false_bool,name(rows[11]['key'])+bytes([im.read(0x22bd76a,4,True)[3] | 1]),1)
 time_example={'date_word':date_word,'date_table_va':hex(table),'date_table_index':index,'table_byte':correction,'time_words':[0,0],'text':timestamp.decode('ascii'),'format_slots':{hex(k):hex(slots[k]) for k in (0x576f560,0x576f568)}}
 return {'target_sha256':DIGEST,'coordinate_system':'ELF virtual address; FDE ends exclusive', 'bodies':bodies,'low_builder_row_zero':{'table_lea':hex(0x2756b76),'table':hex(first_table),'job_count':job_count,'count_site':hex(0x2756fb1)},'hash_links':hash_links,'hash_table_lea':{'site':hex(0x4f598f0),'target':hex(table_ref),'bytes':im.read(0x4f598f0,7,True).hex()},'row_vtable_links':row_links,'closure_edges':edges,'fields':rows,'low_hardfork_fields':nested,'selected_conditional_branches':branches,'instruction_pins':[{'va':hex(a),'bytes':v} for a,v in pins.items()],'unsigned_integer_vectors':vectors,'fraction_branch_descriptors':descriptors,'fraction_branch_examples':fraction,'time_example':time_example,'symbolic_present_low':{'assumptions':'same as symbolic_complete_low except tx_index tag=1 with value=5 and use_system_nonce=1','bytes':present.hex(),'keccak256':keccak256(present,rc).hex()},'symbolic_complete_low':{'assumptions':'named mode and successful writes; both time words zero; date word in time_example; prior prefix inputs; next_oid, next_lid, next_twap_id, system_nonce, use_system_nonce and mac are zero','bytes':complete.hex(),'keccak256':symbolic_digest,'round_constant_table_va':hex(0x7d04c8)},'symbolic_prefix':{'assumptions':'named mode, successful writes; initial_height=0, version=1, hardfork.round=2, height=3, tx_index tag != 1, round=4','bytes':prefix.hex()}}

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 result=collect(TARGET.read_bytes());a.out.mkdir(parents=True,exist_ok=True)
 (a.out/'records.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
if __name__=='__main__': main()
