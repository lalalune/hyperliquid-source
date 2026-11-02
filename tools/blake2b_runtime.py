#!/usr/bin/env python3
"""Static node94 precompile construction, address lookup and dispatch evidence.

No captured execution. Byte-shape decoding is deliberately limited to pinned
FDE bodies; it is not a general x86 disassembler. Names are analyst inferences.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PACKET = 'RE-021-blake2b-runtime-94'
# Query coordinates, not boundaries inferred from neighbouring starts.
FUNCTIONS = {
    0x4e9d240: 'six-way registry selector',
    0x4e99110: 'registry mode 0 base constructor',
    0x4e98c70: 'registry mode 1 constructor',
    0x4e99650: 'registry mode 2 constructor adding address 09',
    0x4e99f30: 'registry mode 3 constructor',
    0x4e99af0: 'registry mode 4 constructor',
    0x4e9a310: 'registry mode 5 constructor',
    0x4e9bc40: 'address to precompile insert or replace',
    0x4e9bec0: 'address set insertion',
    0x4e9c0b0: 'move vector records into map',
    0x4e9db00: 'four-record array iterator materialization',
    0x4e9d920: 'one-record array iterator materialization',
    0x4e9de00: 'seven-record array iterator materialization',
    0x4e94fc0: 'precompile map clone',
    0x4e94e80: 'address set clone',
    0x4e8cfd0: 'owned-map lookup returning value pointer',
    0x4e8a250: '20-byte address hash',
    0x4ea2d70: 'mutable precompile enum dispatch',
    0x4ea2df0: 'shared precompile enum dispatch',
    0x4e6fef0: 'runtime call-frame preparation and precompile result',
    0x4e6f690: 'checkpoint rollback entry',
    0x4e79b00: 'reverse journal traversal',
    0x4e76bc0: 'mode 5 borrowed-registry adapter',
    0x276e2d0: 'mode 2 borrowed-registry adapter',
}
MODES = [0x4e99110,0x4e98c70,0x4e99650,0x4e99f30,0x4e99af0,0x4e9a310]
TABLES = [(0x7c50b8,6,'registry mode',0x4e9d240),
          (0x7c53d0,4,'mutable enum tag',0x4ea2d70),
          (0x7c53e0,4,'shared enum tag',0x4ea2df0)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        if digest(data) != TARGET_SHA256:
            raise ValueError('target digest mismatch')
        self.data = data
        self.sections = sections(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        self.relocations = {}
        sec = self.section('.rela.dyn')
        if sec['size'] % 24:
            raise ValueError('RELA extent')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            if va in self.relocations:
                raise ValueError('duplicate relocation')
            self.relocations[va] = (info, addend, off)

    def section(self, name):
        found = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        if len(found) != 1:
            raise ValueError('missing or ambiguous file section')
        return found[0]

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise ValueError('invalid byte range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('range not uniquely file backed')
        off = matches[0]['offset'] + va - matches[0]['address']
        if off + size > len(self.data):
            raise ValueError('range outside file')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        found = self.fdes.get(start, [])
        if len(found) != 1:
            raise ValueError('missing or ambiguous FDE')
        f = found[0]
        sec = self.section('.text')
        if not sec['address'] <= start < f['end'] <= sec['address'] + sec['size']:
            raise ValueError('FDE outside executable bytes')
        return f

    def relative_target(self, slot):
        info, addend, _ = self.relocations[slot]
        if info != 8:
            raise ValueError('expected symbol-free RELATIVE relocation')
        return addend

    def expect(self, va, expected):
        raw = self.read(va, len(bytes.fromhex(expected)))
        if raw.hex() != expected:
            raise ValueError(f'byte predicate failed at {va:#x}')
        return raw


# Exact opcode families observed in the selected, SHA-256 authenticated corpus.
# ModRM/SIB are used only to find byte extents and RIP displacement fields.
# There is no execution, register simulation, or inferred instruction boundary
# from objdump text. Unsupported byte shapes fail closed.
def one(raw,i):
 start=i; pre=[]
 while raw[i] in (0x66,0xf0,0xf2,0xf3,0x2e,0x64,0x65) or 0x40<=raw[i]<=0x4f:
  pre.append(raw[i]);i+=1
  if i-start>=15:raise ValueError('prefix')
 rex=next((p for p in pre[::-1] if 0x40<=p<=0x4f),0)
 op=raw[i];i+=1; imm=0; mr=False; kind='plain';rel=None; rip=None
 if op in (0xe8,0xe9):imm=4;kind='call' if op==0xe8 else 'jump';rel=i
 elif op==0xeb or 0x70<=op<=0x7f:imm=1;kind='jump' if op==0xeb else 'jcc';rel=i
 elif op==0xc3:kind='return'
 elif op==0xcc:kind='int3'
 elif op in range(0x50,0x60) or op in (0x90,0x98,0x99,0x9c,0x9d):pass
 elif 0xb0<=op<=0xb7:imm=1
 elif 0xb8<=op<=0xbf:imm=8 if rex&8 else 2 if 0x66 in pre else 4
 elif op in (0xa8,0x04,0x0c,0x24,0x2c,0x34,0x3c):imm=1
 elif op in (0xa9,0x05,0x0d,0x25,0x2d,0x35,0x3d,0x68):imm=2 if 0x66 in pre else 4
 elif op==0x6a:imm=1
 elif op==0x0f:
  op2=raw[i];i+=1
  if 0x80<=op2<=0x8f:imm=4;kind='jcc';rel=i
  elif op2==0x0b:kind='trap'
  elif 0xc8<=op2<=0xcf:pass
  elif op2 in (0x10,0x11,0x1f,0x28,0x29,0x2e,0x2f,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x6c,0x6d,0x6e,0x6f,0x74,0x75,0x76,0x7e,0x7f,0xaf,0xb0,0xb1,0xb6,0xb7,0xbc,0xbd,0xbe,0xbf,0xc1,0xd4,0xd6,0xd7,0xdb,0xdf,0xeb,0xef,0xf3,0xfb) or 0x40<=op2<=0x4f or 0x90<=op2<=0x9f:mr=True
  elif op2 in (0x70,0x71,0x72,0x73,0xba,0xc2,0xc4,0xc5,0xc6):mr=True;imm=1
  else:raise ValueError('0f '+hex(op2))
 elif op in (0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b,0x10,0x11,0x12,0x13,0x18,0x19,0x1a,0x1b,0x20,0x21,0x22,0x23,0x28,0x29,0x2a,0x2b,0x30,0x31,0x32,0x33,0x38,0x39,0x3a,0x3b,0x63,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,0x8f,0xd0,0xd1,0xd2,0xd3,0xfe,0xff):mr=True
 elif op in (0x80,0x82,0x83,0xc0,0xc1,0xc6,0x6b):mr=True;imm=1
 elif op in (0x81,0xc7,0x69):mr=True;imm=2 if 0x66 in pre else 4
 elif op in (0xf6,0xf7):mr=True
 else:raise ValueError(hex(op))
 if mr:
  modrm=raw[i];i+=1;mod=modrm>>6;reg=(modrm>>3)&7;rm=modrm&7
  if op==0xff and reg in (2,4):kind='indirect-call' if reg==2 else 'indirect-jump'
  if op in (0xf6,0xf7) and reg==0:imm=1 if op==0xf6 else 2 if 0x66 in pre else 4
  if mod!=3 and rm==4:
   sib=raw[i];i+=1
   if mod==0 and sib&7==5:i+=4
  elif mod==0 and rm==5:rip=i;i+=4
  if mod==1:i+=1
  elif mod==2:i+=4
 end=i+imm
 if end>len(raw) or end-start>15:raise ValueError('length')
 row={'size':end-start,'kind':kind}
 if rel is not None:row['relative']=end+int.from_bytes(raw[rel:end],'little',signed=True)
 if rip is not None:row['rip']=end+struct.unpack_from('<i',raw,rip)[0]
 if kind=='jcc':row['condition']=(op2 if op==0x0f else op)&15
 return row

def walk(raw):
 out=[];i=0
 while i<len(raw):
  try:r=one(raw,i)
  except (ValueError,IndexError) as e:raise ValueError(f'{i:#x}: {raw[i:i+16].hex()} {e}') from e
  out.append((i,r));i+=r['size']
 return out

# These are analyst-selected semantic windows. Endpoints must be decoded
# instruction boundaries. Their labels are interpretations, never decoded names.
WINDOWS = [
 (0x4e9d240,0x4e9d254,'selector: byte enum indexes relative-offset table; no local bounds check'),
 (0x4e99661,0x4e99681,'mode2: return existing cached pointer or acquire mode1 parent'),
 (0x4e99681,0x4e996f6,'mode2: clone map and address set, preserving separate hash seeds'),
 (0x4e99782,0x4e997af,'mode2: three 16-byte reads copy entire address09 record, including tag'),
 (0x4e997af,0x4e997f4,'mode2: four records copied into array iterator and materialized'),
 (0x4e99840,0x4e9986d,'mode2: add each 20-byte address to companion set'),
 (0x4e998be,0x4e998f0,'mode2: move records into key/value map'),
 (0x4e99931,0x4e99945,'mode2: allocate registry object; null goes to allocation failure'),
 (0x4e99983,0x4e999ea,'mode2: publish with cmpxchg; losing thread destroys private allocation'),
 (0x4e99a34,0x4e99a46,'mode2: allocation failure is nonreturning'),
 (0x4e9c0ee,0x4e9c12a,'extend: source stride, key field, value field and insert call'),
 (0x4e9c12a,0x4e9c1a6,'extend: absent-old-value sentinel or release replaced owned payload'),
 (0x4e9bc54,0x4e9bca0,'insert: hash 20-byte key with process and map seed words'),
 (0x4e9bca0,0x4e9bcab,'insert: zero growth budget first reserves capacity'),
 (0x4e9bcd8,0x4e9bd47,'insert: control fingerprint and full key equality'),
 (0x4e9bd50,0x4e9bd91,'insert: remember first special slot; stop at empty or advance probe'),
 (0x4e9bd91,0x4e9bdb8,'insert: existing key returns old 24-byte value then overwrites value'),
 (0x4e9bdb8,0x4e9be4e,'insert: special-slot resolution, mirrored control write, counters, 48-byte record'),
 (0x4e8cfd0,0x4e8d033,'lookup: empty-count exit, seeded hash, fingerprint and bucket mask'),
 (0x4e8d052,0x4e8d0bd,'lookup: compare fingerprint candidates, then all 20 key bytes'),
 (0x4e8d0c0,0x4e8d0f4,'lookup: empty-control miss, triangular group progression, value pointer or null'),
 (0x4e6ff0b,0x4e6ff5f,'runtime: depth guard returns status byte 11 and unchanged gas'),
 (0x4e6ffe5,0x4e70051,'runtime: increment depth and append an empty journal frame'),
 (0x4e70051,0x4e700a7,'runtime: transfer variant and scheme gates; owned/shared registry split'),
 (0x4e706a1,0x4e70785,'runtime shared registry: hash-group lookup, empty miss and full key comparison'),
 (0x4e70909,0x4e7096d,'runtime: selected value pointer passed to shared/mutable/trait dispatcher'),
 (0x4ea2df0,0x4ea2e1b,'shared dispatch tag0: load function at value+8 and call with input/gas'),
 (0x4ea2d70,0x4ea2d9b,'mutable dispatch tag0: load function at value+8 and call with input/gas'),
 (0x4ea2e40,0x4ea2e9b,'shared dispatch tag3: construct fatal error instead of calling mutable trait'),
 (0x4e7096d,0x4e70a6b,'runtime result: successful gas subtraction, underflow, fatal and ordinary errors'),
 (0x4e70adb,0x4e70b12,'runtime result: success decrements depth; failure calls checkpoint rollback'),
 (0x4e70b12,0x4e70b57,'runtime result: copy output, gas, status and return tag to caller'),
 (0x4e6f6a9,0x4e6f727,'rollback: depth decrement and reverse-journal traversal to saved frame'),
 (0x4e6f727,0x4e6f767,'rollback: restore log length and saved journal length'),
 (0x4e76bc0,0x4e76be0,'borrowed adapter: mode5 cache pointer packed with variant zero'),
 (0x276e2d0,0x276e2f0,'borrowed adapter: mode2 cache pointer packed with variant zero'),
]
# These table ranges are finite research queries; enum validity outside them is
# not established. Every decoded target must be a boundary in its owner FDE.
TABLES += [(0x7c355c,4,'runtime account-code variant clone',0x4e6fef0),
           (0x7c356c,4,'runtime account-code scheme6',0x4e6fef0),
           (0x7c357c,4,'runtime account-code other scheme',0x4e6fef0),
           (0x7c3630,11,'rollback journal record tag',0x4e79b00),
           (0x7c365c,4,'rollback account-code drop tag',0x4e79b00),
           (0x7c4a7c,4,'map clone value tag',0x4e94fc0)]


LAYOUT_SPECS = [
 (0x4e9c0ee,'488d4830',3,1,False,'source record stride'),
 (0x4e9c0fd,'0f104018',3,1,False,'source key offset'),
 (0x4e9c0f6,'8b4828',2,1,False,'source key tail offset'),
 (0x4e9c10e,'488b4010',3,1,False,'source third value word offset'),
 (0x4e9bc80,'488b4620',3,1,False,'map hash seed offset'),
 (0x4e8cfd0,'48837f1800',3,1,False,'map element count offset'),
 (0x4e8d02f,'488b7f08',3,1,False,'map bucket mask offset'),
 (0x4e8d028,'48c1e939',3,1,False,'fingerprint right shift'),
 (0x4e8d045,'4c8d40d0',3,1,True,'bucket zero offset from controls'),
 (0x4e8d0e4,'488d41e8',3,1,True,'value offset from bucket end'),
 (0x4e8d0d1,'4883c210',3,1,False,'probe group width'),
 (0x4e8d0d5,'4983c110',3,1,False,'probe step increment'),
 (0x4e9bd32,'81fdffff0000',2,4,False,'key equality byte mask'),
 (0x4e99931,'bf50000000',1,4,False,'registry allocation size'),
 (0x4e6ff0b,'4881bea800000000040000',7,4,False,'depth guard unsigned upper bound'),
 (0x4e6ff07,'4c8b7a58',3,1,False,'call-input gas offset'),
 (0x4e6ff6a,'f3410f6f4660',5,1,False,'call-input address offset'),
 (0x4e70076,'498d4628',3,1,False,'call-input bytes object offset'),
 (0x4e7007e,'4883bde000000000',3,4,False,'context registry discriminant offset'),
 (0x4e706a1,'4c8bade8000000',3,4,False,'context borrowed registry pointer offset'),
 (0x4e70911,'4c8b85d8000000',3,4,False,'context environment pointer offset'),
 (0x4e709e1,'41b053',2,1,False,'gas underflow status byte'),
 (0x4e70a0e,'41b002',2,1,False,'successful precompile status byte'),
 (0x4e70a1e,'41b860000000',2,4,False,'ordinary precompile error status byte'),
 (0x4e70adb,'4180f805',3,1,False,'status threshold for rollback'),
 (0x4e79bdd,'486bc958',3,1,False,'journal record stride'),
]


JUMP_BINDINGS = {
    0x4e9d252:0x7c50b8, 0x4ea2d89:0x7c53d0, 0x4ea2e08:0x7c53e0,
    0x4e70880:0x7c355c, 0x4e70d24:0x7c356c, 0x4e70d7f:0x7c357c,
    0x4e79c33:0x7c3630, 0x4e79e5c:0x7c3630, 0x4e7a385:0x7c365c,
    0x4e951f1:0x7c4a7c,
}
JOURNAL_EFFECTS = [
    'set account flag bit 10h; missing account is a panic boundary',
    'restore account flag bit 1; add four-limb amount; subtract peer unless both keys equal',
    'clear account flag bit 2; saved fork predicate exempts address 03',
    'add four-limb amount to first account and subtract it from second',
    'checked decrement of account word at +60h',
    'clear account flag bit 0; mark storage entries with byte 1; zero account word at +60h',
    'restore four saved words at storage value +20h through +38h',
    'set storage value byte at +40h to 1',
    'restore nonzero transient value via insertion boundary; zero value via removal boundary',
    'replace account code hash from constants; drop code payload and set code tag 4',
    'exit current journal-record loop and release frame buffer',
]
WINDOWS += [
    (0x4e79c40,0x4e79c85,'journal tag0: lookup and flag update'),
    (0x4e79ce9,0x4e79d85,'journal tag1: flag and balance reversal, same-key exception'),
    (0x4e79daa,0x4e79df5,'journal tag2: fork/address03 exception and flag clear'),
    (0x4e79eb0,0x4e79f1c,'journal tag3: reverse balance transfer with carry/borrow'),
    (0x4e7a020,0x4e7a042,'journal tag4: checked nonce-shaped word decrement'),
    (0x4e79f50,0x4e79fed,'journal tag5: account and storage flags, zero nonce-shaped word'),
    (0x4e7a240,0x4e7a283,'journal tag6: restore storage value words'),
    (0x4e7a2e0,0x4e7a30f,'journal tag7: storage warmness-shaped flag write'),
    (0x4e7a0b9,0x4e7a1d4,'journal tag8: zero/nonzero transient storage reversal'),
    (0x4e7a340,0x4e7a3fc,'journal tag9: code hash constants, drop payload, empty tag'),
]


def validated_walk(raw):
    rows = walk(raw)
    boundaries = {i for i, _ in rows}
    for _, row in rows:
        if 'relative' in row and 0 <= row['relative'] < len(raw):
            if row['relative'] not in boundaries:
                raise ValueError('branch target is not an instruction boundary')
    return rows


def static_records(im):
    result = []
    for base in range(0x574ee68, 0x574f258, 48):
        raw = im.read(base,48)
        tag = struct.unpack_from('<Q',raw)[0]
        addr = raw[24:44]
        if tag not in (0,1) or addr[:19] != bytes(19):
            raise ValueError('static record layout predicate')
        result.append({'base':base,'tag':tag,'key':addr.hex(),
                       'callback_slot':base+8,'callback':im.relative_target(base+8),
                       'raw':raw.hex()})
    return result


def jump_table(im, base, count, boundaries):
    raw=im.read(base,count*4)
    values=struct.unpack('<'+'i'*count,raw)
    result=[]
    for index, displacement in enumerate(values):
        target=base+displacement
        if target not in boundaries:
            raise ValueError('table target is not an owner instruction boundary')
        result.append((index,base+index*4,raw[index*4:index*4+4].hex(),target))
    return result


def selector_rows(im, decoded):
    """Bind each decoded selector entry to its cache address and tail call."""
    start = 0x4e9d240
    by_offset = dict(decoded)
    boundaries = {start + off for off in by_offset}
    result = []
    for index, _, _, target in jump_table(im, 0x7c50b8, len(MODES), boundaries):
        off = target - start
        load = by_offset[off]
        raw = im.read(target, load['size'])
        if raw[:3] != bytes.fromhex('488d3d') or 'rip' not in load:
            raise ValueError('selector cache-address load')
        tail_site = target + load['size']
        tail = by_offset[tail_site - start]
        if tail['kind'] != 'jump' or 'relative' not in tail:
            raise ValueError('selector constructor tail jump')
        constructor = start + tail['relative']
        if constructor != MODES[index]:
            raise ValueError('selector mode/constructor mismatch')
        result.append([index, hex(target), hex(start + load['rip']),
                       hex(tail_site), hex(constructor)])
    return result


def address_hash(key, seed, secret0, secret1):
    """Inferred arithmetic of 4e8a250. Seeds are parameters, NOT runtime captures."""
    if len(key)!=20 or any(type(x) is not int or not 0<=x<1<<64
                           for x in (seed,secret0,secret1)):
        raise ValueError('hash input domain')
    def word(i):return int.from_bytes(key[i:i+8],'little')
    def fold(a,b):
        p=a*b
        return (p & ((1<<64)-1)) ^ (p>>64)
    x=fold(word(8)^secret1,word(12)^secret0)
    y=fold(word(0)^seed,word(4)^secret0)
    return fold(x^y^20,secret0)


def probe_lookup(controls, keys, hash_value, key, count):
    """Pure model of observed lookup. Returns bucket and trace, not native proof.

    Canonical fixture table: power-of-two capacity >= 16, FF empty and 80 deleted;
    wrapped controls model the native duplicated control tail. Malformed fixture
    tables without an empty control are rejected rather than allowed to hang.
    """
    n=len(controls)
    if n<16 or n&(n-1) or len(key)!=20 or len(keys)!=n or not 0<=count<=n:
        raise ValueError('table domain')
    if any(c not in (0x80,0xff) and not 0<=c<0x80 for c in controls):
        raise ValueError('control domain')
    if not 0<=hash_value<1<<64 or any(k is not None and len(k)!=20 for k in keys):
        raise ValueError('key/hash domain')
    if 0xff not in controls:
        raise ValueError('fixture requires terminating empty control')
    if count==0:return None, [{'reason':'zero_count'}]
    mask=n-1;pos=hash_value&mask;fingerprint=hash_value>>57;step=0;trace=[]
    for _ in range(n):
        candidates=[(pos+i)&mask for i in range(16)
                    if controls[(pos+i)&mask]==fingerprint]
        row={'group_start':pos,'candidates':candidates,'equal':None}
        for bucket in candidates:
            if keys[bucket]==key:
                row['equal']=bucket;trace.append(row);return bucket,trace
        trace.append(row)
        if any(controls[(pos+i)&mask]==0xff for i in range(16)):
            row['reason']='empty_control';return None,trace
        step+=16;pos=(pos+step)&mask
    raise ValueError('probe fixture did not terminate')


def fixtures(im):
    # Adversarial abstract tables use real key bytes and arbitrary explicit seeds.
    key=im.read(0x574f0c0,20)
    seed=0x0123456789abcdef;s0=0xfedcba9876543211;s1=0x9e3779b97f4a7c15
    hv=address_hash(key,seed,s0,s1);fp=hv>>57;first=hv&63
    cases=[]
    def run(name,controls,keys,count,query=key):
        hit,trace=probe_lookup(controls,keys,hv,query,count)
        cases.append({'name':name,'hash':hex(hv),'query':query.hex(),
                      'controls':bytes(controls).hex(),
                      'keys':{str(i):k.hex() for i,k in enumerate(keys) if k is not None},
                      'count':count,'hit':hit,'trace':trace})
    c=[255]*64;k=[None]*64
    run('zero_count',c,k,0)
    c[first]=fp;k[first]=key;run('hit_at_initial_bucket',c,k,1)
    wrong=bytearray(key);wrong[0]=1;k[first]=bytes(wrong)
    run('same_fingerprint_wrong_prefix',c,k,1)
    wrong=bytearray(key);wrong[-1]^=1;k[first]=bytes(wrong)
    run('same_fingerprint_wrong_last_byte',c,k,1)
    c=[128]*64;k=[None]*64
    c[(first+48)&63]=255;c[(first+17)&63]=fp;k[(first+17)&63]=key
    run('deleted_controls_do_not_terminate_second_group_hit',c,k,1)
    c=[128]*64;k=[None]*64
    c[(first+48)&63]=fp;k[(first+48)&63]=key;c[(first+49)&63]=255
    run('triangular_third_group_hit_before_empty',c,k,1)
    c=[255]*64;k=[None]*64
    c[(first+15)&63]=fp;k[(first+15)&63]=key
    run('candidate_match_precedes_empty_test',c,k,1)
    return {'kind':'independent instruction-derived model; no captured execution',
            'seed':hex(seed),'process_words':[hex(s0),hex(s1)],'cases':cases}


def result_route(gas, output_word0, output_word1, output_word2, output_word4):
    """Inferred branch decisions at runtime result merge, without pointer access.

    Fatal returns bypass the local checkpoint action. Allocation/destruction and
    upper-level fatal-error handling are deliberately not modeled here.
    """
    words=(gas,output_word0,output_word1,output_word2,output_word4)
    if any(type(x) is not int or not 0<=x<1<<64 for x in words):
        raise ValueError('result word domain')
    if output_word0:
        if output_word4<=gas:
            return {'status':2,'remaining_word':gas-output_word4,'checkpoint':'decrement_depth'}
        return {'status':0x53,'remaining_word':gas,'checkpoint':'rollback'}
    if output_word1&1:
        return {'status':None,'remaining_word':None,'checkpoint':'fatal_return_no_local_action'}
    return {'status':0x53 if output_word2==1<<63 else 0x60,
            'remaining_word':gas,'checkpoint':'rollback'}


def result_fixtures():
    # Boundary choices are synthetic; status constants are pinned in layout operands.
    inputs=[('success_zero',0,1,0,0,0),('success_exact_cost',12,1,0,0,12),
            ('success_remaining',13,1,0,0,12),('success_max_gas',(1<<64)-1,1,0,0,1),
            ('gas_underflow',11,1,0,0,12),('gas_underflow_max_cost',0,1,0,0,(1<<64)-1),
            ('ordinary_error_minimum',12,0,0,1<<63,0),
            ('ordinary_error_minimum_plus_one',12,0,0,(1<<63)+1,0),
            ('ordinary_error_minimum_plus_two',12,0,0,(1<<63)+2,0),
            ('fatal_error',12,0,1,39,0)]
    return {'kind':'independent instruction-derived branch model; no captured execution',
            'cases':[{'name':r[0],'input_words':list(r[1:]),'decision':result_route(*r[1:])}
                     for r in inputs]}


def json_bytes(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')


def tsv_bytes(header,rows):
    stream=io.StringIO(newline='');w=csv.writer(stream,delimiter='\t',lineterminator='\n')
    w.writerow(header);w.writerows(rows)
    return stream.getvalue().encode('ascii')


def collect(im):
    function_rows=[];instructions=[];edges=[];riprefs=[];bodies=[];decoded={};by_va={}
    fde_rows=[]
    for start,name in sorted(FUNCTIONS.items()):
        f=im.fde(start);raw=im.read(start,f['end']-start);rows=validated_walk(raw)
        decoded[start]=rows
        function_rows.append([hex(start),hex(f['end']),len(raw),hex(im.offset(start,len(raw))),
                              hex(f['fde']),hex(f['cie']),hex(f['lsda']) if f['lsda'] else '',
                              digest(raw),len(rows),name])
        bodies.append({'start':hex(start),'end':hex(f['end']),'bytes':raw.hex()})
        for field in ('fde','cie'):
            addr=f[field];size=struct.unpack('<I',im.read(addr,4))[0]+4
            fde_rows.append({'function':hex(start),'kind':field,'va':hex(addr),
                             'bytes':im.read(addr,size).hex()})
        for off,row in rows:
            va=start+off;insn=raw[off:off+row['size']];by_va[va]=(start,row,insn)
            instructions.append([hex(start),hex(va),insn.hex(),row['kind']])
            if 'rip' in row:
                dest=start+row['rip'];rela=im.relocations.get(dest)
                riprefs.append([hex(start),hex(va),insn.hex(),hex(dest),
                                hex(rela[0]) if rela else '',hex(rela[1]) if rela else ''])
            if row['kind']!='plain':
                dest=start+row['relative'] if 'relative' in row else None
                slot=None;rela=None
                if row['kind'].startswith('indirect') and 'rip' in row:
                    slot=start+row['rip'];rela=im.relocations.get(slot)
                    if rela and rela[0]==8:dest=rela[1]
                edges.append([hex(start),hex(va),row['kind'],
                              row.get('condition',''),hex(va+row['size']),
                              hex(dest) if dest is not None else '',hex(slot) if slot else '',
                              hex(rela[0]) if rela else '',
                              'packet_entry' if dest in FUNCTIONS else
                              'same_FDE' if dest is not None and start<=dest<f['end'] else
                              'external_boundary' if dest is not None else 'dynamic_or_terminal'])
    windows=[]
    for start,end,label in WINDOWS:
        if start not in by_va:
            raise ValueError(f'window start not a decoded boundary: {start:#x}')
        owner=by_va[start][0]
        if end!=im.fde(owner)['end'] and (end not in by_va or by_va[end][0]!=owner):
            raise ValueError(f'window end not an owner boundary: {end:#x}')
        windows.append([hex(owner),hex(start),hex(end),im.read(start,end-start).hex(),label])
    table_rows=[]
    for base,count,label,owner in TABLES:
        bounds={owner+i for i,_ in decoded[owner]}
        for index,slot,raw,dest in jump_table(im,base,count,bounds):
            table_rows.append([label,hex(owner),hex(base),index,hex(slot),raw,hex(dest)])
    table_edges=[]
    for site,table in sorted(JUMP_BINDINGS.items()):
        owner,row,_=by_va[site]
        if row['kind']!='indirect-jump':
            raise ValueError('table binding is not an indirect jump')
        for r in table_rows:
            if int(r[2],16)==table:
                if int(r[1],16)!=owner:
                    raise ValueError('table owner mismatch')
                table_edges.append([hex(site),r[2],r[3],r[6]])
    records=static_records(im)
    # Construction lineage from direct parent calls and decoded RIP references.
    # Static data overlap identifies the source record, not dynamic reachability.
    lineage=[];members={}
    for mode,start in enumerate(MODES):
        parent=[int(e[5],16) for e in edges if e[0]==hex(start) and e[2]=='call'
                and e[5] and int(e[5],16) in MODES]
        if len(parent)>1:raise ValueError('ambiguous parent')
        refs=[int(r[3],16) for r in riprefs if r[0]==hex(start)]
        additions=[r for r in records if any(r['base']<=v<r['base']+48 for v in refs)]
        current=dict(members[parent[0]]) if parent else {}
        for r in additions:current[r['key']]=r['callback']
        members[start]=current
        lineage.append({'mode':mode,'constructor':hex(start),'parent':hex(parent[0]) if parent else None,
                        'source_records':[hex(r['base']) for r in additions],
                        'derived_members':{k:hex(v) for k,v in sorted(current.items())},
                        'qualification':'membership inferred from clone/extend semantics; not a runtime table dump'})
    # Trace byte-for-byte construction of the newly added BLAKE record.
    copies=[];reconstructed=bytearray(48)
    for site,destination in [(0x4e997a0,0),(0x4e99791,16),(0x4e99782,32)]:
        owner,row,raw=by_va[site]
        if raw[:3]!=bytes.fromhex('0f1005') or 'rip' not in row:
            raise ValueError('expected fixed movups RIP load')
        source=owner+row['rip'];piece=im.read(source,16)
        reconstructed[destination:destination+16]=piece
        copies.append([hex(site),raw.hex(),hex(source),destination,piece.hex()])
    if bytes(reconstructed)!=im.read(0x574f0a8,48):
        raise ValueError('BLAKE record copy mismatch')
    if im.relative_target(0x574f0b0)!=0x4e9d2a0:
        raise ValueError('prior wrapper endpoint changed')
    layouts=[]
    for site,pattern,offset,width,signed,meaning in LAYOUT_SPECS:
        raw=im.expect(site,pattern)
        if site not in by_va or len(raw)!=by_va[site][1]['size']:
            raise ValueError('layout anchor does not cover exactly one instruction')
        value=int.from_bytes(raw[offset:offset+width],'little',signed=signed)
        layouts.append([hex(site),raw.hex(),offset,width,signed,value,meaning])
    relocations=[]
    used_slots={int(r[3],16) for r in riprefs if r[4]}
    used_slots.update(r['callback_slot'] for r in records)
    for slot in sorted(used_slots):
        info,addend,off=im.relocations[slot]
        relocations.append([hex(slot),hex(info),hex(addend),hex(off),im.data[off:off+24].hex()])
    journal=[]
    for r in table_rows:
        if r[0]=='rollback journal record tag':
            journal.append([r[3],r[6],JOURNAL_EFFECTS[r[3]]])
    results={
        'registry-selector.tsv':tsv_bytes(['mode','entry_va','cache_va','tail_jump_va','constructor_va'],selector_rows(im,decoded[0x4e9d240])),
        'table-edges.tsv':tsv_bytes(['jump_site_va','table_va','index','target_va'],table_edges),
        'relocations.tsv':tsv_bytes(['slot_va','r_info','addend','entry_file_offset','entry_bytes'],relocations),
        'journal-effects.tsv':tsv_bytes(['tag','target_va','inferred_effect_and_boundary'],journal),
        'layout-operands.tsv':tsv_bytes(['site_va','instruction_bytes','operand_offset','operand_bytes','signed','value','inferred_meaning'],layouts),
        'functions.tsv':tsv_bytes(['start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','sha256','instruction_count','inferred_role'],function_rows),
        'instructions.tsv':tsv_bytes(['function_va','instruction_va','bytes','byte_shape_kind'],instructions),
        'control-flow.tsv':tsv_bytes(['function_va','site_va','kind','condition_code','next_va','target_va','slot_va','rela_info','target_scope'],edges),
        'rip-references.tsv':tsv_bytes(['function_va','site_va','bytes','target_va','rela_info','rela_addend'],riprefs),
        'semantic-windows.tsv':tsv_bytes(['function_va','start_va','end_va','bytes','inferred_meaning'],windows),
        'jump-tables.tsv':tsv_bytes(['inferred_domain','owner_va','table_va','index','slot_va','bytes','target_va'],table_rows),
        'constructor-copies.tsv':tsv_bytes(['site_va','instruction_bytes','source_va','record_offset','source_bytes'],copies),
        'static-records.json':json_bytes(records),
        'registry-lineage.json':json_bytes(lineage),
        'function-bytes.json':json_bytes(bodies),
        'unwind-records.json':json_bytes(fde_rows),
        'lookup-cases.json':json_bytes(fixtures(im)),
        'result-cases.json':json_bytes(result_fixtures()),
    }
    summary={'target':'node94','sha256':TARGET_SHA256,'coordinate_system':'ELF virtual address; offsets are explicit',
             'function_count':len(function_rows),'instruction_count':len(instructions),
             'selected_code_bytes':sum(r[2] for r in function_rows),'control_records':len(edges),
             'jump_table_entries':len(table_rows),'semantic_windows':len(windows),
             'static_records':len(records),'lookup_model_cases':len(fixtures(im)['cases']),
             'result_model_cases':len(result_fixtures()['cases']),
             'mode_membership_counts':[len(x['derived_members']) for x in lineage],
             'mode_contains_09':[('00'*19+'09') in x['derived_members'] for x in lineage],
             'closure':{
                 'unique_external_resolved_targets':len({e[5] for e in edges if e[8]=='external_boundary'}),
                 'dynamic_call_sites':sum(e[2]=='indirect-call' and not e[5] for e in edges),
                 'table_bound_indirect_jumps':len(JUMP_BINDINGS),
                 'unbound_indirect_jumps':sum(e[2]=='indirect-jump' and int(e[1],16) not in JUMP_BINDINGS for e in edges),
                 'normalization_masks':[],
                 'whole_ELF_identity':False,
                 'helper_semantics_closed':False,
                 'runtime_seed_and_vtable_contents_captured':False},
             'captured_execution':False,'rust_implementation':'not yet implemented',
             'gate_requested':False,
             'limits':['FDE coverage is only the selected corpus, not whole-function census.',
                       'Dynamic call targets, allocation, hash-seed initialization and unwind landing relationships remain external.',
                       'Tables have mapped finite domains; no claim about invalid enum inputs.',
                       'Independent lookup fixtures are semantic checks, not target execution or runtime-state evidence.',
                       'Wrapper and compression bodies are prior work and excluded from new body coverage.']}
    results['summary.json']=json_bytes(summary)
    return results


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    im=Image((ROOT/'artifacts/node/94/hl-node').read_bytes())
    outputs=collect(im)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,data in sorted(outputs.items()):
        (args.out/name).write_bytes(data)
    print(f'{PACKET}: wrote {len(outputs)} deterministic evidence files')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
