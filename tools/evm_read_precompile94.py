#!/usr/bin/env python3
"""Extract a digest-bound revision-9 EVM read/call corridor from ELF bytes.

No captured execution or external program. The x86 shape reader below is
adapted from the MIT RE-021 runtime packet; it is not a general disassembler.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'tools') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
# Selection seeds only. Actual half-open ends are decoded from FDE records.
FUNCTIONS = {
    0x2446ac0: 'bounded EVM read engine builder and result extraction',
    0x244f550: 'postexecution result copy adapter',
    0x244f570: 'postexecution context reset callback',
    0x2461390: 'revision to handler construction',
    0x25134e0: 'executor, registry publication and call handling',
    0x25b6b20: 'copy registry addresses to an independent set',
    0x276d490: 'call adapter and input cleanup',
    0x2786dd0: 'account cache and backing account access',
    0x2788500: 'account and code hydration',
    0x2789db0: 'call frame preparation, lookup and result handling',
    0x2790e20: 'preexecution callback constructor for revisions 9 and 10',
    0x2798a10: 'execution callback constructor for revisions 9 and 10',
}
BODY_PINS = {
    0x2446ac0: (3760, '282d9b76e7837d22b8a2a3fad7215664e540e91b682fd16fb35e2ee8276c553a'),
    0x244f550: (23, '642eb99fad591cef240e7cafa9dff311bade5c2328748b279ea0ab4b87cd5d22'),
    0x244f570: (323, '0de47d8c2a7096fad9a5d044f8f1985a23121efd1353e4ad7de6a7e4cedd837a'),
    0x2461390: (14387, '427bc72a7860ece9d432688b1d85508da9c142789d32279d698b91856d0ef9d0'),
    0x25134e0: (8121, '02d30f8f2651644df2503a69250f316f2eaee9b04ea7df5e653c0bc6cc54ce30'),
    0x25b6b20: (374, '006ac8eb20073279827b8c7695bba5d7f2a2aca2d2038766d80803181a77168c'),
    0x276d490: (119, '7271719bd7657eef461acd1ba41e6f87616bb31e8182e94d58140ec38ac8c5f9'),
    0x2786dd0: (1674, '73ab4d48bfff55b09b0bb80e6b85599420ca4e889848e72d912d136ba906bdb9'),
    0x2788500: (527, 'adfa83aad4c417e53d2573ec2a034c3aac90b5c1f256b319e8503c9e88d7c519'),
    0x2789db0: (5714, 'da3c9936ded8de05bd7cc58e6c8544b59d4234851c89c80db6bad6880039cb7a'),
    0x2790e20: (438, '25a6af6ef63fda05e3030d27e07503f13e023c5064e03427654850933f6cbcb2'),
    0x2798a10: (1381, 'cc3d45435ac4db165435161ce46f65f0867a483556381596fd8b3c64aba8a6e2'),
}

# New observations are selected instruction-aligned ranges, not claimed CFGs.
WINDOWS = [
 (0x2446afe,0x2446b08,'builder arguments and output'),
 (0x2446cac,0x2446cc0,'builder passes revision byte to constructor'),
 (0x2446cc0,0x2446cf6,'builder copies context and handler into adjacent engine storage'),
 (0x2446d12,0x2446d1a,'builder retains input address pointer'),
 (0x244706a,0x244708c,'builder writes call variant and full twenty-byte address'),
 (0x2447094,0x24470ae,'builder copies engine into execution buffer'),
 (0x2447145,0x244715d,'builder copies complete handler into engine buffer'),
 (0x2447196,0x24472af,'builder preparation callbacks and tag gates'),
 (0x24472af,0x24472c7,'builder invokes executor after preparation'),
 (0x24472c7,0x244736e,'builder postprocessing callbacks and copied executor result'),
 (0x244736e,0x244739e,'builder result sentinel and error variant gate'),
 (0x244739e,0x24473c8,'builder non-sentinel result and sign branch'),
 (0x2447548,0x24475a5,'builder sentinel cleanup and zero output tag'),
 (0x244f550,0x244f567,'postexecution copies a 144-byte result'),
 (0x244f57e,0x244f5b7,'context reset takes saved tag and writes tag five'),
 (0x244f64f,0x244f688,'context reset callbacks and replacement'),
 (0x24613b3,0x24613d1,'revision limit and relative switch'),
 (0x2461a4f,0x2461aa9,'raw 9 and 10 branch constructs preexecution callbacks'),
 (0x2461bd6,0x2461c60,'raw 9 and 10 postexecution callback objects'),
 (0x2461c60,0x2461c79,'raw 9 and 10 branch constructs execution callbacks and records canonical 9'),
 (0x2463442,0x24634c4,'common handler publication, first callback blocks'),
 (0x24634c4,0x246352f,'common handler publication, execution callback block'),
 (0x2790e31,0x2790e45,'preexecution callback allocation null branch'),
 (0x2790ef9,0x2790f26,'preexecution callback pairs returned'),
 (0x2798a10,0x2798a4a,'execution callback allocation setup'),
 (0x2798cc3,0x2798cd7,'execution callback slot 2 vtable'),
 (0x25134fd,0x2513570,'preparation gate and registry factory invocation'),
 (0x2513570,0x2513605,'copy registry keys into warm set and publish registry'),
 (0x2513698,0x2513708,'call-type gate and callback invocation'),
 (0x2513708,0x2513747,'executor checks callback outer result word'),
 (0x2513747,0x2513781,'preparation error return'),
 (0x2513959,0x251396a,'callback error payload forwarded to sentinel return'),
 (0x25b6b2e,0x25b6b3d,'registry set conversion ownership branch'),
 (0x25b6c25,0x25b6c3d,'borrowed registry set copy'),
 (0x276d490,0x276d4a5,'selected execution adapter calls frame implementation'),
 (0x2786de1,0x2786e0e,'account cache lookup and miss'),
 (0x2786e29,0x2786e6b,'backing account read and result tag'),
 (0x2786fbd,0x2786fe1,'cache-hit flag clear'),
 (0x27871ea,0x2787220,'address set lookup and account cache insertion probe'),
 (0x2787233,0x278728a,'account cache control and 208-byte entry address'),
 (0x2787331,0x27873ad,'account cache flags, journal tag zero and success result'),
 (0x2788513,0x278853b,'account hydration status and code variant'),
 (0x278853b,0x278856a,'empty-code hash comparison'),
 (0x2788585,0x27885cb,'backing code read and default path'),
 (0x2788603,0x278863f,'default code initialization'),
 (0x278863f,0x27886a6,'loaded code publication and return tag'),
 (0x2789dc1,0x2789e1f,'call depth guard and failure status'),
 (0x2789e22,0x2789e5f,'destination account/code load and error branch'),
 (0x2789e5f,0x2789eb3,'account tag three loads another twenty-byte key before checkpoint'),
 (0x2789eb3,0x2789f1f,'checkpoint depth increment and empty journal frame'),
 (0x2789f1f,0x2789f44,'input value tag and scheme gate'),
 (0x2789f44,0x2789ff0,'ordinary account code path after lookup miss or scheme bypass'),
 (0x278a089,0x278a0a2,'zero versus nonzero four-limb input value'),
 (0x278a1de,0x278a217,'account touch record and flag update'),
 (0x278a217,0x278a284,'four-limb debit and underflow exits'),
 (0x278a2e7,0x278a385,'recipient touch, four-limb credit and overflow exits'),
 (0x278a3b8,0x278a426,'successful transfer journal record'),
 (0x278a42b,0x278a44d,'owned versus borrowed map selection'),
 (0x278a44d,0x278a559,'owned-map fingerprint, full key comparison and miss probe'),
 (0x278a75b,0x278a879,'borrowed-map fingerprint, full key comparison and miss probe'),
 (0x278a879,0x278a8ce,'owned-map value tags and indirect dispatch'),
 (0x278a8d3,0x278a92f,'transfer failure calls checkpoint rollback'),
 (0x278a92f,0x278a952,'borrowed-map hit and shared dispatcher'),
 (0x278adc7,0x278ae08,'owned-map hit and mutable or contextual dispatcher'),
 (0x278ae08,0x278aefd,'precompile result classification and cost underflow'),
 (0x278af77,0x278afae,'success depth decrement or checkpoint rollback'),
]
SLOTS = (0x56a7020, 0x56a7050, 0x56bece8, 0x56c1298, 0x5774588, 0x5774e30, 0x5774e38)
TABLE_VA = 0x3e28b8
TABLE_SHA256 = '78a581accc007efeb033a65311db229dd7ff1a5c61021265e3ef719c86febfd2'
CODE_HASH_HEX = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'


def require(value, message):
    if not value:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        require(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')
        self.data = data
        self.secs, index = unwind_index(data)
        self.cies, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        self.index = {}
        for row in index:
            self.index.setdefault(row['start'], []).append(row)
        rel = self.section('.rela.dyn')
        require(rel['type'] == 4 and rel['size'] % 24 == 0, 'malformed RELA section')
        self.relocs = {}
        for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            require(slot not in self.relocs, 'duplicate relocation slot')
            self.relocs[slot] = (info, addend, off)

    def section(self, name):
        found = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(found) == 1, 'missing or ambiguous file section')
        return found[0]

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0, 'invalid byte range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'address is not uniquely file backed')
        sec = matches[0]
        off = sec['offset'] + va - sec['address']
        require(off >= 0 and off + size <= len(self.data), 'range exceeds input')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def body(self, start):
        rows = self.fdes.get(start, [])
        idx = self.index.get(start, [])
        require(len(rows) == len(idx) == 1, 'missing or duplicate FDE/index')
        fde = rows[0]
        require(fde['fde'] == idx[0]['fde'], 'FDE and unwind index disagree')
        text = self.section('.text')
        require(text['flags'] & 4 and text['address'] <= start < fde['end'] <= text['address'] + text['size'],
                'FDE outside file-backed executable text')
        raw = self.read(start, fde['end'] - start)
        require((len(raw), hashlib.sha256(raw).hexdigest()) == BODY_PINS[start], 'selected body pin mismatch')
        return fde, raw

    def relocation(self, slot):
        require(slot in self.relocs, 'missing relocation')
        info, addend, off = self.relocs[slot]
        require(info == 8, 'not a symbol-free R_X86_64_RELATIVE relocation')
        return info, addend, off


# Restricted opcode-shape matching, adapted from the MIT RE-021 runtime packet.
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



# Synthetic predicates for negative controls; they do not execute target bytes.
def mix_address(key, seed0, seed1, map_seed):
    require(isinstance(key, bytes) and len(key) == 20, 'address must have twenty bytes')
    mask = (1 << 64) - 1
    require(all(type(x) is int and 0 <= x <= mask for x in (seed0, seed1, map_seed)), 'invalid seed')
    u = lambda i: int.from_bytes(key[i:i+8], 'little')
    first = (u(8) ^ seed1) * (u(12) ^ seed0)
    second = (u(0) ^ map_seed) * (u(4) ^ seed0)
    folded = (first & mask) ^ (first >> 64) ^ (second & mask) ^ (second >> 64) ^ 20
    final = folded * seed0
    return ((final & mask) ^ (final >> 64)) & mask


def probe(controls, keys, hash_word, query, count):
    require(isinstance(controls, bytes) and len(controls) >= 16 and len(controls) & (len(controls)-1) == 0,
            'invalid synthetic control array')
    require(isinstance(query, bytes) and len(query) == 20, 'invalid synthetic query')
    require(type(count) is int and 0 <= count <= len(controls), 'invalid synthetic count')
    require(type(hash_word) is int and 0 <= hash_word < (1 << 64), 'invalid synthetic hash')
    if not count:
        return None
    mask = len(controls)-1
    fingerprint = hash_word >> 57
    start, stride, seen = hash_word & mask, 0, set()
    while start not in seen:
        seen.add(start)
        group = [(start + i) & mask for i in range(16)]
        for i in group:
            if controls[i] == fingerprint:
                require(i in keys and isinstance(keys[i], bytes) and len(keys[i]) == 20,
                        'invalid synthetic candidate')
                if keys[i] == query:
                    return i
        if any(controls[i] == 0xff for i in group):
            return None
        stride += 16
        start = (start + stride) & mask
    raise ValueError('invalid synthetic table: probe never reached an empty control')


def result_policy(first, second, third, gas, cost):
    maximum = (1 << 64) - 1
    require(all(type(x) is int and 0 <= x <= maximum for x in (first, second, third, gas, cost)),
            'invalid synthetic result word')
    if first:
        return ('success', 2, gas-cost) if cost <= gas else ('rollback', 0x53, None)
    if second & 1:
        return ('fatal', 4, None)
    return ('rollback', 0x53 if third == (1 << 63) else 0x60, None)


def tsv(headers, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode()


def h(value):
    return '' if value is None else hex(value)


def decoded_body(img, start):
    fde, raw = img.body(start)
    rows = []
    for off, item in walk(raw):
        row = dict(item)
        row['va'] = start + off
        row['bytes'] = raw[off:off + row['size']].hex()
        if 'relative' in row:
            row['target'] = start + row.pop('relative')
        if 'rip' in row:
            row['rip'] += start
        rows.append(row)
    boundaries = {r['va'] for r in rows} | {fde['end']}
    require(sum(r['size'] for r in rows) == len(raw), 'incomplete byte traversal')
    for row in rows:
        if row['kind'] in ('jcc', 'jump') and start <= row['target'] < fde['end']:
            require(row['target'] in boundaries, 'internal branch lands inside a byte shape')
    return fde, raw, rows


def read_record(img, va):
    first = img.read(va, 4)
    length = struct.unpack('<I', first)[0]
    require(0 < length < 0xffffffff, 'invalid frame record length')
    raw = img.read(va, length + 4)
    return {'va': h(va), 'file_offset': h(img.offset(va, len(raw))), 'bytes': raw.hex()}


def cases(img, code_rows, code_end):
    raw = img.read(TABLE_VA, 20 * 4)
    require(hashlib.sha256(raw).hexdigest() == TABLE_SHA256, 'revision table pin mismatch')
    by_va = {r['va']: r for r in code_rows}
    result = []
    for number in range(20):
        delta = struct.unpack_from('<i', raw, number * 4)[0]
        destination = TABLE_VA + delta
        require(destination in by_va, 'switch entry does not land on decoded boundary')
        suffix = [r for r in code_rows if destination <= r['va'] < code_end]
        markers = [r for r in suffix if r['bytes'].startswith('c68398110000')]
        require(bool(markers), 'missing canonical revision store')
        store = markers[0]
        require(len(bytes.fromhex(store['bytes'])) == 7, 'invalid canonical revision store')
        require(not any(r['kind'] in ('jump', 'indirect-jump') for r in suffix if r['va'] < store['va']),
                'nonlinear revision case before store')
        call_rows = [r for r in suffix if r['va'] < store['va'] and r['kind'] == 'call']
        require(bool(call_rows), 'missing case callback constructor call')
        result.append({'raw': number, 'entry_va': destination, 'entry_raw': raw[4*number:4*number+4].hex(),
                       'canonical': bytes.fromhex(store['bytes'])[-1], 'store': store['va'],
                       'final_constructor_call': call_rows[-1]['va'], 'constructor': call_rows[-1]['target']})
    require(result[9]['entry_va'] == result[10]['entry_va'], 'revision 9 and 10 no longer share a case')
    require(result[9]['canonical'] == 9 and result[9]['constructor'] == 0x2798a10,
            'revision 9 callback binding changed')
    guard = by_va[0x24613b7]
    require(by_va[0x24613b3]['bytes'] == '4080fe13' and guard['kind'] == 'jcc'
            and guard['condition'] == 7 and guard['target'] in by_va, 'revision bound changed')
    dest = guard['target']
    suffix = [r for r in code_rows if dest <= r['va'] < code_end]
    stores = [r for r in suffix if r['bytes'].startswith('c68398110000')]
    require(bool(stores) and bytes.fromhex(stores[0]['bytes'])[-1] == 255, 'default revision changed')
    require(not any(r['kind'] in ('jump', 'indirect-jump') for r in suffix if r['va'] < stores[0]['va']),
            'nonlinear default revision before store')
    result.append({'raw': '20..255', 'entry_va': dest, 'entry_raw': '', 'canonical': 255,
                   'store': stores[0]['va'], 'final_constructor_call': None, 'constructor': None})
    return result


def allocation_checks(all_rows):
    """Match argument, indirect call, null test and branch in three bounded paths."""
    groups = ((0x2461390, 0x2461a4f, 0x2461c79, 6, 'revision-9 case'),
              (0x2790e20, 0x2790e20, 0x2790fd6, 4, 'preexecution constructor'),
              (0x2798a10, 0x2798a10, 0x2798f75, 11, 'execution constructor'))
    found = []
    for owner, lo, hi, expected, label in groups:
        rows = all_rows[owner]
        boundaries = {row['va'] for row in rows}
        group = []
        for i, call in enumerate(rows):
            if not (lo <= call['va'] < hi and call['kind'] == 'indirect-call'
                    and call.get('rip') == 0x576dfd8):
                continue
            require(i > 0 and i + 2 < len(rows), 'incomplete allocation check')
            arg, test, branch = rows[i-1], rows[i+1], rows[i+2]
            immediate = bytes.fromhex(arg['bytes'])
            require(len(immediate) == 5 and immediate[0] == 0xbf,
                    'unsupported allocation argument')
            require(test['bytes'] == '4885c0' and branch['kind'] == 'jcc'
                    and branch.get('condition') == 4 and branch.get('target') in boundaries,
                    'allocation null check changed')
            group.append((h(owner), label, h(arg['va']), int.from_bytes(immediate[1:], 'little'),
                          h(call['va']), call['bytes'], h(test['va']), h(branch['va']),
                          branch['bytes'], h(branch['target'])))
        require(len(group) == expected, 'allocation check count changed')
        found.extend(group)
    return found


def code_hash_constants(img):
    """Read the two file-backed chunks compared by the code-hydration branch."""
    parts = [(0x206160, img.read(0x206160, 16)),
             (0x204be0, img.read(0x204be0, 16))]
    require(b''.join(raw for _, raw in parts).hex() == CODE_HASH_HEX,
            'code hash constant changed')
    return [(index, h(va), h(img.offset(va, len(raw))), len(raw), raw.hex())
            for index, (va, raw) in enumerate(parts)]


def copy_symbol_relocation(img):
    """Resolve the one symbol-bearing GOT relocation used by the copy adapter."""
    slot = 0x576dfe0
    require(slot in img.relocs, 'missing copy relocation')
    info, addend, rel_off = img.relocs[slot]
    index, kind = info >> 32, info & 0xffffffff
    require(kind == 6 and addend == 0, 'copy relocation type changed')
    sym, strings = img.section('.dynsym'), img.section('.dynstr')
    require(sym['type'] == 11 and strings['type'] == 3 and sym['size'] % 24 == 0
            and index < sym['size'] // 24, 'invalid dynamic symbol index')
    sym_off = sym['offset'] + index * 24
    raw_sym = img.data[sym_off:sym_off+24]
    require(len(raw_sym) == 24, 'truncated dynamic symbol')
    name_off = struct.unpack_from('<I', raw_sym)[0]
    require(name_off < strings['size'], 'dynamic symbol name outside table')
    name_start = strings['offset'] + name_off
    name_end = img.data.find(b'\0', name_start, strings['offset'] + strings['size'])
    require(name_end >= name_start, 'unterminated dynamic symbol')
    name = bytes(img.data[name_start:name_end])
    require(name == b'memcpy', 'copy relocation symbol changed')
    return (h(slot), h(info), index, kind, addend, h(rel_off),
            img.data[rel_off:rel_off+24].hex(), h(sym_off), raw_sym.hex(),
            h(name_start), name.decode('ascii'))



# LSDA call-site extraction adapted from the MIT RE-021 installation packet.
# The common ULEB reader is reused; action and type-table semantics are opaque.
def exception_sites(img, start, rows):
    fde = img.fdes[start][0]
    if fde['lsda'] is None:
        return [], None
    va = fde['lsda']
    section = img.section('.gcc_except_table')
    off = img.offset(va, 1)
    end = section['offset'] + section['size']
    require(section['offset'] <= off < end, 'LSDA outside exception section')
    data = img.data
    pos = off
    require(data[pos] == 0xff, 'unsupported LSDA landing-pad base')
    pos += 1
    require(pos < end, 'truncated LSDA type encoding')
    encoding = data[pos]
    pos += 1
    type_base = None
    if encoding != 0xff:
        require(encoding == 0x9b, 'unsupported LSDA type encoding')
        delta, pos = uleb(data, pos, end)
        type_base = pos + delta
        require(type_base <= end, 'LSDA type base outside section')
    require(pos < end and data[pos] == 1, 'unsupported LSDA call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, end)
    limit = pos + length
    require(limit <= end and (type_base is None or limit <= type_base), 'LSDA call-site table outside bounds')
    boundaries = {row['va'] for row in rows} | {fde['end']}
    result, previous = [], 0
    while pos < limit:
        record = pos
        lo, pos = uleb(data, pos, limit)
        size, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        require(lo >= previous and start+lo+size <= fde['end'], 'invalid exception interval')
        previous = lo+size
        require(start+lo in boundaries and start+lo+size in boundaries, 'exception interval splits byte shape')
        require(not landing or start+landing in boundaries-{fde['end']}, 'invalid landing pad')
        result.append((h(start), h(va), h(record), h(start+lo), size, h(start+lo+size),
                       h(start+landing) if landing else '', action, data[record:pos].hex()))
    raw_end = type_base if type_base is not None else limit
    return result, {'owner': h(start), 'lsda': h(va), 'type_encoding':encoding,
                    'type_table_file_offset':h(type_base), 'call_table_end_file_offset':h(limit),
                    'raw_prefix':data[off:raw_end].hex(),
                    'scope':'Call-site edges only; action chains and catch types unresolved.'}


def generate(img):
    all_rows = {}
    funcs = []
    unwind = []
    instruction_rows = []
    control_rows = []
    exception_rows = []
    exception_headers = []
    for start in sorted(FUNCTIONS):
        fde, raw, rows = decoded_body(img, start)
        all_rows[start] = rows
        sites, header = exception_sites(img, start, rows)
        exception_rows.extend(sites)
        if header is not None:
            exception_headers.append(header)
        funcs.append((h(start), h(fde['end']), len(raw), h(img.offset(start, len(raw))),
                      h(fde['fde']), h(fde['cie']), h(fde['lsda']),
                      hashlib.sha256(raw).hexdigest(), len(rows), FUNCTIONS[start]))
        unwind.append({'start':h(start), 'end':h(fde['end']), 'fde':read_record(img, fde['fde']),
                       'cie':read_record(img, fde['cie']), 'lsda':h(fde['lsda'])})
        for row in rows:
            target = row.get('target')
            rip = row.get('rip')
            instruction_rows.append((h(start), h(row['va']), row['bytes'], row['kind'], h(target), h(rip)))
            if row['kind'] not in ('plain', 'int3'):
                next_va = row['va'] + row['size']
                fall = next_va if row['kind'] in ('call', 'indirect-call', 'jcc') else None
                resolved = None
                if rip in img.relocs and img.relocs[rip][0] == 8:
                    resolved = img.relocs[rip][1]
                control_rows.append((h(start), h(row['va']), row['kind'], row['bytes'], h(target),
                                     h(fall), h(rip), h(resolved),
                                     '' if 'condition' not in row else row['condition']))

    index = {row['va']: row for rows in all_rows.values() for row in rows}
    boundaries = set(index)
    for start in FUNCTIONS:
        boundaries.add(img.fdes[start][0]['end'])
    window_rows = []
    for start, end, label in WINDOWS:
        owners = [(owner, img.fdes[owner][0]) for owner in FUNCTIONS
                  if owner <= start < end <= img.fdes[owner][0]['end']]
        require(len(owners) == 1 and start in boundaries and end in boundaries, f'window not on selected boundaries: {start:#x}..{end:#x}')
        require(all(v in index for v in (start,)), 'missing window start')
        raw = img.read(start, end-start)
        window_rows.append((h(owners[0][0]), h(start), h(end), len(raw), raw.hex(), label))

    relocs = []
    for slot in SLOTS:
        info, addend, offset = img.relocation(slot)
        relocs.append((h(slot), info, h(addend), h(offset), img.data[offset:offset+24].hex()))
    expected_relocs = {0x56a7020:0x244f550, 0x56a7050:0x244f570,
                       0x56bece8:0x276e2d0, 0x56c1298:0x276d490,
                       0x5774588:0x4e91cb0, 0x5774e30:0x4ea2df0, 0x5774e38:0x4ea2d70}
    require(all(img.relocation(k)[1] == v for k, v in expected_relocs.items()), 'vtable or dispatch relocation mismatch')
    revision = cases(img, all_rows[0x2461390], img.fdes[0x2461390][0]['end'])
    allocations = allocation_checks(all_rows)
    code_hash = code_hash_constants(img)
    copy_symbol = copy_symbol_relocation(img)
    # Fixed byte/target assertions provide corruption controls for the critical edges.
    direct = {0x2446cbb:0x2461390, 0x24472c2:0x25134e0,
              0x2461aa4:0x2790e20, 0x2461c68:0x2798a10,
              0x251357b:0x25b6b20, 0x276d4a0:0x2789db0,
              0x2788516:0x2786dd0, 0x2789e4a:0x2788500}
    for site, target in direct.items():
        require(site in index and index[site]['kind'] == 'call' and index[site]['target'] == target,
                'direct call binding changed')
    require(index[0x2798ccc].get('rip') == 0x56c1270, 'revision-9 callback table changed')
    require(index[0x2798cd3]['bytes'] == '48894b28', 'callback field store changed')
    require(index[0x2461c3a].get('rip') == 0x56a6ff8 and
            index[0x2461c51].get('rip') == 0x56a7028, 'postexecution vtables changed')
    require(index[0x244f554]['bytes'] == 'ba90000000' and
            index[0x244f559]['bytes'] == '4889ce' and
            index[0x244f55c].get('rip') == 0x576dfe0, 'result copy binding changed')
    require(index[0x251356d]['bytes'] == 'ff5128' and index[0x2513704]['bytes'] == '41ff5028',
            'executor virtual calls changed')
    require(index[0x278a94c].get('rip') == 0x5774e30 and index[0x278ade4].get('rip') == 0x5774e38,
            'lookup dispatch slots changed')
    require(index[0x2788547].get('rip') == 0x204be0 and index[0x278854f].get('rip') == 0x206160,
            'code hash comparison references changed')
    require(img.read(0x2461c6d,7).hex() == 'c6839811000009', 'canonical revision store changed')

    # The revision table reports code-derived cases; constructor addends outside
    # 9/10 are omitted to avoid claiming unrelated branches.
    case_rows = [(r['raw'], h(TABLE_VA + 4*r['raw']) if type(r['raw']) is int else '', r['entry_raw'], h(r['entry_va']),
                  r['canonical'], h(r['store']), h(r['final_constructor_call']) if r['raw'] in (9,10) else '',
                  h(r['constructor']) if r['raw'] in (9,10) else '') for r in revision]
    metrics = {'target_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual addresses; FDE ends exclusive',
               'selected_fdes': len(funcs), 'selected_code_bytes': sum(row[2] for row in funcs),
               'decoded_shapes': len(instruction_rows), 'control_records': len(control_rows),
               'semantic_windows': len(window_rows), 'revision_table_entries': len(revision)-1, 'revision_default_ranges': 1,
               'relative_relocations': len(relocs), 'exception_sites': len(exception_rows),
               'allocation_null_checks': len(allocations), 'code_hash_chunks': len(code_hash),
               'symbol_relocations': 1,
               'limits': 'Linear byte shapes are not a reachable CFG. External helpers, alternate dynamic calls and complete EVM behavior are not closed.'}
    return {
      'functions.tsv': tsv(('start_va','end_va','size','file_offset','fde_va','cie_va','lsda_va','sha256','byte_shapes','role'), funcs),
      'instructions.tsv': tsv(('owner','va','bytes','shape','direct_target','rip_target'), instruction_rows),
      'control-flow.tsv': tsv(('owner','site','shape','bytes','direct_target','fallthrough','rip_slot','relative_addend','condition_code'), control_rows),
      'semantic-windows.tsv': tsv(('owner','start_va','end_va','size','bytes','inferred_role'), window_rows),
      'revision-cases.tsv': tsv(('raw_revision','entry_va','signed_delta_bytes','destination','canonical_revision','store_va','constructor_call','constructor'), case_rows),
      'allocation-checks.tsv': tsv(('owner','phase','argument_site','size','call_site','call_bytes','test_site','branch_site','branch_bytes','null_target'), allocations),
      'code-hash-constants.tsv': tsv(('order','va','file_offset','size','bytes'), code_hash),
      'copy-symbol-relocation.tsv': tsv(('slot_va','r_info','symbol_index','r_type','addend','rela_file_offset','rela_bytes','symbol_file_offset','symbol_bytes','name_file_offset','name'), [copy_symbol]),
      'relocations.tsv': tsv(('slot_va','r_info','addend','file_offset','rela_bytes'), relocs),
      'exception-sites.tsv': tsv(('owner','lsda_va','record_file_offset','start_va','size','end_va','landing_pad','action','record_bytes'), exception_rows),
      'exception-prefixes.json': (json.dumps(exception_headers,indent=2,sort_keys=True)+'\n').encode(),
      'unwind-records.json': (json.dumps(unwind,indent=2,sort_keys=True)+'\n').encode(),
      'summary.json': (json.dumps(metrics,indent=2,sort_keys=True)+'\n').encode(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    img = Image(TARGET.read_bytes())
    files = generate(img)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        (args.out / name).write_bytes(data)


if __name__ == '__main__':
    main()
