#!/usr/bin/env python3
"""Extract selected node #94 ABCI JSON state reader decisions, without executing it."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = (0x315ba80, 0x3182d10, 0x2fe5290, 0x36ee4d0, 0x3094420)
TABLE = 0x57b1fc

class EvidenceError(ValueError):
    pass

def check(ok, msg):
    if not ok:
        raise EvidenceError(msg)

def authenticated(data):
    check(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')

def mapping(secs, va, size):
    check(va >= 0 and size > 0, 'invalid address or length')
    choices = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    check(len(choices) == 1, 'address is not uniquely file-backed')
    s = choices[0]
    return s['offset'] + va - s['address']

def read(data, secs, va, size):
    off = mapping(secs, va, size)
    return data[off:off + size]

def rel32(code, at, prefix):
    check(code[at:at + len(prefix)] == prefix, 'unexpected instruction opcode')
    end = at + len(prefix) + 4
    check(end <= len(code), 'truncated relative instruction')
    return end + struct.unpack_from('<i', code, at + len(prefix))[0]

def pin(data, secs, va, expected):
    raw = bytes.fromhex(expected)
    actual = read(data, secs, va, len(raw))
    check(actual == raw, 'instruction pin changed')
    return {'va': hex(va), 'file_offset': hex(mapping(secs, va, len(raw))), 'bytes': actual.hex()}

def extract_rows(data, secs, lo, hi):
    default = read(data,secs,0x36eef0a,2)
    check(default[0] == 0xb1, 'unknown classifier tag opcode changed')
    unknown_tag = default[1]
    check(unknown_tag == 60, 'unknown classifier tag changed')
    table = read(data, secs, TABLE, (unknown_tag+1)*4)
    result = []
    for tag in range(unknown_tag+1):
        arm = TABLE + struct.unpack_from('<i', table, 4 * tag)[0]
        check(lo <= arm < hi, 'dispatch target outside visitor extent')
        raw = read(data, secs, arm, 32)
        if tag == unknown_tag:
            check(raw.startswith(bytes.fromhex('498b4e20498b46284839c8')), 'unknown arm changed')
            result.append({'tag': tag, 'arm_va': hex(arm), 'arm_prefix': raw[:11].hex(), 'role': 'unknown field arm'})
            continue
        matches = [i for i in range(2, 26) if raw[i:i+2] in (b'\x0f\x84', b'\x0f\x85')]
        check(len(matches) == 1, 'duplicate-guard conditional is ambiguous')
        j = matches[0]
        check(raw[0] in (0x80, 0x83, 0x48, 0x4c), 'unexpected guard')
        dest = arm + rel32(raw, j, raw[j:j+2])
        check(lo <= dest < hi, 'duplicate target outside visitor extent')
        handler = read(data, secs, dest, 120)
        check(handler[:3] == b'\x48\x8d\x05', 'duplicate label LEA changed')
        label_va = dest + rel32(handler, 0, b'\x48\x8d\x05')
        check(handler[7:15] == bytes.fromhex('4889842430140000'), 'duplicate label pointer store changed')
        check(handler[15:23] == bytes.fromhex('48c7842438140000'), 'duplicate label length store changed')
        diag = handler.find(bytes.fromhex('488d3d'))
        check(diag >= 27 and dest + rel32(handler, diag, b'\x48\x8d\x3d') == 0x1e0fd5,
              'duplicate diagnostic reference changed')
        n = struct.unpack_from('<I', handler, 23)[0]
        check(0 < n <= 64, 'invalid field label length')
        name = read(data, secs, label_va, n).decode('ascii')
        check(all(c.islower() or c.isdigit() or c == '_' for c in name), 'unexpected field label')
        result.append({'tag': tag, 'arm_va': hex(arm), 'guard_bytes': raw[:j].hex(),
                       'conditional_va': hex(arm+j), 'conditional_bytes': raw[j:j+6].hex(),
                       'duplicate_va': hex(dest), 'duplicate_prefix': handler[:27].hex(), 'diagnostic_site': hex(dest+diag),
                       'label_va': hex(label_va), 'label_file_offset': hex(mapping(secs,label_va,n)),
                       'label': name, 'length': n})
    check(len({r['label'] for r in result[:-1]}) == unknown_tag, 'duplicate field labels')
    return result

def missing_field_sites(data, secs, start, end, rows):
    body = read(data,secs,start,end-start)
    labels = {r['label']:r['tag'] for r in rows[:-1]}
    out=[]; p=0
    while True:
        p=body.find(b'\x48\x8d\x3d',p)
        if p<0: break
        if p+7<=len(body) and start+rel32(body,p,b'\x48\x8d\x3d')==0x1df8f3:
            hits=[]
            for j in range(max(0,p-100),p-26):
                if (body[j:j+3]==b'\x48\x8d\x05' and body[j+7:j+11]==b'\x48\x89\x84\x24'
                        and body[j+15:j+19]==b'\x48\xc7\x84\x24'):
                    slot1=struct.unpack_from('<I',body,j+11)[0]
                    slot2=struct.unpack_from('<I',body,j+19)[0]
                    if slot2!=slot1+8: continue
                    va=start+rel32(body,j,b'\x48\x8d\x05')
                    n=struct.unpack_from('<I',body,j+23)[0]
                    check(0<n<=64,'invalid missing-label length')
                    name=read(data,secs,va,n).decode('ascii')
                    hits.append((j,va,n,name,slot1))
            check(len(hits)==1,'ambiguous missing-field label')
            j,va,n,name,slot=hits[0]
            check(name in labels,'missing-field label absent from duplicate table')
            out.append({'tag':labels[name], 'label':name, 'diagnostic_site':hex(start+p),
                        'label_lea_site':hex(start+j), 'label_va':hex(va),
                        'length':n, 'local_slot':hex(slot), 'label_setup':body[j:j+27].hex(),
                        'diagnostic_bytes':body[p:p+7].hex()})
        p+=1
    check(len(out)==35 and len({r['tag'] for r in out})==35, 'missing-field scan count changed')
    return out

def simd_classifier_names(data, secs, start, end, rows):
    # Recognize the complete two-vector comparison form only. Other forms stay unresolved.
    pattern = (rb'\xf3\x0f\x6f\x06(?:(\xf3\x0f\x6f\x4e)|(\xf3\x0f\x7e\x4e)|'
               rb'(\x66\x0f\x6e\x4e))(.)(\x66\x0f\x74\x0d....)'
               rb'(\x66\x0f\x74\x05....)\x66\x0f\xdb\xc1\x66\x0f\xd7\xc8'
               rb'\x81\xf9\xff\xff\x00\x00(?:\x0f[\x84\x85]....|[\x74\x75].)')
    body = read(data, secs, start, end-start)
    out = []
    for match in re.finditer(pattern, body, re.DOTALL):
        site = start + match.start()
        raw = match.group()
        off = match.group(4)[0]
        tail_size = (16, 8, 4)[next(i for i in range(3) if match.group(i+1))]
        first_pos, second_pos = match.start(6)-match.start(), match.start(5)-match.start()
        pfirst = site + rel32(raw, first_pos, bytes.fromhex('660f7405'))
        psecond = site + rel32(raw, second_pos, bytes.fromhex('660f740d'))
        first, tail = read(data,secs,pfirst,16), read(data,secs,psecond,16)
        check(tail_size == 16 or not any(tail[tail_size:]), 'nonzero SIMD padding')
        check(off <= 16 and off+tail_size >= 16, 'unsupported SIMD coverage')
        check(first[off:16] == tail[:16-off], 'inconsistent SIMD overlap')
        name = first + tail[16-off:tail_size]
        branch_pos = len(raw)-6 if raw[-6] == 0x0f else len(raw)-2
        if raw[branch_pos] == 0x0f:
            target = site + rel32(raw,branch_pos,raw[branch_pos:branch_pos+2])
            mismatch = raw[branch_pos+1] == 0x85
        else:
            target = site + branch_pos + 2 + struct.unpack_from('<b',raw,branch_pos+1)[0]
            mismatch = raw[branch_pos] == 0x75
        if mismatch:
            check(target == 0x36eef0a, 'unexpected SIMD mismatch target')
            success = site+len(raw)
        else:
            success = target
        code = read(data,secs,success,6)
        if code[0] == 0xe9:
            success += rel32(code, 0, b'\xe9')
            code = read(data,secs,success,6)
        # One match branches to a longer continuation; do not guess its tag.
        if code[0] != 0xb1:
            continue
        tag = code[1]
        check(tag < 60, 'SIMD tag outside duplicate table')
        out.append({'tag': tag, 'name': name.decode('ascii'), 'duplicate_label': rows[tag]['label'], 'comparison_va': hex(site),
                    'comparison_bytes': raw.hex(), 'first_constant_va': hex(pfirst),
                    'second_constant_va': hex(psecond), 'first_constant': first.hex(),
                    'second_constant': tail.hex(), 'tail_input_offset': off,
                    'tail_load_size': tail_size, 'success_va': hex(success)})
    check(len(out) >= 25, 'SIMD comparison census unexpectedly small')
    return out

def narrow_simd_names(data, secs, start, end, rows):
    pattern = (rb'\xf3\x0f\x6f\x06\x0f([\xb6\xb7])\x4e\x10\x66\x0f\x6e\xc9'
               rb'\x66\x0f\x74\x05....\x66\x0f\x74\x0d....'
               rb'\x66\x0f\xdb\xc8\x66\x0f\xd7\xc9\x81\xf9\xff\xff\x00\x00\x0f[\x84\x85]....')
    body=read(data,secs,start,end-start); out=[]
    for m in re.finditer(pattern,body,re.DOTALL):
        site=start+m.start(); raw=m.group(); length=1 if m.group(1)==b'\xb6' else 2
        first=site+rel32(raw,12,bytes.fromhex('660f7405'))
        second=site+rel32(raw,20,bytes.fromhex('660f740d'))
        a,b=read(data,secs,first,16),read(data,secs,second,16)
        check(not any(b[length:]), 'narrow SIMD padding changed')
        name=a+b[:length]; pos=len(raw)-6
        target=site+rel32(raw,pos,raw[pos:pos+2])
        success=target if raw[pos+1]==0x84 else site+len(raw)
        if raw[pos+1]==0x85: check(target==0x36eef0a, 'narrow mismatch target changed')
        code=read(data,secs,success,6)
        if code[0]==0xe9:
            success += rel32(code,0,b'\xe9'); code=read(data,secs,success,2)
        check(code[0]==0xb1 and code[1]<60, 'narrow SIMD success tag changed')
        tag=code[1]
        out.append({'tag':tag, 'name':name.decode('ascii'), 'duplicate_label':rows[tag]['label'],
                    'comparison_va':hex(site), 'comparison_bytes':raw.hex(),
                    'first_constant_va':hex(first), 'second_constant_va':hex(second),
                    'first_constant':a.hex(), 'second_constant':b.hex(), 'success_va':hex(success)})
    check(len(out)==4, 'narrow SIMD census changed')
    return out

def short_classifier_names(data, secs, start, end, rows):
    body = read(data,secs,start,end-start)
    specs = [
        (rb'\x66\x81\x3e(..)\x0f[\x84\x85]....', 'two'),
        (rb'\x0f\xb7\x0e\x81\xf1(..)\x00\x00\x0f\xb6\x56\x02\x83\xf2(.)\x66\x09\xca\x0f[\x84\x85]....', 'three'),
        (rb'\x81\x3e(....)\x0f[\x84\x85]....', 'four'),
    ]
    out = []
    for pattern, kind in specs:
        for match in re.finditer(pattern,body,re.DOTALL):
            site = start+match.start(); raw=match.group()
            name = match.group(1) + (match.group(2) if kind=='three' else b'')
            pos = len(raw)-6
            target = site+rel32(raw,pos,raw[pos:pos+2])
            if raw[pos+1] == 0x85:
                check(target == 0x36eef0a, 'short mismatch target changed')
                success = site+len(raw)
            else:
                success = target
            code = read(data,secs,success,2)
            check(code[0] == 0xb1, 'short match does not set tag')
            tag = code[1]
            check(tag < 60 and rows[tag]['label'].encode() == name, 'short key and diagnostic differ')
            out.append({'name':name.decode('ascii'), 'tag':tag, 'comparison_va':hex(site),
                        'comparison_bytes':raw.hex(), 'success_va':hex(success)})
    out.sort(key=lambda row: row['tag'])
    check(len(out) == 9, 'short comparison census changed')
    return out

def evidence(data):
    authenticated(data)
    secs = sections(data)
    summary, fdes, _ = fde_extents(data)
    selected = {}
    for start in STARTS:
        matches = [f for f in fdes if f['start'] == start]
        check(len(matches) == 1, 'missing or ambiguous FDE')
        f = matches[0]
        body = read(data, secs, f['start'], f['end']-f['start'])
        selected[start] = {'start': hex(start), 'end': hex(f['end']), 'fde_va': hex(f['fde']),
                           'file_offset': hex(mapping(secs,start,len(body))), 'size': len(body),
                           'body_sha256': hashlib.sha256(body).hexdigest()}
    lo, hi = int(selected[0x2fe5290]['start'],16), int(selected[0x2fe5290]['end'],16)
    rows = extract_rows(data, secs, lo, hi)
    missing = missing_field_sites(data, secs, lo, hi, rows)
    pinspec = [
      (0x2fe545e,'c644242f02'),
      (0x2fe55a8,'be000000004889b42480000000'),
      (0x2fe55d4,'c784243c01000000000000'),
      (0x2fe6db5,'4883fe3a0f85d5a500004885c00f8400b7000049894628488dbc24800700004c89f6e8c4d81500488b8c2480070000488b842488070000488984248001000048898c24800000004885c90f84d25b0000'),
      (0x2fe6f52,'4883fe3a0f8528b200004885c00f8463b5000049894628488dbc24301400004c89f6e8a7d40a0080bc2430140000010f849d5400000fb68424311400008844242fe982180000'),
      (0x2fe6d52,'4883fe3a0f8598a100004885c00f8463b7000049894628488dbc24301400004c89f6e887a9b90083bc2430140000010f849d5600008b8424341400008984246c020000488b8424381400004889842408060000c784243c01000001000000e9651a0000'),
      (0x3094497,'4183f966747a4183f9740f851e0100004883f8010f843b010000488d78ff48897e284839d70f83cc0000000fb67c01ff488946284080ff720f85e50000004839d00f83b0000000488d7801440fb6040148897e284180f8750f85c50000004839d70f83900000000fb64c01014883c00248894628b00180f9657475e9a30000004883f8010f84cb000000488d78ff48897e284839d773600fb67c01ff488946284080ff61757d4839d0734c488d7801440fb6040148897e284180f86c75654839d77334488d7802440fb644010148897e284180f873754c4839d7731b0fb64c01024883c0034889462880f965753531c088430131c0eb1f'),
      (0x30945a7,'48894308b00188034889d84883c4285b415ec3'),
      (0x36eea32,'f30f6f06660f6e4e10660f740d0d65b1fc660f74051565b1fc660fdbc1660fd7c881f9ffff00000f84e1040000f30f6f06660f6e4e10660f740d8093b1fc660f7405e889b1fc660fdbc1660fd7c881f9ffff00000f84e3040000f30f6f06660f6e4e10660f740d5393b1fc660f74056b4eb1fc660fdbc1660fd7c881f9ffff00000f84ce040000f30f6f06660f6e4e10660f740d0690b1fc660f74054e4eb1fc660fdbc1660fd7c881f9ffff00000f84b3040000f30f6f06660f6e4e10660f740d0951b1fc660f7405c147b1fc660fdbc1660fd7c881f9ffff00000f8494040000f30f6f06660f6e4e10660f740d6c51b1fc660f74056493b1fc660fdbc1660fd7c881f9ffff00000f8478040000f30f6f06660f6e4e10660f740d8f57b1fc660f74051764b1fc660fdbc1660fd7c881f9ffff00000f8452040000f30f6f06660f6e4e10660f740d7292b1fc660f74052a81b1fc660fdbc1660fd7c881f9ffff00000f8570030000e9bc030000'),
      (0x36ee665,'f30f6f060fb74e10660f6ec9660f74057752b1fc660f740d1f59b1fc660fdbc8660fd7c981f9ffff00000f8575080000e991030000'),
      (0x3183413,'488d15b6b45502488d7424274c89f7e8190fe6ff'),
      (0x3760c50,'488b3e488b4608488b4018488d35ff80e3fcba0f000000ffe0'),
      (0x315c0f1,'4c8bbc24c03f00004983ff027577488d0562e30afd48898424885f000048c78424905f00000800000048896c2428488d050a0b69004889442430488d3dc13708fd488d742428e8f4192800'),
      (0x315c2ae,'488d05b3e10afd48898424885f000048c78424905f00000800000048896c2428488d055b0969004889442430488d3df44c08fd488d742428e845182800'),
      (0x315bcde,'4c89f7e8aa76e8ff4885c00f85b2010000'),
      (0x2fe6d25,'4883fe3a0f85289a00004885c00f8490b70000498946284c89f7e84cc6ffff4885c00f84cd1a0000e9075b0000'),
      (0x315c212,'488d1557225802488d7424074c89f7e81a81e8ff'),
      (0x3285030,'488b3e488b4608488b4018488d35cbed2ffdba12000000ffe0'),
      (0x36ee5d5,'488d0df3a2eafcba210000004889f74889ce4889c3ff1588fd070289c14889d885c90f850d090000b11ae908090000'),
      (0x36eeea4,'488d0d2899eafcba330000004889f74889ce4889c3ff15b9f4070289c14889d885c97542b10feb40'),
      (0x36eeecc,'4989c6488d059399eafcba240000004889f34889f74889c6ff158ef4070285c07466488d35bf9beafcba240000004889dfff1575f4070285c04c89f07451'),
      (0x36eed42,'4889c3488d05bf9deafc4989f64889f74889c64989d7ff151af6070285c00f8448020000'),
      (0x36eef54,'b1154c89f0ebb1b132ebad'),
      (0x36ee4d5,'4889f8488d4afe4883f9310f87240a0000488d3d0b87eafc48630c8f4801f9ffe1'),
      (0x36eec8e,'f30f6f06f30f6f4e07660f740d2179b1fc660f7405f98ab1fc660fdbc1660fd7c881f9ffff00000f8491020000f30f6f06f30f6f4e07660f740dd445b1fc660f7405fc55b1fc660fdbc1660fd7c881f9ffff00000f8493020000f30f6f06f30f6f4e07660f740d0772b1fc660f74059f7fb1fc660fdbc1660fd7c881f9ffff00000f8476020000f30f6f06f30f6f4e07660f740dea71b1fc660f74058283b1fc660fdbc1660fd7c881f9ffff00000f842e010000'),
      (0x36eedf3,'f30f6f06f30f6f4e03660f740d8c67b1fc660f7405c477b1fc660fdbc1660fd7c881f9ffff00000f8430010000f30f6f06f30f6f4e03660f740d3f6ab1fc660f7405875eb1fc660fdbc1660fd7c881f9ffff00000f8432010000'),
      (0x315bc62,'48837c2438087515488b00483b05f4e70afd488d7c24280f8494000000'),
      (0x315bd13,'83bc24c03f0000020f858d050000'),
      (0x315bd80,'4c89f6e8886f0200'),
      (0x315bf63,'4c89f6e8a56d0200'),
      (0x315c0f1,'4c8bbc24c03f00004983ff027577488d0562e30afd48898424885f000048c78424905f000008000000'),
      (0x315c2ae,'488d05b3e10afd48898424885f000048c78424905f000008000000'),
      (0x3182dc1,'83ff5b0f84d100000083ff7b0f8540060000410fb64e4884c90f8437090000fec941884e480f84830500004885c00f840809000049894628488dbc24d02b00004c89f6e88724e6ff'),
      (0x2fe56f0,'488dbc24301400004889c6e8d08d700080bc2430140000010f84704600000fb6842431140000488d0ddf5a59fd486304814801c849bd0000000000000080488bbc24c8000000ffe0'),
      (0x36eee4d,'488d0dd79beafc4889f74889ce4889c3ff1515f5070289c14889d885c90f859a000000b12be995000000'),
      (0x36ee836,'b962726964330eba6467653233560309ca0f84df060000b97374616b330eba6b696e6733560309ca0f85a6060000b109e9a1060000'),
      (0x36ee9dc,'48b973706f745f64697348330e48ba5f656e61626c65644881c205040500483356054809ca0f8464050000'),
      (0x36eef2c,'b108'),
      (0x36eef6b,'b118'),
      (0x36ee819,'b96c6f6375330e0fb6560483f27309ca0f85db06000031c9e9d6060000'),
      (0x36ee969,'48b968797065726c697148330e48ba6971756964697479483356064809ca0f84ab050000'),
      (0x36ee9b8,'48b96167656e745f747248330e48ba5f747261636b6572483356054809ca0f8460050000'),
      (0x36eea07,'48b9686970335f6e6f5f48330e48ba6e6f5f63726f7373483356054809ca0f85df040000b12fe9da040000'),
      (0x36eef38,'b117ebd0b103ebcc'),
      (0x36ee7c6,'48b973706f745f626f6f48330e0fb756084881f26b7300004809ca0f8523070000b102e91e070000'),
      (0x36ee7ee,'48b965766d5f656e616248330e48ba5f656e61626c6564483356034809ca0f85f8060000b127e9f3060000'),
      (0x36ee98d,'48b9616374696f6e5f6448330e48ba5f64656c61796572483356064809ca0f8559050000b12ae954050000'),
      (0x36eed94,'48b97072756e655f616748330e48ba67656e745f696478483356074809ca0f8552010000b119e94d010000'),
      (0x36eec2d,'48b9706572705f64657848330e0fb656084883f2734809ca0f84fd02000048b9635f7374616b696e48330e0fb656084883f2674809ca0f840e03000048b968797065725f657648330e0fb656084883f26d4809ca0f8583020000b11fe97e020000'),
      (0x36eef0a,'b13c884801c600005b415e415fc3'),
      (0x36eef48,'b101ebc0'),
      (0x36eef77,'b10aeb91'),
    ]
    pins = [pin(data, secs, a, b) for a,b in pinspec]
    check(read(data,secs,0x1e0fd5,18) == b'\x11duplicate field `', 'duplicate template changed')
    check(read(data,secs,0x1df8f3,16) == b'\x0fmissing field `', 'missing template changed')
    lens_base = 0x596bf8
    lengths = read(data,secs,lens_base,200)
    cls_lo = int(selected[0x36ee4d0]['start'],16)
    cls_hi = int(selected[0x36ee4d0]['end'],16)
    classifier_prefix = read(data,secs,0x36ee4d8,14)
    check(classifier_prefix[:4] == bytes.fromhex('488d4afe') and classifier_prefix[4:7] == bytes.fromhex('4883f9'), 'classifier length gate changed')
    minimum = -struct.unpack_from('<b',classifier_prefix,3)[0]
    maximum = minimum + classifier_prefix[7]
    check(0x36ee4d8 + rel32(classifier_prefix,8,b'\x0f\x87') == 0x36eef0a, 'length reject branch changed')
    lengths = read(data,secs,lens_base,(maximum-minimum+1)*4)
    length_routes = []
    for index in range(maximum-minimum+1):
        dest = lens_base + struct.unpack_from('<i',lengths,index*4)[0]
        check(cls_lo <= dest < cls_hi, 'classifier length target outside extent')
        length_routes.append({'length': index+minimum, 'target': hex(dest)})
    # Decode immediate bytes and output tags from the pinned compare sequences.
    raw = lambda va,n: read(data,secs,va,n)
    checks = [
      (raw(0x36ee837,4)+raw(0x36ee83e,4)[1:], raw(0x36eef2d,1)[0]),
      (raw(0x36ee84e,4)+raw(0x36ee855,4)[1:], raw(0x36ee865,1)[0]),
      (raw(0x36ee9de,8)+(int.from_bytes(raw(0x36ee9eb,8),'little')+int.from_bytes(raw(0x36ee9f6,4),'little')).to_bytes(8,'little')[3:], raw(0x36eef6c,1)[0]),
      (raw(0x36ee81a,4)+raw(0x36ee826,1), 0),
      (raw(0x36ee96b,8)+raw(0x36ee978,8)[2:], raw(0x36eef39,1)[0]),
      (raw(0x36ee9ba,8)+raw(0x36ee9c7,8)[3:], raw(0x36eef3d,1)[0]),
      (raw(0x36eea09,8)+raw(0x36eea16,8)[3:], raw(0x36eea2c,1)[0]),
      (raw(0x36ee7c8,8)+raw(0x36ee7da,2), raw(0x36ee7e8,1)[0]),
      (raw(0x36ee7f0,8)+raw(0x36ee7fd,8)[5:], raw(0x36ee813,1)[0]),
      (raw(0x36ee98f,8)+raw(0x36ee99c,8)[2:], raw(0x36ee9b2,1)[0]),
      (raw(0x36eed96,8)+raw(0x36eeda3,8)[1:], raw(0x36eedb9,1)[0]),
      (raw(0x36eec2f,8)+bytes([raw(0x36eec41,1)[0]]), raw(0x36eef49,1)[0]),
      (raw(0x36eec4d,8)+bytes([raw(0x36eec5f,1)[0]]), raw(0x36eef78,1)[0]),
      (raw(0x36eec6b,8)+bytes([raw(0x36eec7d,1)[0]]), raw(0x36eec88,1)[0]),
    ]
    simd_checks = simd_classifier_names(data, secs, cls_lo, cls_hi, rows)
    short_checks = short_classifier_names(data, secs, cls_lo, cls_hi, rows)
    narrow_checks = narrow_simd_names(data, secs, cls_lo, cls_hi, rows)
    # The 19-byte comparison is passed through a dynamic equality helper.
    alias_code = read(data,secs,0x36eee4d,42)
    alias_va = 0x36eee4d + rel32(alias_code,0,b'\x48\x8d\x0d')
    alias_name = read(data,secs,alias_va,19).decode('ascii')
    alias_tag = alias_code[36]
    check(alias_tag < 60 and rows[alias_tag]['label'] == alias_name, 'canonical alias mismatch')
    alias_slot = 0x36eee4d + rel32(alias_code,16,b'\xff\x15')
    reloc = next(s for s in secs if s['name'] == '.rela.dyn')
    relbytes = data[reloc['offset']:reloc['offset']+reloc['size']]
    check(len(relbytes)%24 == 0, 'invalid relocation section')
    hits = [(info,addend) for slot,info,addend in struct.iter_unpack('<QQq',relbytes) if slot == alias_slot]
    check(len(hits)==1 and hits[0][0]&0xffffffff == 6, 'alias comparison relocation changed')
    type_refs = [(info,addend) for slot,info,addend in struct.iter_unpack('<QQq',relbytes) if slot==0x56de488]
    check(type_refs == [(8,0x3285030)], 'expected-value vtable relocation changed')
    exchange_refs = [(info,addend) for slot,info,addend in struct.iter_unpack('<QQq',relbytes) if slot==0x56de8e8]
    check(exchange_refs == [(8,0x3760c50)], 'exchange expected-value vtable changed')
    exchange_type = read(data,secs,0x598d61,15).decode('ascii')
    check(exchange_type == 'struct Exchange', 'exchange expected type changed')
    type_name = read(data,secs,0x583e0d,18).decode('ascii')
    check(type_name == 'struct AbciStateDe', 'root expected-type label changed')
    symidx = hits[0][0] >> 32
    symtab = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    check(symidx*24+24 <= symtab['size'], 'dynamic symbol outside table')
    symoff = struct.unpack_from('<I',data,symtab['offset']+24*symidx)[0]
    check(symoff < strings['size'], 'dynamic symbol name outside table')
    pool = data[strings['offset']:strings['offset']+strings['size']]
    name_end = pool.find(b'\0',symoff)
    check(name_end >= 0, 'unterminated dynamic symbol')
    symbol = pool[symoff:name_end].decode('ascii')
    check(symbol == 'bcmp', 'unexpected equality helper')
    # Immediate-length and length-dispatch equality branches, all byte pinned above.
    memory_checks = []
    for lea, prefix, n, tagsite in (
        (0x36ee5d5, b'\x48\x8d\x0d', 33, 0x36ee5fe),
        (0x36eeea4, b'\x48\x8d\x0d', 51, 0x36eeec9),
        (0x36eeecf, b'\x48\x8d\x05', 36, 0x36eef55),
        (0x36eeeee, b'\x48\x8d\x35', 36, 0x36eef5c),
        (0x36eed45, b'\x48\x8d\x05', 23, 0x36eefaf),
    ):
        opcode = read(data,secs,lea,7)
        address = lea + rel32(opcode,0,prefix)
        label = read(data,secs,address,n).decode('ascii')
        tag = read(data,secs,tagsite,1)[0]
        check(tag < 60, 'equality tag outside table')
        memory_checks.append({'comparison_va': hex(lea), 'name_va': hex(address), 'name': label,
                              'length': n, 'tag': tag, 'duplicate_label': rows[tag]['label']})
    aliases = [r for r in simd_checks if r['tag']==alias_tag and r['name'] != alias_name]
    check(len(aliases)==1, 'expected exactly one selected alias')
    check(length_routes[11]['target'] == hex(0x36ee9b8) and length_routes[16]['target'] == hex(0x36ee665) and length_routes[18]['target'] == hex(0x36eea32) and length_routes[17]['target'] == hex(0x36eedf3) and length_routes[21]['target'] == hex(0x36eec8e) and length_routes[34]['target'] == hex(0x36eeecc), 'alias length routing changed')
    for name, tag in checks:
        check(tag < 60 and rows[tag]['label'].encode() == name, 'classifier/duplicate label mismatch')
    scalar_checks = [{'tag': tag, 'name': name.decode('ascii')} for name,tag in checks]
    canonical = {'tag':alias_tag, 'name':alias_name}
    all_checks = scalar_checks + simd_checks + narrow_checks + memory_checks + short_checks + [canonical]
    check({r['tag'] for r in all_checks} == set(range(60)), 'classifier tag coverage incomplete')
    check(all(any(r['tag']==i and r['name']==rows[i]['label'] for r in all_checks)
              for i in range(60)), 'a diagnostic label lacks a matching classifier')
    alias_rows = sorted([{'tag':r['tag'], 'name':r['name'], 'duplicate_label':rows[r['tag']]['label']}
                         for r in all_checks if r['name'] != rows[r['tag']]['label']], key=lambda x:x['tag'])
    check(len(alias_rows)==3, 'unexpected selected alias count')
    named = sorted([{'tag':r['tag'], 'name':r['name'], 'duplicate_label':rows[r['tag']]['label']}
                    for r in all_checks],key=lambda x:(x['tag'],x['name']))
    check(len({r['name'] for r in named})==len(named), 'duplicate selected classifier name')
    return {'binary_sha256': DIGEST, 'coordinate_system': 'ELF link-time virtual addresses, no load base',
            'fde_limit': 'unwind-described extents, not proof of complete function boundaries',
            'functions': [selected[s] for s in STARTS], 'visitor_dispatch_table_va': hex(TABLE),
            'visitor_dispatch_table_file_offset': hex(mapping(secs,TABLE,len(rows)*4)),
            'visitor_dispatch_raw': read(data,secs,TABLE,len(rows)*4).hex(), 'rows': rows, 'missing_field_sites': missing,
            'classifier_name_length_min': minimum, 'classifier_name_length_max': maximum,
            'classifier_length_table_va': hex(lens_base), 'classifier_length_table_raw': lengths.hex(),
            'classifier_length_routes': length_routes,
            'classifier_checked': scalar_checks, 'classifier_names': named, 'aliases': alias_rows,
            'classifier_simd_checked': simd_checks, 'classifier_narrow_checked': narrow_checks, 'classifier_short_checked': short_checks, 'classifier_memory_checked': memory_checks,
            'alias': {'tag': alias_tag, 'canonical_name': alias_name, 'canonical_va': hex(alias_va),
                      'alternate_name': aliases[0]['name'], 'alternate_comparison_va': aliases[0]['comparison_va'],
                      'equality_slot': hex(alias_slot), 'equality_symbol': symbol, 'dynamic_symbol_index': symidx},
            'root_field': read(data,secs,0x20a468,8).decode('ascii'), 'root_expected_type': type_name, 'child_expected_type': exchange_type,
            'duplicate_template_hex': read(data,secs,0x1e0fd5,20).hex(),
            'missing_template_hex': read(data,secs,0x1df8f3,18).hex(), 'pins': pins,
            'limitations': ['Comparator matches and branch targets are static patterns; a complete arbitrary-input CFG proof is not provided.',
                'No full nested value codecs, default or required-field census, runtime execution, or cross-release claims.']}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    data = TARGET.read_bytes()
    record = evidence(data)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    lines = ['tag\tduplicate_label\tarm_va\tduplicate_va\tconditional_bytes']
    for r in record['rows'][:-1]:
        lines.append('\t'.join(str(r[k]) for k in ('tag','label','arm_va','duplicate_va','conditional_bytes')))
    (args.out / 'fields.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['tag\tmatched_comparator_name\tduplicate_label']
    for r in record['classifier_names']:
        lines.append('\t'.join(str(r[k]) for k in ('tag','name','duplicate_label')))
    (args.out / 'names.tsv').write_text('\n'.join(lines)+'\n')
    lines = ['tag\tlabel\tdiagnostic_site\tlabel_lea_site']
    for r in sorted(record['missing_field_sites'],key=lambda r:r['tag']):
        lines.append('\t'.join(str(r[k]) for k in ('tag','label','diagnostic_site','label_lea_site')))
    (args.out / 'missing.tsv').write_text('\n'.join(lines)+'\n')

if __name__ == '__main__':
    try:
        main()
    except (EvidenceError, ValueError, OSError) as e:
        print('error:', e, file=sys.stderr)
        sys.exit(1)
