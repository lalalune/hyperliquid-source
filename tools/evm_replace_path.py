#!/usr/bin/env python3
"""Recover selected node 94 account/code replacement path from fixed ELF bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# Exact instruction windows, read on instruction boundaries during static inspection.
PINS = {
 0x326aa54: '488b02488d0de67431fd486304814801c8ffe0',
 0x326aa67: '488b7318eb1e488b4308488bb0d8000000eb11488b5318488b73304839d60f8707010000',
 0x326aa90: 'f30f6f4368f30f6f4b78660f740d3ea1f9fc660f7405b6b6f9fc4c8d6368660fdbc1660fd7c03dffff00007524',
 0x326ab08: '488d4368488b4b70480b8b80000000488b5368480b53784809ca75170f1005651ffafc0f114010f30f6f05491ffafcf30f7f00',
 0x326ab73: 'ff15e7a95002833b0474084889dfe87abe0300',
 0x326ab92: '488d0d5f4d4e0231ffff153f375002',
 0x326a718: '488db728090000',
 0x326a745: 'e8766c5600837c2420040f8421020000',
 0x326a795: '498b8700120000498b8f0812000031d24883e801480f42c2498987001200004c8b6c24184c29e9480f42ca49898f08120000',
 0x326a8ed: 'ba00080000ff15e8365002',
 0x326a910: '410fb78c47000a0000410fb79447020a000066c1c1080fb7b4442010000066c1c60829f166c1c10866c1c2080fb7b4442210000066c1c6086641898c47000a000029f266c1c2086641899447020a00004883c002483d0004000075a4',
 0x326a976: '4d8da7080900004981c7000a00004c8dac24200800004c89ef4c89f64889dae836a101004c89ff4c89eee8eb115800410f1006410f104e100f298c24300800000f2984242008000048899c2440080000488db424200800004c89e7e82a765600',
 0x326abf8: '488d7720',
 0x326ac20: 'e88b635600837c2420010f85e8010000',
 0x326ac42: '488b83f8080000488b8b0009000031d24883e801480f42c2488983f80800004c8b6c24184c29e9480f42ca48898b00090000',
 0x326ad76: 'ba00080000ff152f535002',
 0x326adc0: '0fb78c43f80000000fb79443fa00000066c1c1080fb7b444f00f000066c1c60829f166c1c10866c1c2080fb7b444f20f000066c1c60866898c43f800000029f266c1c20866899443fa0000004883c002483d0004000075a8',
 0x326ae18: '4c8da3f80000004c8dac24f00700004c89ef4c89fe4c89f2e85b9f01004c89e74c89eee8500d5800418b471089842400080000410f10070f298424f00700004c89b42408080000488db424f00700004889dfe871675600',
 0x327199b: 'ff15af3b5002',
 0x32719ac: 'ff15ae3b5002',
 0x37ebbb0: '488b870008000048ffc048c7c1ffffffff480f44c1488987000800004c8b6610488b87080800004c01e0480f43c8480f43c848898f08080000',
 0x37ebd06: 'b8010000000f1f4400000fb74c43fe0fb7144366c1c1080fb7b444860f000066c1c60801ce66c1c60866c1c2080fb78c44880f000066c1c10801d166c1c10866897443fe66890c434883c002483d0104000075b6',
}
STARTS = (0x326a6f0, 0x326aa40, 0x326abd0, 0x3271680, 0x37ebb90)
# These sites are instruction-aligned by hand, not a raw-byte caller census.
CALLS = (0x326a745,0x326a790,0x326a7c7,0x326a88a,0x326a8d7,0x326a995,0x326a9a0,0x326a9d1,
         0x326aac3,0x326ab02,0x326ab73,0x326ac20,0x326ac3d,0x326ac74,0x326ad31,0x326ad7b,
         0x326ae30,0x326ae3b,0x326ae6a,0x327199b,0x32719ac,0x37ebbf0,0x37ebc8a,0x37ebcd2)
BRANCHES = (0x326a74f, 0x326aa85, 0x326aa8e, 0x326aabb, 0x326ab22, 0x326ab7c, 0x326ac2a)
SLOTS = (0x57700b0,0x57700c0,0x57700c8,0x5775550,0x5775560)


def checked_data(path=TARGET):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('target SHA-256 mismatch')
    return data


def read_va(data, va, size, sec=None):
    if size < 0 or va < 0:
        raise ValueError('invalid address or size')
    matches = [s for s in (sec or sections(data)) if s['type'] != 8 and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address lacks unique file-backed section')
    s = matches[0]
    off = s['offset'] + va - s['address']
    return data[off:off + size]


def check_pins(data, sec):
    rows = []
    for va, expected in sorted(PINS.items()):
        actual = read_va(data, va, len(bytes.fromhex(expected)), sec)
        if actual.hex() != expected:
            raise ValueError(f'instruction mismatch at {va:#x}')
        rows.append({'va': hex(va), 'bytes': actual.hex()})
    return rows


def decode_call(data, va, sec):
    raw = read_va(data, va, 6, sec)
    if raw[0] == 0xe8:
        target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
        return {'site':hex(va), 'kind':'rel32', 'target':hex(target), 'bytes':raw[:5].hex()}
    if raw[:2] == b'\xff\x15':
        target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        return {'site':hex(va), 'kind':'rip_slot', 'target':hex(target), 'bytes':raw.hex()}
    raise ValueError(f'unsupported call bytes at {va:#x}')


def decode_branch(data, va, sec):
    raw = read_va(data, va, 6, sec)
    if raw[0] in (0x74,0x75,0x77):
        length = 2
        displacement = struct.unpack_from('<b',raw,1)[0]
        opcode = raw[0]
    elif raw[0] == 0x0f and raw[1] in (0x84,0x85,0x87):
        length = 6
        displacement = struct.unpack_from('<i',raw,2)[0]
        opcode = raw[1] - 0x10
    else:
        raise ValueError(f'unsupported branch at {va:#x}')
    return {'site':hex(va),'condition':{0x74:'equal',0x75:'not_equal',0x77:'unsigned_above'}[opcode],
            'target':hex(va+length+displacement),'fallthrough':hex(va+length),
            'bytes':raw[:length].hex()}


def relocation_rows(data, sec):
    rel = [s for s in sec if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rel) != 1 or rel[0]['size'] % 24:
        raise ValueError('invalid rela.dyn')
    r = rel[0]
    found = []
    for off in range(r['offset'],r['offset'] + r['size'],24):
        slot, info, addend = struct.unpack_from('<QQq',data,off)
        if slot in SLOTS:
            if info != 8:
                raise ValueError('unexpected relocation')
            found.append({'slot':hex(slot),'type':info,'addend':hex(addend)})
    if sorted(int(x['slot'],16) for x in found) != sorted(SLOTS):
        raise ValueError('missing or duplicate relocation')
    return sorted(found,key=lambda row:int(row['slot'],16))


def generate(data):
    sec = sections(data)
    pins = check_pins(data,sec)
    summary, fdes, _ = fde_extents(data)
    fde_by_start = {}
    for r in fdes:
        if r['start'] in STARTS:
            if r['start'] in fde_by_start:
                raise ValueError('duplicate FDE')
            fde_by_start[r['start']] = r
    if set(fde_by_start) != set(STARTS):
        raise ValueError('missing FDE')
    functions=[]
    for start in STARTS:
        f=fde_by_start[start]
        body=read_va(data,start,f['end']-start,sec)
        functions.append({'start':hex(start),'end_exclusive':hex(f['end']),
                          'size':len(body),'sha256':hashlib.sha256(body).hexdigest()})
    table=0x581f44
    table_bytes=read_va(data,table,20,sec)
    jumps=[hex(table+offset) for offset in struct.unpack('<5i',table_bytes)]
    if jumps != ['0x326aa67','0x326aa7a','0x326aa6d','0x326aa67','0x326ab08']:
        raise ValueError('unexpected dispatch table')
    hash_a=read_va(data,0x206160,16,sec)+read_va(data,0x204be0,16,sec)
    hash_b=read_va(data,0x20ca80,32,sec)
    if hash_a != hash_b or hash_a.hex() != 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470':
        raise ValueError('unexpected constant')
    calls=[decode_call(data,va,sec) for va in CALLS]
    relocs=relocation_rows(data,sec)
    return {'target_sha256':hashlib.sha256(data).hexdigest(),
      'coordinate_system':'ELF virtual addresses; exclusive FDE ends',
      'functions':functions,'dispatch_table':{'va':hex(table),'bytes':table_bytes.hex(),'targets':jumps},
      'hash_constant':hash_a.hex(),'branches':[decode_branch(data,va,sec) for va in BRANCHES], 'calls':calls,'relocations':relocs,'instruction_windows':pins,
      'scope':'Fixed instruction-aligned sites only. The fourth FDE supplies two call sites; its body is not mapped. The fifth is the common addition helper.'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    evidence=generate(checked_data())
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'evidence.json').write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8')

if __name__ == '__main__':
    main()
