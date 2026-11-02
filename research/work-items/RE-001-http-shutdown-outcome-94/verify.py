#!/usr/bin/env python3
"""Verify one captured HTTP shutdown branch without executing captured code."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
PACKET = Path(__file__).resolve().parent
RANGES = [
    (0x1493170, 0x149788c, 0xfd8648, '424594342bdcbe3e0e3c327d8f5df58adb53d167b4a4cf585f6257ca0edc9764'),
    (0x4f7d610, 0x4f7d650, 0xf68674, '9fe4d61f57ee424b1544666d3c3b240cdc8abcdaf556da3a1c2f18924750b395'),
    (0x14c1360, 0x14c14a4, 0xfdb77c, 'eff0c9d0bcfcb8c12624dc812b74a1fe79f7c312e638842c1238b08a96ab6074'),
    (0x157a9f0, 0x157aa09, 0xcfadac, '57aeab5f0c65e167d322f63cbd22c644b4ceaaf24a12d1d1dc54896a0a56267f'),
    (0x29c7d90, 0x29c7df5, 0x11179c4, 'c3e9e0d07b697696f621757c0b0edcb60c5817c82d916111d95990a3f4885357'),
]
ANCHORS = {
    0x1493181: '898c2428040000',
    0x1493188: '48891424',
    0x149318c: '48897c2408',
    0x149321f: '4c8bbc2478060000',
    0x1493240: '4d8dbc24c0010000',
    0x1495330: '4d8dbe88000000',
    0x1496d07: '488b442408',
    0x1496d0c: '48c70003000000',
    0x1496d73: '4881c498060000',
    0x1496f1a: '80bc242804000000',
    0x1496f22: '0f84bd010000',
    0x1496f28: '4183bfe800000002',
    0x1496f30: '756d',
    0x1496f32: '498dbff0000000',
    0x1496f3d: 'e81ea40200',
    0x1496f9f: '498dbfe8000000',
    0x1496faa: 'ff15388c2d04',
    0x1496fb0: '4889d3',
    0x1496fb3: 'a801',
    0x1496fb5: '0f854cfdffff',
    0x1496fbb: '4885db',
    0x1496fbe: '0f8412010000',
    0x14970e5: '498b87c8000000',
    0x14970ec: '49c787c800000000000000',
    0x14970f7: '4885c0',
    0x14970fa: '0f85eb000000',
    0x1497100: '488b442408',
    0x1497105: '48c70000000000',
    0x149710c: 'e962fcffff',
    0x14971e2: '4889df',
    0x14971e5: 'ff15158a2d04',
    0x14971eb: '488b4c2408',
    0x14971f0: '48c70102000000',
    0x14971f7: '48894108',
    0x14971fb: 'e973fbffff',
    0x4f7d610: '50',
    0x4f7d611: '8b7f18',
    0x4f7d614: '83ffff',
    0x4f7d617: '742a',
    0x4f7d619: 'be01000000',
    0x4f7d61e: 'ff151c1e7f00',
    0x4f7d624: '83f8ff',
    0x4f7d627: '7406',
    0x4f7d629: '31d2',
    0x4f7d62b: '31c0',
    0x4f7d62d: '59',
    0x4f7d62e: 'c3',
    0x4f7d62f: 'ff15a3127f00',
    0x4f7d635: '8b10',
    0x4f7d637: '48c1e220',
    0x4f7d63b: '4883ca02',
    0x4f7d63f: '31c0',
    0x4f7d641: '59',
    0x4f7d642: 'c3',
    0x4f7d643: '488d3d3e897d00',
    0x4f7d64a: 'ff15200e7f00',
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def observe(data):
    """Structural observer; controls use mutated bytes without calling them authentic."""
    secs = sections(data)
    def read(va, size):
        maps = [s['offset'] + va - s['address'] for s in secs
                if s['type'] != 8 and s['address'] <= va
                and va + size <= s['address'] + s['size']]
        require(len(maps) == 1, 'Ambiguous VA mapping')
        return data[maps[0]:maps[0] + size]
    # Check the actual instructions before whole-body checks so controls can
    # distinguish a broken branch/field contract from a generic digest refusal.
    for va, expected in ANCHORS.items():
        require(read(va, len(bytes.fromhex(expected))) == bytes.fromhex(expected),
                f'Changed selected instruction at {va:#x}')
    _, frames = eh_frame_records(data, secs)
    ranges = []
    for start, end, fde, digest in RANGES:
        matches = [f for f in frames if f['start'] == start]
        require(len(matches) == 1 and matches[0]['end'] == end
                and matches[0]['fde'] == fde, 'Changed FDE extent')
        ranges.append({'start': hex(start), 'end': hex(end), 'fde': hex(fde),
                       'bytes': end-start, 'sha256': hashlib.sha256(read(start, end-start)).hexdigest()})
    by = {s['name']: s for s in secs}
    rel = by['.rela.dyn']
    require(rel['size'] % 24 == 0, 'Truncated relocation table')
    wanted = {0x576fbe8: (8, 0x4f7d610), 0x576fc00: (8, 0x29c7d90),
              0x576e470: (8, 0x157a9f0), 0x576f440: (6, 'shutdown'),
              0x576e8d8: (6, '__errno_location')}
    found = {}
    for where, info, addend in struct.iter_unpack('<QQq', data[rel['offset']:rel['offset']+rel['size']]):
        if where not in wanted:
            continue
        require(where not in found, 'Duplicate selected relocation')
        kind, sym = info & 0xffffffff, info >> 32
        value = addend
        if kind == 6:
            name = struct.unpack_from('<I', data, by['.dynsym']['offset'] + 24*sym)[0]
            pos = by['.dynstr']['offset'] + name
            value = data[pos:data.index(b'\0', pos)].decode('ascii')
        require((kind, value) == wanted[where], f'Changed relocation at {where:#x}')
        found[where] = {'slot': hex(where), 'type': kind,
                        'target': hex(value) if isinstance(value, int) else value}
    require(set(found) == set(wanted), 'Missing selected relocation')
    def relative(va, size, displacement_offset):
        fmt = '<b' if size == 2 else '<i'
        return va + size + struct.unpack_from(fmt, read(va, size), displacement_offset)[0]
    edges = []
    for va, size, disp, expected in [
        (0x1496f3d,5,1,0x14c1360), (0x1496faa,6,2,0x576fbe8),
        (0x14971e5,6,2,0x576fc00), (0x4f7d61e,6,2,0x576f440),
        (0x4f7d62f,6,2,0x576e8d8), (0x4f7d64a,6,2,0x576e470),
        (0x1496f30,2,1,0x1496f9f), (0x1496fb5,6,2,0x1496d07)]:
        target = relative(va,size,disp)
        require(target == expected, f'Changed edge at {va:#x}')
        edges.append({'site':hex(va),'target':hex(target)})
    for va, expected in [(0x1496f22,0x14970e5),(0x1496fbe,0x14970d6),(0x14970fa,0x14971eb)]:
        require(relative(va,6,2) == expected, f'Changed completion edge at {va:#x}')
        edges.append({'site':hex(va),'target':hex(expected)})
    # These fields and immediate outputs are decoded from the verified stores.
    clear = read(0x14970ec,11)
    clear_offset, clear_value = struct.unpack_from('<II',clear,3)
    tags = {label:struct.unpack('<i',read(va,7)[3:])[0]
            for label,va in [('completion-empty',0x1497105),
                             ('completion-payload',0x14971f0),
                             ('delegate-low-bit',0x1496d0c)]}
    fd_offset = read(0x4f7d611,3)[2]
    how = struct.unpack_from('<I',read(0x4f7d619,5),1)[0]
    require((clear_offset,clear_value)==(0xc8,0), 'Changed completion clearing')
    require(tags=={'completion-empty':0,'completion-payload':2,'delegate-low-bit':3}, 'Changed output tags')
    require((fd_offset,how)==(0x18,1), 'Changed socket input contract')
    for row,(_,_,_,expected) in zip(ranges,RANGES):
        require(row['sha256']==expected, f"Changed complete body at {row['start']}")
    return {'targetSha256': TARGET, 'ranges':ranges,
            'relocations':[found[k] for k in sorted(found)], 'selectedEdges':edges,
            'completion':{'localBase':'R15 at selected branch, not entry-object type',
                          'retainedFieldOffset':hex(clear_offset),'clearedTo':clear_value,
                          'rawOutputTags':tags},
            'socketWrapper':{'fdOffset':hex(fd_offset),'how':how,
                             'errorPayload':'(u32 errno << 32) | 2',
                             'normalRax':0},
            'capturedExecution':False, 'rustReconstruction':False,
            'fullDriverOrPeerClaim':False, 'progressGateRequested':False}


def verify_exports(data, packet=PACKET):
    """Bind both retained decoder exports to each other and actual capture bytes."""
    secs = sections(data)
    def read(va,n):
        matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
        require(len(matches)==1,'Ambiguous export VA')
        s=matches[0];off=s['offset']+va-s['address'];return data[off:off+n]
    decoded=json.loads(gzip.decompress((packet/'disassembly.json.gz').read_bytes()))
    gnu=gzip.decompress((packet/'gnu.objdump.txt.gz').read_bytes()).decode('utf8')
    current=None;raw={}
    for line in gnu.splitlines():
        group=re.match(r'^=== ([0-9a-f]+)\.objdump\.txt ===$',line)
        if group:
            current=group[1];require(current not in raw,'Duplicate GNU export');raw[current]=[]
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
        if m and current is not None:raw[current].append((int(m[1],16),bytes.fromhex(m[2])))
    expected={format(s,'x') for s,_,_,_ in RANGES}
    require(set(decoded)==expected and set(raw)==expected,'Decoder range inventory differs')
    counts=[]
    for start,end,_,_ in RANGES:
        name=format(start,'x');pairs=[];cursor=start
        for ins in decoded[name]['instructions']:
            va=int(ins['va'],16);value=bytes.fromhex(ins['bytes'])
            require(va==cursor and 0<len(value)<=15,'Noncontiguous decoder instructions')
            require(read(va,len(value))==value,'Decoder bytes differ from capture')
            pairs.append((va,value));cursor+=len(value)
        require(cursor==end,'Decoder does not cover complete FDE')
        require(pairs==raw[name],'Independent decoder pairs differ')
        counts.append({'start':hex(start),'instructions':len(pairs),'bytes':end-start})
    return counts


def build(data, packet=PACKET):
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==TARGET,
            'Wrong node94 capture identity')
    result=observe(data)
    result['dualDecoderCoverage']=verify_exports(data,packet)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--out',type=Path)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args();result=build(args.binary.read_bytes())
    text=json.dumps(result,indent=2)+'\n'
    if args.check:
        require(result==json.loads((PACKET/'observations.json').read_bytes()),'Committed observations differ')
    if args.out:args.out.write_text(text,encoding='utf8')
    else:print(text,end='')

if __name__=='__main__':
    main()
