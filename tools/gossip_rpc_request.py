#!/usr/bin/env python3
"""Node115 GossipRpcRequest static relation; no capture execution or emulation."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/'research/work-items/RE-005-node115-gossip-rpc-request'
COMPONENT = ROOT/'src/node115-gossip-rpc-request'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
U64 = (1 << 64)-1
EXTENTS = {0x5aac6a0: 0x5aac7b7, 0x5821150: 0x5821243,
           0x5821250: 0x5821335, 0x5822490: 0x58225b5,
           0x58225c0: 0x58226fc, 0x5822700: 0x582270e}
SLOTS = {0x64e7f70: 0x5822490, 0x64e6c38: 0x58225c0, 0x64e7f78: 0x5822700}
TABLES = {0x935bcc: [0x58211b9, 0x58211c5, 0x5821213, 0x58211fb],
          0x935bdc: [0x58212b6, 0x58212ce, 0x58212c2, 0x5821305],
          0x935c14: [0x58224f7, 0x5822504, 0x5822585, 0x582256d],
          0x935c24: [0x5822627, 0x5822641, 0x5822634, 0x58226cc]}
ANCHORS = {0x5aac6bb: '3c12', 0x5aac6c7: '83f801', 0x5aac6cc: '83f802',
           0x5aac762: 'c60305', 0x5821151: '833e01', 0x5821251: '833e01',
           0x582115a: '4883f8fb', 0x582115e: '7711',
           0x582125a: '4883f8f7', 0x582125e: '7711',
           0x5821164: '4883c004', 0x5821264: '4883c008',
           0x582117d: '4883f804', 0x582127d: '4883f808',
           0x582118a: '81fafb000000', 0x582128a: '4881fafb000000',
           0x58211ee: '31d2', 0x58212f8: '31d2',
           0x58224a9: '4c890e', 0x58225d9: '4c890e',
           0x5822700: '4889f8c6070340887701885702c3'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def read(data, secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va+size <= s['address']+s['size']]
    need(len(matches) == 1, 'unmapped/ambiguous image VA')
    s = matches[0]
    offset = s['offset']+va-s['address']
    return offset, data[offset:offset+size]

def analyze(data, authenticate=True):
    if authenticate:
        need(len(data) == 105896032 and sha(data) == SHA, 'target identity mismatch')
    secs = sections(data)
    fdes = eh_frame_records(data, secs)[1]
    bodies = []
    for start, end in EXTENTS.items():
        frame = next((f for f in fdes if f['start'] == start), None)
        need(frame is not None and frame['end'] == end, 'native FDE extent differs')
        offset, raw = read(data, secs, start, end-start)
        metadata = {}
        for name in ('fde', 'cie'):
            va = frame[name]
            length = int.from_bytes(read(data, secs, va, 4)[1], 'little')
            need(0 < length < 4096, 'unexpected frame record length')
            metadata[name] = {'imageVA': hex(va), 'bytesHex': read(data, secs, va, length+4)[1].hex()}
        bodies.append({'start': hex(start), 'end': hex(end), 'bytes': len(raw),
                       'fileOffset': hex(offset), 'bodySHA256': sha(raw),
                       'frame': frame, 'unwindRecords': metadata})
    anchors = []
    for va, expected in ANCHORS.items():
        off, raw = read(data, secs, va, len(bytes.fromhex(expected)))
        need(raw.hex() == expected, 'native operand mismatch at '+hex(va))
        anchors.append({'imageVA': hex(va), 'fileOffset': hex(off), 'bytesHex': expected})
    bindings = []
    for s in secs:
        if s['type'] == 4:
            need(s['size'] % 24 == 0, 'invalid RELA size')
            for off in range(s['offset'], s['offset']+s['size'], 24):
                where, info, addend = struct.unpack_from('<QQq', data, off)
                if where in SLOTS:
                    need(info == 8 and addend == SLOTS[where], 'read helper RELA differs')
                    need(not any(b['slotVA'] == hex(where) for b in bindings), 'duplicate selected RELA')
                    bindings.append({'slotVA': hex(where), 'targetVA': hex(addend),
                                     'type': 8, 'recordFileOffset': hex(off)})
    need(len(bindings) == 3, 'all three actual helper bindings required')
    tables = []
    for va, expected in TABLES.items():
        off, raw = read(data, secs, va, 16)
        targets = [va+v for v in struct.unpack('<iiii', raw)]
        need(targets == expected, 'native dispatch table differs')
        tables.append({'imageVA': hex(va), 'fileOffset': hex(off), 'bytesHex': raw.hex(),
                       'targets': list(map(hex, targets))})
    need(read(data, secs, 0x4519b0, 16)[1] == b'GossipRpcRequest', 'actual type literal differs')
    return {'targetSHA256': SHA, 'coordinateSystem': 'ELF image virtual address',
            'bodies': bodies, 'anchors': anchors, 'bindings': sorted(bindings, key=lambda b:b['slotVA']),
            'dispatchTables': tables, 'invalidVariantType': {'imageVA': '0x4519b0', 'byteLength': 16,
            'text': 'GossipRpcRequest', 'diagnosticContextVA': '0x456bb0',
            'diagnosticContext32BytesHex': read(data, secs, 0x456bb0, 32)[1].hex()},
            'reusedReaderCommit': '45e91f8499f1a78460407d235f580c1625f44d1a',
            'scope': 'Full selected prefix value/error/cursor/charge relation with valid disjoint slice storage and canonical limit classes; not original ABI/padding/formatting or network framing.'}

def parameters(data):
    secs = sections(data)
    byte = lambda a: read(data, secs, a, 1)[1][0]
    return {'charge32': byte(0x5821167), 'charge64': byte(0x5821267),
            'threshold32': byte(0x5821180), 'threshold64': byte(0x5821280),
            'markerFloor': int.from_bytes(read(data, secs, 0x582118c, 4)[1], 'little')}

def relation(source, limited, charged, limit, params):
    """Hand-authored native scalar equations, not a machine-code interpreter."""
    position = 0
    def integer(width):
        nonlocal position, charged
        charge = params['charge'+str(width)]
        if limited:
            if charged > U64-charge:
                return 'e2', None
            charged += charge
            if charged > limit:
                return 'e2', None
        remaining = len(source)-position
        slow = remaining <= params['threshold'+str(width)]
        if not remaining:
            return 'e0:1', None
        marker = source[position]
        begin = position
        if slow:
            position += 1
        if marker < params['markerFloor']:
            position = begin+1
            return None, marker
        payload = {251:2, 252:4, 253:8}.get(marker)
        expected = 3 if width == 64 and slow else 2
        if payload is None or payload*8 > width:
            found = {253:3, 254:4}.get(marker, 12)
            return f'e3:{expected}:{found}', None
        needed = payload+1
        if remaining < needed:
            return 'e0:'+str(needed-remaining), None
        value = int.from_bytes(source[begin+1:begin+needed], 'little')
        position = begin+needed
        return None, value
    error, kind = integer(32)
    if not error:
        if kind == 0:
            error, first = integer(64)
            if not error:
                error, second = integer(64)
                if not error:
                    result = f'v0:{first}:{second}'
        elif kind in (1, 2):
            result = 'v'+str(kind)
        else:
            error = 'e5:'+str(kind)
    return (error if error else result)+f'|{position}|{charged}'

def forms(value, width):
    result = []
    if value < 251:
        result.append(bytes([value]))
    for marker, count in ((251,2), (252,4), (253,8)):
        if count*8 <= width and value < 1 << (8*count):
            result.append(bytes([marker])+value.to_bytes(count,'little'))
    return result

def cases():
    streams = {b'', b'\x00', b'\x00\x00', b'\x00\x00\x00', b'\x01', b'\x02'}
    values = (0,1,2,3,249,250,251,252,255,256,65535,65536,(1<<32)-1,1<<32,U64)
    payloads = set()
    for value in values:
        fs = forms(value,64)
        payloads.update((fs[0],fs[-1]))
    for tag in forms(0,32):
        for first in payloads:
            for second in payloads:
                streams.add(tag+first+second)
    for kind in (1,2,3,250,251,65535,(1<<32)-1):
        for tag in forms(kind,32):
            for tail in (b'',b'\x00',bytes(4),bytes(9),bytes(16)):
                streams.add(tag+tail)
    for marker in range(256):
        for length in (0,1,2,3,4,5,7,8,9,12):
            part=bytes([marker])+bytes(range(length))
            streams.update((part,b'\x00'+part,b'\x00\x00'+part))
    for a in (0,251,(1<<32)-1,U64):
        for b in (0,251,(1<<32)-1,U64):
            wire=forms(0,32)[-1]+forms(a,64)[-1]+forms(b,64)[-1]
            streams.update(wire[:n] for n in range(len(wire)+1))
    result={(0,0,0,s) for s in streams}
    representatives=[b'',b'\x00',b'\x00\x00',b'\x00\x00\x00',b'\x01',b'\x02',b'\x03',
                     b'\xfb',b'\xfb\x01',b'\xfb\x01\x00',b'\xfc\x01\x00\x00\x00',
                     b'\xff',b'\xff'+bytes(4),b'\x00\xff',b'\x00\xff'+bytes(9),
                     b'\x00\x00\xff',b'\x00\x00\xff'+bytes(9),b'\x00\xfd'+bytes(8),
                     b'\x00\xfd'+bytes(8)+b'\xfd'+bytes(8)]
    for source in representatives:
        for charged in (0,1,U64-8,U64-7,U64-4,U64-3,U64):
            result.add((0,charged,0,source))
            for limit in (0,3,4,11,12,19,20,21,U64-1,U64):
                result.add((1,charged,limit,source))
    state=0x5aac6a0
    for i in range(512):
        state=(state*6364136223846793005+1442695040888963407)&((1<<128)-1)
        source=state.to_bytes(16,'little')[:i%17]
        result.add((i&1,(state>>64)&U64,(state>>32)&U64,source))
    return sorted(result)

def corpus(data):
    params=parameters(data)
    rows=[]
    for mode,charged,limit,source in cases():
        expected=relation(source,mode==1,charged,limit,params)
        rows.append(f'{mode}\t{charged}\t{limit}\t{source.hex() or "-"}\t{expected}\n')
    return ''.join(rows).encode()

def validate(binary):
    data=Path(binary).read_bytes()
    record=analyze(data)
    need(record==json.loads((PACKET/'records.json').read_text()),'frozen native records differ')
    expected=corpus(data)
    need(expected==(COMPONENT/'cases.tsv').read_bytes(),'frozen corpus differs')
    return {'status':'PASS','targetSHA256':SHA,'cases':len(expected.splitlines()),
            'fixtureSHA256':sha(expected),'capturedExecutionOrEmulation':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/115/hl-node')
    args=parser.parse_args()
    print(json.dumps(validate(args.binary),indent=2))
