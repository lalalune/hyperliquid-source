"""Bind the conditional two-hop read and both complete direct-caller contexts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import capstone

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x5361710, 0x5361738
CALLERS = [(0x5380f50,0x53814d0,0x5380fb7),(0x53825f0,0x5382c46,0x538265a)]
BODY = 'f30f1efa488b5708488b82e00100004885c0740c488b4008c30f1f8000000000488b8278010000c3'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def listing(path, image, begin, end):
    rows, cursor = [], begin
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= end, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == end, 'complete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    cies, frames = eh_frame_records(data)
    def frame_record(begin, end):
        overlapping = [f for f in frames if f['start'] < end and begin < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (begin, end), 'unique complete FDE')
        frame, records = overlapping[0], {}
        for kind in ['fde', 'cie']:
            address = frame[kind]
            size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': raw.hex()}
        return {'frame': frame, 'cie': cies[frame['cie']], 'records': records}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    def region(begin, end, name):
        raw, where = image.va_bytes(begin, end-begin, executable=True)
        rows = listing(PACKET / (name+'.gnu.txt'), image, begin, end)
        require(rows == listing(PACKET / (name+'.llvm.txt'), image, begin, end), 'GNU/LLVM boundaries')
        decoded = list(decoder.disasm(raw, begin))
        require(rows == [(i.address, bytes(i.bytes)) for i in decoded], 'Capstone boundaries')
        return {**frame_record(begin, end), 'begin':begin, 'end':end, 'bytes':len(raw), 'hex':raw.hex(),
                'sha256':sha(raw), 'file_offset':where['file_offset'],
                'instructions':[{'address':i.address,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in decoded]}
    body = region(START, END, 'window'); callers = [region(a,b,'caller'+str(i)) for i,(a,b,_) in enumerate(CALLERS)]
    require(body['hex'] == BODY, 'complete body identity')
    ins = body['instructions']
    require(not any(i['mnemonic'] == 'call' or 'rip' in i['operands'] for i in ins), 'no helper or RIP data')
    branches = [(i['address'], i['mnemonic'], int(i['operands'], 16)) for i in ins if i['mnemonic'].startswith('j')]
    require(branches == [(START+18, 'je', START+32)], 'branch closure')
    require([i['address'] for i in ins if i['mnemonic'] == 'ret'] == [START+24,END-1], 'return closure')
    for caller,(begin,end,site) in zip(callers,CALLERS):
        require(any(i['address'] == site and i['mnemonic'] == 'call' and int(i['operands'],16) == START for i in caller['instructions']), 'caller instruction boundary')
    require(image.va_bytes(START-11,11)[0] == b'\xcc'*11, 'preceding padding')
    neighbors = [frame_record(0x53615c0,0x5361705), frame_record(0x5361738,0x53617d6)]
    count = 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:continue
        require(section['entsize'] == 24 and section['size']%24 == 0, 'RELA shape')
        for at in range(section['offset'], section['offset']+section['size'], 24):
            dest,info,addend = struct.unpack_from('<QQq',data,at);count += 1
            require(info&0xffffffff in [1,6,7,8,18], 'unreviewed relocation width')
            require(not any(dest<end and begin<dest+8 for begin,end in [(START-11,END)]+[(a,b) for a,b,_ in CALLERS]), 'code/padding relocation')
            require(addend != START, 'unexpected entry naming relocation')
    require(count == 80300, 'complete RELA census')
    text = next(s for s in image.sections if s['name'] == '.text');code = image.va_bytes(text['address'],text['size'],executable=True)[0];edges = {}
    for opcode in [b'\xe8', b'\xe9']:
        hits,position = [],0
        while (position := code.find(opcode,position)) >= 0:
            if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0] == START:hits.append(text['address']+position)
            position += 1
        require(hits == ([c[2] for c in CALLERS] if opcode == b'\xe8' else []), 'direct candidate closure');edges[opcode.hex()] = hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':body,'callers':callers,'neighbors':neighbors,
            'preceding_padding_hex':'cc'*11,'following_padding_hex':'','branches':branches,'naming_relocations':[],
            'caller_limit':'Complete code/FDE/CIE and selected call-boundary context only; caller algorithm, other helpers and LSDA/personality behavior are not reconstructed.',
            'rela_records_checked':count,'direct_encoding_candidates':edges,'complete_xref_census':False,
            'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}


def validate():
    data = (ROOT/'artifacts/node/94/hl-node').read_bytes()
    require(len(data) == 91774280 and sha(data) == TARGET, 'target identity')
    record = inspect(data);body = record['body'];changes = {}
    for ins in body['instructions']:
        offset = body['file_offset']+ins['address']-START
        changes[f'instruction {ins["address"]:#x}'] = offset
        if len(bytes.fromhex(ins['bytes'])) > 1:changes[f'operand {ins["address"]:#x}'] = offset+len(bytes.fromhex(ins['bytes']))-1
    changes.update({'FDE extent':body['records']['fde']['file_offset']+12,'CIE encoding':body['records']['cie']['file_offset']+15,
                    'preceding padding':body['file_offset']-1,'internal NOP last byte':body['file_offset']+31})
    for index,(caller,(begin,end,site)) in enumerate(zip(record['callers'],CALLERS)):
        changes.update({f'caller {index} first':caller['file_offset'],f'caller {index} last':caller['file_offset']+caller['bytes']-1,
                        f'caller {index} call displacement':caller['file_offset']+site-begin+1,
                        f'caller {index} FDE':caller['records']['fde']['file_offset']+12,
                        f'caller {index} CIE':caller['records']['cie']['file_offset']+15})
    for i,n in enumerate(record['neighbors']):changes[f'neighbor{i} FDE extent'] = n['records']['fde']['file_offset']+12
    rejected = {}
    for label,at in changes.items():
        changed = bytearray(data);changed[at] ^= 1
        try:
            other = inspect(bytes(changed))
            require({k:v for k,v in other.items() if k!='target_sha256'} == {k:v for k,v in record.items() if k!='target_sha256'}, 'structural drift')
        except ValueError as error:rejected[label] = str(error)
        else:raise ValueError('accepted corruption '+label)
    image = Elf(data,3);rel = next(s for s in image.sections if s['type'] == 4)['offset']
    for label,at,replacement in [('introduced entry reference',rel+16,struct.pack('<q',START)),('partial code relocation',rel,struct.pack('<Q',START-3))]:
        changed = bytearray(data);changed[at:at+len(replacement)] = replacement
        try:inspect(bytes(changed))
        except ValueError as error:rejected[label] = str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls'] = rejected
    return record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args();record=validate()
    if args.freeze:
        with (PACKET/'static.json').open('xb') as f:f.write(encoded(record))
    else:require((PACKET/'static.json').read_bytes()==encoded(record),'static drift')
    print(json.dumps({'instructions':len(record['body']['instructions']),'caller_instructions':sum(len(c['instructions']) for c in record['callers']),'controls':len(record['corruption_controls'])}))
if __name__=='__main__':main()
