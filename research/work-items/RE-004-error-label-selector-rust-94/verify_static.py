"""Close the full byte-selector body, entry relocation and all returned data spans."""
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
START, END = 0x14b4e20, 0x14b4e48
A, B, DATA_END, SLOT = 0x21bf92, 0x21bfa3, 0x21c2ae, 0x566de38
BODY = '0fb60f4889c84883f001488d14404883c20e488d356a71d6fe488d055271d6fe4885c9480f45c6c3'


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
    raw, where = image.va_bytes(START, END-START, executable=True)
    rows = listing(PACKET/'window.gnu.txt', image, START, END)
    require(rows == listing(PACKET/'window.llvm.txt', image, START, END), 'GNU/LLVM boundaries')
    decoded = list(decoder.disasm(raw, START))
    require(rows == [(i.address, bytes(i.bytes)) for i in decoded], 'Capstone boundaries')
    require(raw.hex() == BODY, 'full body identity')
    body = {**frame_record(START, END), 'begin':START, 'end':END, 'bytes':len(raw), 'hex':raw.hex(),
            'sha256':sha(raw), 'file_offset':where['file_offset'],
            'instructions':[{'address':i.address,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in decoded]}
    require(len(decoded) == 10 and [i.mnemonic for i in decoded] == ['movzx','mov','xor','lea','add','lea','lea','test','cmovne','ret'], 'complete call-free grammar')
    require(START+25+struct.unpack_from('<i',raw,21)[0] == B, 'RSI RIP target')
    require(START+32+struct.unpack_from('<i',raw,28)[0] == A, 'RAX RIP target')
    require(image.va_bytes(START-4,4)[0] == b'\xcc'*4, 'preceding padding')
    require(image.va_bytes(END,8)[0] == b'\xcc'*8, 'following padding')
    neighbors = [frame_record(0x14b4df0,0x14b4e1c), frame_record(0x14b4e50,0x14b4f75)]
    window, mapping = image.va_bytes(A, DATA_END-A)
    require(window == bytes.fromhex((PACKET/'captured-window.hex').read_text()), 'complete captured data')
    require(mapping['section']['name'] == '.rodata' and mapping['section']['flags'] & 7 == 2, 'allocated nonwritable nonexecutable rodata')
    require(mapping['PT_LOAD']['flags'] == 4, 'read-only file-backed PT_LOAD')
    require(window[:17] == b'invalid character' and window[17:31] == b'invalid length', 'two literal extents')
    spans = []
    for tag in range(256):
        start = A if tag == 0 else B
        length = 3*(tag^1)+14
        require(A <= start and start+length <= DATA_END, 'all byte-domain span bounds')
        spans.append({'tag':tag,'begin':start,'bytes':length,'end':start+length,'sha256':sha(window[start-A:start-A+length])})
    require(max(s['end'] for s in spans) == DATA_END and spans[254]['bytes'] == 779, 'tight maximum data extent')
    slot_raw, slot_mapping = image.va_bytes(SLOT,8)
    require(slot_raw == bytes(8) and slot_mapping['section']['name'] == '.data.rel.ro', 'unapplied entry slot')
    count, naming, writers = 0, [], []
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:continue
        require(section['entsize'] == 24 and section['size']%24 == 0, 'RELA shape')
        for at in range(section['offset'],section['offset']+section['size'],24):
            dest,info,addend = struct.unpack_from('<QQq',data,at);count += 1
            require(info&0xffffffff in [1,6,7,8,18], 'unreviewed relocation width')
            require(not any(dest<end and begin<dest+8 for begin,end in [(START-4,END+8),(A,DATA_END)]), 'code or returned data relocation writer')
            record = {'destination':dest,'info':info,'addend':addend,'file_offset':at,'hex':data[at:at+24].hex()}
            if addend == START:naming.append(record)
            if dest<SLOT+8 and SLOT<dest+8:writers.append(record)
    require(count == 80300, 'complete RELA census')
    require(len(naming) == 1 and naming == writers and naming[0]['destination'] == SLOT and naming[0]['info'] == 8, 'unique exact entry-slot RELATIVE writer')
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'],text['size'],executable=True)[0];edges = {}
    for opcode in [b'\xe8',b'\xe9']:
        hits,position = [],0
        while (position := code.find(opcode,position)) >= 0:
            if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0] == START:hits.append(text['address']+position)
            position += 1
        require(hits == [], 'direct encoding candidate closure');edges[opcode.hex()] = hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':body,'neighbors':neighbors,
            'preceding_padding_hex':'cc'*4,'following_padding_hex':'cc'*8,
            'window':{'begin':A,'end':DATA_END,'bytes':len(window),'sha256':sha(window),'mapping':mapping},
            'spans':spans,'naming_relocations':naming,'slot_mapping':slot_mapping,
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
                    'preceding padding':body['file_offset']-1,'following padding':body['file_offset']+40,
                    'first literal':A,'second literal':B,'outside old 62-byte extent':A+62,'maximum last byte':DATA_END-1,
                    'entry raw slot':record['slot_mapping']['file_offset'],'entry relocation addend':record['naming_relocations'][0]['file_offset']+16})
    for i,n in enumerate(record['neighbors']):changes[f'neighbor{i} FDE extent'] = n['records']['fde']['file_offset']+12
    rejected = {}
    def check(label,changed):
        try:
            other = inspect(bytes(changed))
            require({k:v for k,v in other.items() if k!='target_sha256'} == {k:v for k,v in record.items() if k!='target_sha256'}, 'structural drift')
        except ValueError as error:rejected[label] = str(error)
        else:raise ValueError('accepted corruption '+label)
    for label,at in changes.items():
        changed=bytearray(data);changed[at]^=1;check(label,changed)
    image=Elf(data,3);rel=next(s for s in image.sections if s['type']==4)['offset']
    for label,at,replacement in [('introduced entry reference',rel+16,struct.pack('<q',START)),('partial code writer',rel,struct.pack('<Q',START-3)),('partial data writer',rel,struct.pack('<Q',A-3)),('last data byte writer',rel,struct.pack('<Q',DATA_END-1)),('duplicate entry slot writer',rel,struct.pack('<Q',SLOT+3))]:
        changed=bytearray(data);changed[at:at+len(replacement)]=replacement;check(label,changed)
    record['corruption_controls']=rejected
    return record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args();record=validate()
    if args.freeze:
        with (PACKET/'static.json').open('xb') as f:f.write(encoded(record))
    else:require((PACKET/'static.json').read_bytes()==encoded(record),'static drift')
    print(json.dumps({'instructions':len(record['body']['instructions']),'data_bytes':record['window']['bytes'],'controls':len(record['corruption_controls'])}))
if __name__=='__main__':main()
