"""Qualify an unwindless popcount body, bracketing FDEs and its call edges."""
import argparse
import json
import re
import struct
import sys
from oracle import ROOT, PACKET, require, sha
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records
from libcore_fmt_correspondence import Elf
from foundation_unwindless_popcount import CALLERS, CALLER_FDES
import capstone

TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BEGIN, END = 0x5660010, 0x5660072
BODY = '09027f7508488f9fabf097f96e8db1d2e2740cf931ae88d008e04df4a8ab2916'
ADAPTER = '50fbc6d1c10dbce2d2c037c275f0c4a7ea279770e14258aaa632c2607f71f50b'


def listing(path, image, begin, end):
    rows, cursor = [], begin
    for line in path.read_text().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if match:
            address, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(address == cursor and address + len(raw) <= end, 'listing extent')
            require(image.va_bytes(address, len(raw), executable=True)[0] == raw, 'listing bytes')
            rows.append((address, raw)); cursor += len(raw)
    require(cursor == end, 'incomplete listing')
    return rows


def inspect(data):
    image = Elf(data, 3)
    _, frames = eh_frame_records(data)
    require(not any(f['start'] < END and BEGIN < f['end'] for f in frames), 'unexpected FDE overlap')
    require(max(f['end'] for f in frames if f['end'] <= BEGIN) == 0x5660004, 'lower FDE bracket')
    require(min(f['start'] for f in frames if f['start'] >= END) == 0x5660080, 'upper FDE bracket')
    require(image.va_bytes(0x5660004, 12)[0] == b'\xcc' * 12, 'leading padding')
    require(image.va_bytes(END, 14)[0] == b'\xcc' * 14, 'trailing padding')
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); decoder.detail = True
    body, mapping = image.va_bytes(BEGIN, END - BEGIN, executable=True)
    require(sha(body) == BODY, 'complete popcount body')
    rows = listing(PACKET / 'popcount.gnu.txt', image, BEGIN, END)
    require(rows == listing(PACKET / 'popcount.llvm.txt', image, BEGIN, END), 'decoder body boundaries')
    ins = list(decoder.disasm(body, BEGIN))
    require([(i.address, bytes(i.bytes)) for i in ins] == rows, 'Capstone body boundaries')
    require(not any(i.mnemonic.startswith(('j', 'call')) for i in ins), 'unexpected control edge')
    require([i.address for i in ins if i.mnemonic == 'ret'] == [END - 1], 'terminal return')
    require(not any(o.type == capstone.x86.X86_OP_MEM for i in ins for o in i.operands), 'explicit leaf memory dependency')
    def qualified(start, end):
        overlapping = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(overlapping) == 1 and (overlapping[0]['start'], overlapping[0]['end']) == (start, end), 'complete unique FDE')
        frame, records = overlapping[0], {}
        for kind in ('fde', 'cie'):
            address = frame[kind]; size = int.from_bytes(image.va_bytes(address, 4)[0], 'little') + 4
            raw, where = image.va_bytes(address, size)
            records[kind] = {'va': address, 'file_offset': where['file_offset'], 'hex': raw.hex()}
        return {'frame': frame, 'records': records}
    brackets = [qualified(0x565ff80, 0x5660004), qualified(0x5660080, 0x5660092)]
    callers = []
    for _, _, start, end in CALLER_FDES:
        record = qualified(start, end)
        raw, where = image.va_bytes(start, end - start, executable=True)
        decoded = list(decoder.disasm(raw, start))
        require(sum(i.size for i in decoded) == len(raw), 'complete caller decode')
        selected = [i for i in decoded if i.mnemonic == 'call' and i.op_str == hex(BEGIN)]
        expected = [va for va in CALLERS if start <= va < end]
        require([i.address for i in selected] == expected, 'caller instruction edges')
        record.update(bytes=len(raw), sha256=sha(raw), file_offset=where['file_offset'], instructions=len(decoded),
                      sites=[{'va':i.address,'hex':i.bytes.hex(),'file_offset':where['file_offset']+i.address-start} for i in selected])
        if start == 0x4f9eb90:
            require(sha(raw) == ADAPTER, 'complete field adapter')
            adapter_rows = listing(PACKET / 'field.gnu.txt', image, start, end)
            require(adapter_rows == listing(PACKET / 'field.llvm.txt', image, start, end) == [(i.address, bytes(i.bytes)) for i in decoded], 'field decoder boundaries')
            require(image.va_bytes(0x4f9eb98, 3)[0].hex() == '8b7f40', 'u32 field load offset/width')
        callers.append(record)
    text = next(s for s in image.sections if s['name'] == '.text')
    code = image.va_bytes(text['address'], text['size'], executable=True)[0]
    candidates, position = [], 0
    while (position := code.find(b'\xe8', position)) >= 0:
        if position + 5 <= len(code) and text['address'] + position + 5 + struct.unpack_from('<i', code, position + 1)[0] == BEGIN:
            candidates.append(text['address'] + position)
        position += 1
    require(candidates == CALLERS, 'direct call candidate census')
    count = 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:
            continue
        require(section['entsize'] == 24 and section['size'] % 24 == 0, 'RELA shape')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            dest, _, addend = struct.unpack_from('<QQq', data, offset); count += 1
            require(addend not in (BEGIN, 0x4f9eb90), 'unexpected naming relocation')
            require(not any(dest < b and a < dest + 8 for a, b in [(0x5660004, 0x5660080), (0x4f9eb90, 0x4f9eba5)]), 'protected code relocation')
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':{'begin':BEGIN,'end':END,'bytes':len(body),
            'sha256':sha(body),'hex':body.hex(),'file_offset':mapping['file_offset'],'instructions':len(ins)},
            'fde_records_scanned':len(frames),'body_fde_overlaps':[], 'brackets':brackets,'callers':callers,
            'direct_e8_candidates':candidates,'complete_xref_census':False,'rela_records_checked':count,
            'capstone_version':capstone.__version__,'captured_code_executed':False,'instruction_emulation':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();require(sha(data)==TARGET,'target identity')
    record=inspect(data);base=record['body']['file_offset']
    edits={'pair mask':(base+8,bytes([data[base+8]^1])),
           'final fold':(base+0x5f,bytes([data[base+0x5f]^1])),
           'leading padding':(base-1,b'\x90'),'trailing padding':(base+END-BEGIN,b'\x90')}
    off=record['brackets'][0]['records']['fde']['file_offset']+12
    edits['overlapping FDE']=(off,struct.pack('<I',struct.unpack_from('<I',data,off)[0]+16))
    off=record['brackets'][0]['records']['cie']['file_offset']+15;edits['CIE encoding']=(off,bytes([data[off]^1]))
    for c in record['callers']:
        off=c['sites'][0]['file_offset']+1;edits['call '+hex(c['sites'][0]['va'])]=(off,bytes([data[off]^1]))
    adapter=record['callers'][0]['file_offset'];edits['field width']=(adapter+8,b'\x48')
    rejected={}
    for label,(offset,raw) in edits.items():
        changed=bytearray(data);changed[offset:offset+len(raw)]=raw
        try:
            other=inspect(bytes(changed));require(other==record,'structural record drift')
        except ValueError as error:
            rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected
    text=json.dumps(record,indent=2,sort_keys=True)+'\n'
    if args.write:
        with (PACKET/'static.json').open('x') as f:f.write(text)
    else:require((PACKET/'static.json').read_text()==text,'retained static drift')
    print(json.dumps({'body_instructions':record['body']['instructions'],'callers':len(record['callers']),
                      'call_sites':len(record['direct_e8_candidates']),'controls':rejected},indent=2))

if __name__=='__main__':main()
