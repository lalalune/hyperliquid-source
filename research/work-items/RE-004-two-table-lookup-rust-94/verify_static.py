"""Bind the complete signed two-table address leaf and selected data context."""
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
START, END = 0x5560660, 0x55606a8
CALLER, CALLER_END, CALL = 0x55c84f0, 0x55c8bc3, 0x55c8554
BASES = [0x576d9e0, 0x576db20]
BODY = 'f30f1efa8d47fd83f802770583fe01741f4863d24863ff488d0492488d1447488d055ad32000488b04d0c30f1f4400004863d24898488d14524801d0488d157dd42000488b04c2c3'


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
    body = region(START, END, 'window'); caller = region(CALLER, CALLER_END, 'caller')
    require(body['hex'] == BODY, 'complete body identity')
    ins = body['instructions']
    require(not any(i['mnemonic']=='call' for i in ins), 'leaf calls')
    branches = [(i['address'],i['mnemonic'],int(i['operands'],16)) for i in ins if i['mnemonic'].startswith('j')]
    require(branches == [(START+10,'ja',START+17),(START+15,'je',START+48)], 'branch closure')
    require([i['address'] for i in ins if i['mnemonic']=='ret'] == [START+42, END-1], 'return closure')
    require(any(i['address']==CALL and i['mnemonic']=='call' and int(i['operands'],16)==START for i in caller['instructions']), 'caller instruction boundary')
    require(image.va_bytes(END,8)[0] == b'\xcc'*8, 'following padding')
    neighbor = frame_record(0x55606b0,0x55606cb)
    context=[]
    for base in BASES:
        raw,where=image.va_bytes(base,8)
        require(raw==bytes(8) and where['section']['name']=='.data.rel.ro', 'base storage context')
        context.append({'va':base,'file_hex':raw.hex(),'mapping':where,'relocations':[]})
    relocations, count = [], 0
    for section in image.sections:
        require(section['type'] != 9, 'unsupported REL table')
        if section['type'] != 4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for at in range(section['offset'],section['offset']+section['size'],24):
            dest,info,addend=struct.unpack_from('<QQq',data,at);kind,symbol=info&0xffffffff,info>>32;count+=1
            require(kind in [1,6,7,8,18], 'unreviewed relocation width')
            require(not any(dest<end and begin<dest+8 for begin,end in [(START,END+8),(CALLER,CALLER_END)]),'code relocation')
            require(addend != START, 'unexpected entry naming relocation')
            for c in context:
                if dest<c['va']+8 and c['va']<dest+8:
                    require(dest==c['va'] and kind==8 and symbol==0 and section['name']=='.rela.dyn','base RELATIVE relocation')
                    c['relocations'].append({'file_offset':at,'hex':data[at:at+24].hex(),'destination':dest,'type':kind,'symbol':symbol,'addend':addend})
    require([len(c['relocations']) for c in context]==[1,1],'unique base qword relocations')
    require([c['relocations'][0]['addend'] for c in context]==[0x5585670,0x55af100],'base qword loaded values')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0]
    edges={}
    for opcode in [b'\xe8',b'\xe9']:
        hits,position=[],0
        while (position:=code.find(opcode,position))>=0:
            if position+5<=len(code) and text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]==START:hits.append(text['address']+position)
            position+=1
        require(hits==([CALL] if opcode==b'\xe8' else []),'direct edge candidate closure');edges[opcode.hex()]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':body,'caller':caller,'next_fde':neighbor,
            'following_padding_hex':'cc'*8,'branches':branches,'base_qword_context':context,
            'context_limit':'Only the two base qwords are numeric data samples; neither a logical table extent nor other selected contents is asserted. The API receives the actual runtime image.',
            'rela_records_checked':count,'direct_encoding_candidates':edges,'complete_xref_census':False,
            'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}


def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    require(len(data)==91774280 and sha(data)==TARGET,'target identity')
    record=inspect(data);body=record['body'];caller=record['caller']
    changes={f'body operand+{n}':body['file_offset']+n for n in [6,9,11,14,16,19,22,26,30,34,39,41,45,50,52,56,59,63,68,70]}
    changes.update({'FDE extent':body['records']['fde']['file_offset']+12,'CIE encoding':body['records']['cie']['file_offset']+15,
                    'following padding':body['file_offset']+72,'next FDE':record['next_fde']['records']['fde']['file_offset']+12,
                    'caller start':caller['file_offset'],'caller end':caller['file_offset']+caller['bytes']-1,
                    'caller call displacement':caller['file_offset']+CALL-CALLER+1,'caller FDE':caller['records']['fde']['file_offset']+12})
    for i,c in enumerate(record['base_qword_context']):
        changes[f'base{i} file qword']=c['mapping']['file_offset']
        for label,n in [('destination',0),('type',8),('symbol',12),('addend',16)]:changes[f'base{i} relocation {label}']=c['relocations'][0]['file_offset']+n
    rejected={}
    for label,at in changes.items():
        changed=bytearray(data);changed[at]^=1
        try:
            other=inspect(bytes(changed))
            require({k:v for k,v in other.items() if k!='target_sha256'}=={k:v for k,v in record.items() if k!='target_sha256'},'structural drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected
    return record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args();record=validate()
    if args.freeze:
        with (PACKET/'static.json').open('xb') as file:file.write(encoded(record))
    else:require((PACKET/'static.json').read_bytes()==encoded(record),'static drift')
    print(json.dumps({'instructions':len(record['body']['instructions']),'caller_instructions':len(record['caller']['instructions']),'controls':len(record['corruption_controls'])}))


if __name__=='__main__':main()
