"""Bind the low32 selector, full selected base and all complete caller contexts."""
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
START, END = 0x552cac0, 0x552cade
CALLERS = [(0x54cbd50,0x54cbfed,[(0x54cbfc2,0x552cac0)]),
           (0x54cbff0,0x54cc126,[(0x54cc11a,0x552cac0)]),
           (0x551e750,0x551e971,[(0x551e8d0,0x552cac0),(0x551e8e7,0x552cac0)]),
           (0x54cab80,0x54cb487,[(0x54cac3f,0x552b280),(0x54cac54,0x552b280)]),
           (0x54e3b10,0x54e3e00,[(0x54e3be8,0x54cbd40)]),
           (0x54e3e00,0x54e40f0,[(0x54e3ed8,0x54cbd40)])]
WRAPPERS = [(0x552b280,0x552b28d,0x552b288,0x552cac0,'f30f1efa4883c718e933180000',3),
            (0x54cbd40,0x54cbd50,0x54cbd4b,0x552b280,'f30f1efa4881c798290000e930f50500',0)]
BODY = 'f30f1efa488d8718e500004881c710ec000083fe01480f44f8488b4778c3'


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


def llvm_logical_rows(rows, begin, end):
    """Join the three observed standalone LOCK rendering rows, without byte masks."""
    allowed = [0x551e926, 0x551e93b, 0x551e948]
    result, joined, i = [], [], 0
    while i < len(rows):
        address, raw = rows[i]
        if raw == b'\xf0':
            require(address in allowed and i+1 < len(rows), 'unexpected split prefix')
            following, tail = rows[i+1]
            require(following == address+1, 'nonadjacent LOCK rendering')
            result.append((address, raw+tail));joined.append(address);i += 2
        else:
            result.append((address, raw));i += 1
    require(joined == [a for a in allowed if begin <= a < end], 'exact LLVM split-prefix inventory')
    return result


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
        llvm = listing(PACKET / (name+'.llvm.txt'), image, begin, end)
        require(rows == llvm_logical_rows(llvm, begin, end), 'GNU/LLVM logical boundaries')
        decoded = list(decoder.disasm(raw, begin))
        require(rows == [(i.address, bytes(i.bytes)) for i in decoded], 'Capstone boundaries')
        return {**frame_record(begin, end), 'begin':begin, 'end':end, 'bytes':len(raw), 'hex':raw.hex(),
                'sha256':sha(raw), 'file_offset':where['file_offset'],
                'instructions':[{'address':i.address,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str} for i in decoded]}
    body = region(START, END, 'window')
    wrappers = [region(a,b,'wrapper'+str(i)) for i,(a,b,*_) in enumerate(WRAPPERS)]
    callers = [region(a,b,'caller'+str(i)) for i,(a,b,_) in enumerate(CALLERS)]
    require(body['hex'] == BODY, 'complete leaf body identity')
    require([i['address'] for i in body['instructions'] if i['mnemonic']=='ret']==[END-1], 'leaf return')
    require(not any(i['mnemonic'].startswith('j') or i['mnemonic']=='call' or 'rip' in i['operands'] for i in body['instructions']), 'leaf call/branch/data closure')
    for wrapper,(a,b,site,target,raw,pad) in zip(wrappers,WRAPPERS):
        require(wrapper['hex']==raw,'complete wrapper identity')
        require([(i['address'],i['mnemonic'],i['operands']) for i in wrapper['instructions'] if i['mnemonic'].startswith('j') or i['mnemonic']=='call']==[(site,'jmp',hex(target))], 'wrapper tail closure')
        require(not any(i['mnemonic']=='ret' or 'rip' in i['operands'] for i in wrapper['instructions']), 'wrapper has no extra return/data')
        if pad:require(image.va_bytes(b,pad)[0]==b'\xcc'*pad,'wrapper padding')
    for caller,(begin,end,edges) in zip(callers,CALLERS):
        for site,target in edges:
            require(any(i['address']==site and i['mnemonic']=='call' and int(i['operands'],16)==target for i in caller['instructions']),'caller instruction boundary')
    require(image.va_bytes(START-13,13)[0]==b'\xcc'*13,'preceding padding')
    require(image.va_bytes(END,2)[0]==b'\xcc'*2,'following padding')
    neighbors=[frame_record(0x552c980,0x552cab3),frame_record(0x552cae0,0x552cb45)]
    starts={START}|{w[0] for w in WRAPPERS}
    protected=[(START-13,END+2)]+[(a,b+pad) for a,b,_,_,_,pad in WRAPPERS]+[(a,b)for a,b,_ in CALLERS]
    count=0
    for section in image.sections:
        require(section['type']!=9,'unsupported REL table')
        if section['type']!=4:continue
        require(section['entsize']==24 and section['size']%24==0,'RELA shape')
        for at in range(section['offset'],section['offset']+section['size'],24):
            dest,info,addend=struct.unpack_from('<QQq',data,at);count+=1
            require(info&0xffffffff in [1,6,7,8,18],'unreviewed relocation width')
            require(not any(dest<end and begin<dest+8 for begin,end in protected),'code/padding relocation')
            require(addend not in starts,'unexpected member naming relocation')
    require(count==80300,'complete RELA census')
    text=next(s for s in image.sections if s['name']=='.text');code=image.va_bytes(text['address'],text['size'],executable=True)[0];edges={}
    for opcode in [b'\xe8',b'\xe9']:
        hits,position=[],0
        while(position:=code.find(opcode,position))>=0:
            if position+5<=len(code):
                target=text['address']+position+5+struct.unpack_from('<i',code,position+1)[0]
                if target in starts:hits.append((text['address']+position,target))
            position+=1
        want=sorted([edge for _,_,es in CALLERS for edge in es] if opcode==b'\xe8' else [(site,target)for _,_,site,target,_,_ in WRAPPERS])
        require(hits==want,'all family direct candidate closure');edges[opcode.hex()]=hits
    return {'target_sha256':sha(data),'target_bytes':len(data),'body':body,'wrappers':wrappers,'callers':callers,'neighbors':neighbors,
            'family_bytes':sum(m['bytes']for m in [body,*wrappers]),'preceding_padding_hex':'cc'*13,'following_padding_hex':'cc'*2,
            'naming_relocations':[],'rela_records_checked':count,'direct_encoding_candidates':edges,'complete_xref_census':False,
            'caller_limit':'Complete code/FDE/CIE and direct call-boundary context only; caller algorithms, other helpers and data are not reconstructed.',
            'llvm_split_lock_prefixes':[0x551e926,0x551e93b,0x551e948],
            'listing_normalization':'Only join exact standalone F0 rows to the next adjacent LLVM row; no bytes removed or changed. GNU and Capstone logical boundaries match.',
            'capstone_version':capstone.__version__,'captured_execution':False,'instruction_emulation':False}


def validate():
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes()
    require(len(data)==91774280 and sha(data)==TARGET,'target identity')
    record=inspect(data);changes={}
    for index,m in enumerate([record['body'],*record['wrappers']]):
        changes[f'member {index} FDE']=m['records']['fde']['file_offset']+12
        changes[f'member {index} CIE']=m['records']['cie']['file_offset']+15
        for ins in m['instructions']:
            at=m['file_offset']+ins['address']-m['begin'];changes[f'instruction {ins["address"]:x}']=at
            if len(bytes.fromhex(ins['bytes']))>1:changes[f'operand {ins["address"]:x}']=at+len(bytes.fromhex(ins['bytes']))-1
    body=record['body'];changes.update({'leaf preceding padding':body['file_offset']-1,'leaf following padding':body['file_offset']+30,'inner wrapper following padding':record['wrappers'][0]['file_offset']+13})
    for index,(caller,(begin,end,edges)) in enumerate(zip(record['callers'],CALLERS)):
        changes.update({f'caller {index} first':caller['file_offset'],f'caller {index} last':caller['file_offset']+caller['bytes']-1,
                        f'caller {index} FDE':caller['records']['fde']['file_offset']+12,f'caller {index} CIE':caller['records']['cie']['file_offset']+15})
        for site,_ in edges:changes[f'caller edge {site:x}']=caller['file_offset']+site-begin+1
    for i,n in enumerate(record['neighbors']):changes[f'neighbor {i} FDE']=n['records']['fde']['file_offset']+12
    # Shared CIE offsets are exercised once, not counted repeatedly.
    unique={}
    for label,at in changes.items():unique.setdefault(at,[]).append(label)
    rejected={}
    for at,labels in unique.items():
        label='; '.join(labels);changed=bytearray(data);changed[at]^=1
        try:
            other=inspect(bytes(changed));require({k:v for k,v in other.items()if k!='target_sha256'}=={k:v for k,v in record.items()if k!='target_sha256'},'structural drift')
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    image=Elf(data,3);rel=next(s for s in image.sections if s['type']==4)['offset']
    for label,at,replacement in [('introduced entry reference',rel+16,struct.pack('<q',START)),('partial code relocation',rel,struct.pack('<Q',START-3))]:
        changed=bytearray(data);changed[at:at+len(replacement)]=replacement
        try:inspect(bytes(changed))
        except ValueError as error:rejected[label]=str(error)
        else:raise ValueError('accepted corruption '+label)
    record['corruption_controls']=rejected
    return record


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--freeze',action='store_true');args=parser.parse_args();record=validate()
    if args.freeze:
        with(PACKET/'static.json').open('xb')as f:f.write(encoded(record))
    else:require((PACKET/'static.json').read_bytes()==encoded(record),'static drift')
    print(json.dumps({'members':3,'member_bytes':record['family_bytes'],'instructions':sum(len(m['instructions'])for m in [record['body'],*record['wrappers']]),'caller_instructions':sum(len(c['instructions'])for c in record['callers']),'caller_bytes':sum(c['bytes']for c in record['callers']),'controls':len(record['corruption_controls'])}))
if __name__=='__main__':main()
