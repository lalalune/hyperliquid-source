#!/usr/bin/env python3
"""Offline byte/FDE/edge verification. Never executes the captured program."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def require(ok, why):
    if not ok:
        raise ValueError(why)


class Elf:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b'\x7fELF\x02\x01', 'ELF64 LE identity')
        off = struct.unpack_from('<Q', data, 40)[0]
        stride, count, names = struct.unpack_from('<HHH', data, 58)
        require(stride >= 64 and count and names < count and off + stride * count <= len(data), 'section table bounds')
        rows = [struct.unpack_from('<IIQQQQIIQQ', data, off + stride * i) for i in range(count)]
        n = rows[names]
        strings = data[n[4]:n[4] + n[5]]
        self.sections = {}
        for row in rows:
            end = strings.find(b'\0', row[0])
            require(end >= row[0], 'section name')
            name = strings[row[0]:end].decode()
            require(name not in self.sections, 'duplicate section name')
            require(row[1] == 8 or row[4] + row[5] <= len(data), 'section file bounds')
            self.sections[name] = row

    def offset(self, va, size):
        rows = [r for r in self.sections.values() if r[1] != 8 and r[3] <= va and va + size <= r[3] + r[5]]
        require(len(rows) == 1, 'unambiguous file-backed VA')
        return rows[0][4] + va - rows[0][3]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def frame(self, relative):
        sec = self.sections['.eh_frame']
        va = sec[3] + relative
        length, back = struct.unpack('<II', self.read(va, 8))
        require(length >= 12 and relative + length + 4 <= sec[5], 'FDE bounds')
        cie = va + 4 - back
        require(self.read(cie, 24) == bytes.fromhex('1400000000000000017a5200017810011b0c070890010000'), 'supported zR pcrel-sdata4 CIE')
        delta, extent = struct.unpack('<iI', self.read(va + 8, 8))
        return dict(offset=hex(relative), start=hex(va + 8 + delta), end=hex(va + 8 + delta + extent), raw=self.read(va, length + 4).hex())

    def binding(self, slot):
        found = []
        for name in ('.rela.dyn', '.rela.plt'):
            sec = self.sections[name]
            require(sec[9] == 24 and sec[5] % 24 == 0, 'RELA entry size')
            for off in range(sec[4], sec[4] + sec[5], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                if dst == slot:
                    found.append((info, addend))
        require(len(found) == 1, 'unique selected relocation')
        info, addend = found[0]
        dyn = self.sections['.dynsym']
        names = list(self.sections.values())
        # The section link indexes original table order, retained by insertion order.
        st = names[dyn[6]]
        sym = struct.unpack_from('<IBBHQQ', self.data, dyn[4] + (info >> 32) * dyn[9])
        strings = self.data[st[4]:st[4] + st[5]]
        end = strings.index(b'\0', sym[0])
        return dict(slot=hex(slot), type=info & 0xffffffff, symbol=strings[sym[0]:end].decode(), addend=addend)


SPEC = {'name': 'format-result-adapter', 'ranges': [(21799920, 21800097, 30788)], 'pins': [(21799952, 'ff5018'), (21799960, '88442410'), (21799964, 'c644241100'), (21799998, 'ff158c560105'), (21800004, '0fb64c2410'), (21800009, '0fb6442411'), (21800016, 'f6d208caf6c201740a'), (21800025, '08c82401'), (21800040, 'f6401280'), (21800086, 'ff50182401')], 'data': [(4605415, '4572726f72'), (4562720, '6b696e64'), (4647214, '207d'), (4646988, '7d')], 'bindings': [105773776, 104828600], 'binding_values': [{'slot': '0x64dfad0', 'type': 8, 'symbol': '', 'addend': 23583056}, {'slot': '0x63f8eb8', 'type': 8, 'symbol': '', 'addend': 22979920}]}


def identity(data):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == SHA, 'full node115 identity')


def decode_lines(text):
    rows=[]
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)',line)
        if m:
            rows.append((int(m[1],16),bytes.fromhex(m[2])))
    return rows


def facts(data):
    elf=Elf(data)
    for va,raw in SPEC['pins']:
        require(elf.read(va,len(bytes.fromhex(raw))).hex()==raw,'instruction anchor '+hex(va))
    for va,raw in SPEC['data']:
        require(elf.read(va,len(bytes.fromhex(raw))).hex()==raw,'data anchor '+hex(va))
    frames=[elf.frame(offset) for start,end,offset in SPEC['ranges']]
    for frame,(start,end,offset) in zip(frames,SPEC['ranges']):
        require(frame['start']==hex(start) and frame['end']==hex(end),'FDE measured extent')
    bindings=[elf.binding(slot) for slot in SPEC['bindings']]
    require(bindings==SPEC['binding_values'],'selected relocation bindings')
    result=dict(target='node115',sha256=SHA,base='05bc2de303c05525b71e7e257426e741bc66a390',
      ranges=[dict(start=hex(a),end=hex(b),length=b-a,file_offset=hex(elf.offset(a,b-a)),sha256=hashlib.sha256(elf.read(a,b-a)).hexdigest(),raw=elf.read(a,b-a).hex()) for a,b,_ in SPEC['ranges']],
      frames=frames,bindings=bindings,pins=[dict(va=hex(a),raw=b) for a,b in SPEC['pins']],
      data=[dict(va=hex(a),raw=b) for a,b in SPEC['data']],captured_binary_executed=False)
    if 'jump_table' in SPEC:
        table=SPEC['jump_table']
        result['table']=[dict(raw_index=i,entry=hex(table+4*i),signed_offset=v,target=hex(table+v)) for i,v in enumerate(struct.unpack('<12i',elf.read(table,48)))]
    return elf,result


def export(data,objdump):
    elf,record=facts(data)
    native={}; lines=[]; covered=set(); edges=[]; rips=[]
    # Export a private byte-identical authenticated snapshot, never the target as a program.
    with tempfile.TemporaryDirectory(prefix='static-export-',dir=ROOT/'work') as tmp:
        snapshot=Path(tmp)/'authenticated-node115'; snapshot.write_bytes(data)
        for i,(start,end,_) in enumerate(SPEC['ranges']):
            proc=subprocess.run([str(objdump),'-d','--start-address='+hex(start),'--stop-address='+hex(end),str(snapshot)],check=True,capture_output=True,text=True)
            text=proc.stdout.replace(str(snapshot),'<authenticated-node115>')
            native['owner'+str(i)+'.objdump.txt']=text
            rows=decode_lines(text); lines.extend(rows)
            for va,raw in rows:
                require(start<=va and va+len(raw)<=end,'native instruction in exact FDE')
                require(elf.read(va,len(raw))==raw,'native/raw instruction binding')
                byte_set=set(range(va,va+len(raw))); require(not byte_set&covered,'unique native byte coverage'); covered.update(byte_set)
                if raw[0] in (0xe8,0xe9) and len(raw)==5:
                    edges.append(dict(site=hex(va),raw=raw.hex(),kind='direct',target=hex(va+5+struct.unpack('<i',raw[1:])[0])))
                elif (len(raw)==2 and (0x70<=raw[0]<=0x7f or raw[0]==0xeb)) or (len(raw)==6 and raw[0]==15 and 0x80<=raw[1]<=0x8f):
                    offset=1 if len(raw)==2 else 2
                    edges.append(dict(site=hex(va),raw=raw.hex(),kind='branch',target=hex(va+len(raw)+int.from_bytes(raw[offset:],'little',signed=True))))
                elif len(raw)==6 and raw[:2] in (b'\xff\x15',b'\xff\x25'):
                    edges.append(dict(site=hex(va),raw=raw.hex(),kind='RIP-indirect',slot=hex(va+6+struct.unpack('<i',raw[2:])[0])))
                elif len(raw)==7 and raw[0] in (0x48,0x4c) and raw[1]==0x8d and raw[2]&0xc7==5:
                    rips.append(dict(site=hex(va),raw=raw.hex(),target=hex(va+7+struct.unpack('<i',raw[3:])[0])))
        require(covered=={v for a,b,_ in SPEC['ranges'] for v in range(a,b)},'complete FDE native coverage')
    record.update(instruction_rows=len(lines),edges=edges,rip_references=rips,native_tool_version=subprocess.run([str(objdump),'--version'],check=True,capture_output=True,text=True).stdout.strip(),python_version=sys.version.split()[0])
    native['evidence.json']=json.dumps(record,indent=2)+'\n'
    native['frames.json']=json.dumps(record['frames'],indent=2)+'\n'
    return native,record


def verify(data):
    elf,record=facts(data)
    saved=json.loads((HERE/'evidence.json').read_text())
    for key,value in record.items(): require(saved[key]==value,'saved '+key)
    for row in saved['edges']:
        va=int(row['site'],16); raw=bytes.fromhex(row['raw'])
        require(elf.read(va,len(raw))==raw,'saved edge bytes')
        if row['kind']=='direct':
            require(len(raw)==5 and raw[0] in (0xe8,0xe9),'direct edge shape'); offset=1
        elif row['kind']=='branch':
            require((len(raw)==2 and (0x70<=raw[0]<=0x7f or raw[0]==0xeb)) or (len(raw)==6 and raw[0]==15 and 0x80<=raw[1]<=0x8f),'branch edge shape'); offset=1 if len(raw)==2 else 2
        else:
            require(len(raw)==6 and raw[:2] in (b'\xff\x15',b'\xff\x25'),'RIP edge shape'); offset=2
        target=hex(va+len(raw)+int.from_bytes(raw[offset:],'little',signed=True))
        require(target==row['slot' if row['kind']=='RIP-indirect' else 'target'],'saved edge target')
    for row in saved['rip_references']:
        va=int(row['site'],16); raw=bytes.fromhex(row['raw'])
        require(len(raw)==7 and raw[0] in (0x48,0x4c) and raw[1]==0x8d and raw[2]&0xc7==5,'saved RIP shape')
        require(elf.read(va,7)==raw and hex(va+7+struct.unpack('<i',raw[3:])[0])==row['target'],'saved RIP target')
    require(json.loads((HERE/'frames.json').read_text())==saved['frames'],'retained frames export')
    rows=[]
    for i in range(len(SPEC['ranges'])):
        rows.extend(decode_lines((HERE/('owner'+str(i)+'.objdump.txt')).read_text()))
    covered=set()
    for va,raw in rows:
        require(elf.read(va,len(raw))==raw,'retained native bytes')
        span=set(range(va,va+len(raw))); require(not covered&span,'retained native duplicate'); covered.update(span)
    require(covered=={v for a,b,_ in SPEC['ranges'] for v in range(a,b)},'retained full FDE coverage')
    require(len(rows)==saved['instruction_rows'],'retained line count')
    return elf,saved


def controls(data,elf):
    cases=[]
    def rejected(label,category,changed,action):
        try: action(changed)
        except (ValueError,IndexError,struct.error) as error:
            cases.append(dict(label=label,category=category,rejected=True,reason=str(error)))
        else: raise ValueError('escaped negative control '+label)
    changed=bytearray(data); changed[0]^=1
    rejected('full-identity','full-image hash/identity',changed,identity)
    # Deliberately bypass full-image hash for exact operand/data/FDE/RELA controls;
    # facts runs before any body-hash or retained-disassembly comparison.
    for va,raw in SPEC['pins']:
        changed=bytearray(data); changed[elf.offset(va+len(bytes.fromhex(raw))-1,1)]^=1
        rejected('operand-'+hex(va),'below full/body hashes: exact selected anchor',changed,facts)
    for va,raw in SPEC['data']:
        changed=bytearray(data); changed[elf.offset(va,1)]^=1
        rejected('data-'+hex(va),'below full/body hashes: selected data',changed,facts)
    for _,_,offset in SPEC['ranges']:
        changed=bytearray(data); changed[elf.offset(elf.sections['.eh_frame'][3]+offset+12,1)]^=1
        rejected('FDE-'+hex(offset),'below full/body hashes: measured extent',changed,facts)
    for slot in SPEC['bindings']:
        offsets=[]
        for name in ('.rela.dyn','.rela.plt'):
            sec=elf.sections[name]
            offsets.extend(off for off in range(sec[4],sec[4]+sec[5],24) if struct.unpack_from('<Q',data,off)[0]==slot)
        require(len(offsets)==1,'negative RELA uniqueness')
        changed=bytearray(data); changed[offsets[0]+16]^=1
        rejected('RELA-'+hex(slot),'below full/body hashes: exact binding',changed,facts)
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/115/hl-node')
    parser.add_argument('--objdump',type=Path,default=Path('/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'))
    parser.add_argument('--output',type=Path)
    parser.add_argument('--negative-controls',action='store_true')
    args=parser.parse_args(); data=args.binary.read_bytes(); identity(data)
    if args.output:
        require(not args.output.exists(),'fresh output directory required')
        outputs,record=export(data,args.objdump)
        args.output.mkdir(parents=True)
        for name,text in outputs.items(): (args.output/name).write_text(text)
        print(json.dumps(dict(captured_binary_executed=False,instruction_rows=record['instruction_rows'],output_files=list(outputs)),indent=2))
    else:
        elf,saved=verify(data)
        result=dict(identity='PASS',structural='PASS',instruction_rows=saved['instruction_rows'],captured_binary_executed=False,full_required_suite_run=False)
        if args.negative_controls: result['controls']=controls(data,elf)
        print(json.dumps(result,indent=2))


if __name__=='__main__': main()
