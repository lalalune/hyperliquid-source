#!/usr/bin/env python3
"""Bind a second selected sender caller to the already measured context producer."""
import argparse
import copy
import json
from pathlib import Path
import struct
import subprocess

import capstone
import collect as first

START, END = 0x2b69d20, 0x2b6ae9f
DIRECT = {0x2b6a3a4: 0x2b782e0, 0x2b6a6a6: 0x2b7a290}
COPY_CALLS = [0x2b6a3cb, 0x2b6a533, 0x2b6a57f]


def check(image, anchors):
    for a in anchors:
        va = int(a['va'], 16)
        first.require(image.read(va, len(bytes.fromhex(a['bytes_hex']))).hex() == a['bytes_hex'],
                      'Changed followup span: '+a['name'])
    for va, target in DIRECT.items():
        raw = image.read(va, 5)
        first.require(raw[0] == 0xe8 and va+5+struct.unpack('<i', raw[1:])[0] == target, 'Followup direct call')
    for va in COPY_CALLS:
        raw = image.read(va, 6)
        first.require(raw[:2] == b'\xff\x15' and va+6+struct.unpack('<i', raw[2:])[0] == 0x64df508,
                      'Followup memcpy slot')
    raw = image.read(0x2b6a5ae, 7)
    first.require(raw[:3] == b'\x4c\x8b\x25' and 0x2b6a5b5+struct.unpack('<i', raw[3:])[0] == 0x64df508,
                  'Followup R12 import load')
    first.require(image.read(0x2b6a5ba, 3) == image.read(0x2b6a5ed, 3) == b'\x41\xff\xd4',
                  'Followup R12 calls')
    first.require(0x604b48+struct.unpack('<i', image.read(0x604b48, 4))[0] == 0x2b69da8,
                  'Followup initial dispatch')


def collect(out):
    data = (first.ROOT / 'artifacts/node/115/hl-node').read_bytes()
    first.authenticate(data)
    image = first.Image(data)
    # Re-authenticate the producer/constructor/socket route and imported copy contract.
    first.bindings(image, json.loads((first.PACKET / 'anchors.json').read_text()))
    anchors = json.loads((first.PACKET / 'followup-anchors.json').read_text())
    check(image, anchors)
    fdes = [f for f in image.fdes if f['start'] == START and f['end'] == END]
    first.require(len(fdes) == 1, 'Followup FDE extent')
    body = image.read(START, END-START)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins = list(md.disasm(body, START))
    first.require(sum(i.size for i in ins) == END-START, 'Followup incomplete decode')
    boundaries = {i.address for i in ins} | {END}
    for a in anchors:
        va = int(a['va'], 16)
        first.require(va in boundaries and va+len(bytes.fromhex(a['bytes_hex'])) in boundaries,
                      'Followup anchor boundary')
    out.mkdir(parents=True, exist_ok=False)
    rows, commands, versions = [], [], {'capstone': capstone.__version__}
    for tool, extra, filename in [('objdump', ['-z','--insn-width=16'], 'caller.gnu.objdump'),
                                  ('llvm-objdump', ['--disassemble-zeroes'], 'caller.llvm.objdump')]:
        versions[tool] = subprocess.check_output([tool,'--version'],cwd=first.ROOT).decode()
        args = [tool, '-d', *extra, f'--start-address={START}', f'--stop-address={END}', 'artifacts/node/115/hl-node']
        p = subprocess.run(args, cwd=first.ROOT, capture_output=True, check=True)
        (out / filename).write_bytes(p.stdout)
        (out / (filename+'.stderr')).write_bytes(p.stderr)
        native = first.native_rows(p.stdout, image, START, END)
        splits = first.compare_boundaries(native, ins)
        rows.append({'file':filename,'sha256':first.sha(p.stdout),'raw_rows':len(native),'lock_prefix_splits':splits})
        commands.append(args)
    (out/'caller.capstone.txt').write_text('\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n',encoding='utf-8',newline='\n')
    rejected = []
    for name, va in [(a['name'],int(a['va'],16)+len(bytes.fromhex(a['bytes_hex']))-1) for a in anchors]+[('initial-dispatch',0x604b48)]:
        changed = copy.copy(image)
        def read(start, size, va=va):
            raw = bytearray(image.read(start, size))
            if start <= va < start+size:
                raw[va-start] ^= 1
            return bytes(raw)
        changed.read = read
        try:
            check(changed, anchors)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Accepted followup corruption: '+name)
    record = {
        'target_sha256':first.TARGET,'source_base':'05bc2de303c05525b71e7e257426e741bc66a390',
        'captured_code_executed_or_emulated':False,'start':hex(START),'end':hex(END),
        'fde':hex(fdes[0]['fde']),'file_offset':image.offset(START,END-START),
        'length':END-START,'body_sha256':first.sha(body),'instructions':len(ins),
        'native':rows,'normalization_masks':[],
        'initial_input':{'tag':0,'word_value':4002,'store_va':'0x2b69dbb','field':'caller+0x86'},
        'input_pointer_route':['caller+0x80','caller+0x140 first qword','RCX -> caller+0x1a0','double dereference at 0x2b6a369/370','32 bytes copied to caller+0x278','producer 0x2b782e0'],
        'context_tail_copy_route':['producer result+0x10 -> caller+0x1e0 (inside 0x98-byte copy)','caller+0x1e0 -> stack+0x1a0','stack+0x1a0 -> stack+0x248','stack+0x248 -> stack+0x2d0','stack+0x2d0 -> caller+0xb0 (context+0x10)'],
        'sender_context':'caller+0xa0, passed in caller+0x178 with sender base caller+0x168',
        'conditional_port_value':4002,'eligible_by_port_predicate':True,
        'length_threshold_still_required':1025,'negative_controls_rejected':rejected,
        'limitations':['Selected initial path with normal helper/copy contracts and no unmodeled alias effects only','Retry/resume states and helper internals remain open','No recovered Rust type, network execution or full-caller census claim'],
    }
    for name, obj in [('records.json',record),('commands.json',commands),('versions.json',versions)]:
        (out/name).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'bytes':END-START,'instructions':len(ins),'rejected_controls':len(rejected),'port':4002}))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    collect(parser.parse_args().out)
