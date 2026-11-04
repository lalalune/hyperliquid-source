#!/usr/bin/env python3
"""Export selected authenticated node115 static evidence to a new directory."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import verify

BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
SPEC = {'range': (23236048, 23236432), 'fde': 98064, 'rip': [(23236094, 7, 3), (23236406, 7, 3), (23236413, 6, 2), (23236419, 7, 3), (23236426, 6, 2)], 'slots': [105773128, 105772320], 'data': [(4636219, 400)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=verify.ROOT/'artifacts/node/115/hl-node')
    parser.add_argument('--objdump', default='/Library/Developer/CommandLineTools/usr/bin/llvm-objdump')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    verify.require(not args.output.exists(), 'output must be new')
    data = args.binary.read_bytes()
    verify.require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == verify.SHA, 'node115 full identity')
    elf = verify.Elf(data)
    start, end = SPEC['range']
    frame = elf.frame(SPEC['fde'])
    verify.require((int(frame['start'],16),int(frame['end'],16)) == (start,end), 'selected actual FDE')
    # Native tools see only a private byte-identical copy of the authenticated
    # data, avoiding a later read of an unverified mutable checkout path.
    with tempfile.TemporaryDirectory(prefix='node115-static-', dir=verify.ROOT/'work') as temporary:
        snapshot = Path(temporary)/'input.elf'
        snapshot.write_bytes(data)
        bodycmd = [args.objdump,'-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(snapshot)]
        body = subprocess.check_output(bodycmd,text=True).replace(str(snapshot),'artifacts/node/115/hl-node')
        framecmd = [args.objdump,'--dwarf=frames',str(snapshot)]
        allframes = subprocess.check_output(framecmd,text=True)
        marker = f"{SPEC['fde']:08x} "
        blocks = [b for b in allframes.split('\n\n') if b.startswith(marker)]
        verify.require(len(blocks) == 1, 'independent native FDE block')
        frames = blocks[0]+'\n'
    cursor, count = start, 0
    direct, branches, indirect = [], [], []
    for line in body.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if not match:
            continue
        va, raw = int(match[1],16), bytes.fromhex(match[2])
        verify.require(va == cursor and elf.read(va,len(raw)) == raw and '<unknown>' not in match[3], 'complete byte-exact native decode')
        cursor += len(raw); count += 1
        if len(raw) == 6 and raw[:2] == bytes.fromhex('ff15'):
            indirect.append(dict(site=hex(va),raw=raw.hex(),slot=hex(va+6+int.from_bytes(raw[2:],'little',signed=True))))
        if len(raw) == 5 and raw[0] in (0xe8,0xe9):
            direct.append(dict(site=hex(va),kind='call' if raw[0] == 0xe8 else 'jump',raw=raw.hex(),target=hex(va+5+int.from_bytes(raw[1:],'little',signed=True))))
        elif len(raw) == 2 and (raw[0] == 0xeb or 0x70<=raw[0]<=0x7f):
            branches.append(dict(site=hex(va),raw=raw.hex(),target=hex(va+2+int.from_bytes(raw[1:],'little',signed=True))))
        elif len(raw) == 6 and raw[0] == 0x0f and 0x80<=raw[1]<=0x8f:
            branches.append(dict(site=hex(va),raw=raw.hex(),target=hex(va+6+int.from_bytes(raw[2:],'little',signed=True))))
    verify.require(cursor == end, 'exact body endpoint')
    rip = []
    for site,width,disp in SPEC['rip']:
        raw = elf.read(site,width)
        rip.append(dict(site=hex(site),raw=raw.hex(),displacement_offset=disp,target=hex(site+width+int.from_bytes(raw[disp:disp+4],'little',signed=True))))
    record = dict(target_release=115,target_sha256=verify.SHA,target_size=len(data),source_commit=BASE,
                  coordinate_system='linked ELF virtual addresses; half-open ranges; section-resolved file offsets',
                  ranges=[dict(start=hex(start),end=hex(end),file_offset=hex(elf.offset(start,end-start)),sha256=hashlib.sha256(elf.read(start,end-start)).hexdigest())],
                  frames=[frame],direct_edges=direct,branch_edges=branches,indirect_calls=indirect,
                  bindings=[elf.binding(slot) for slot in SPEC['slots']],rip_references=rip,
                  data=[dict(va=hex(va),raw=elf.read(va,length).hex()) for va,length in SPEC['data']],
                  nobits_globals=[],retained_instruction_lines=count,
                  Python=platform.python_version(),platform=platform.system()+' '+platform.machine(),
                  LLVM_version=subprocess.check_output([args.objdump,'--version'],text=True).splitlines()[0],
                  native_input='private byte-identical authenticated snapshot; path labels normalized only',
                  captured_binary_executed=False,progress_gate_requested=False)
    args.output.mkdir(parents=True)
    (args.output/'body.objdump.txt').write_text(body)
    (args.output/'frames.txt').write_text(frames)
    (args.output/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(bytes=end-start,FDEs=1,instruction_lines=count,indirect_calls=len(indirect),branch_edges=len(branches))))


if __name__ == '__main__':
    main()
