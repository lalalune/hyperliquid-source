#!/usr/bin/env python3
"""Re-export these selected static ranges to a new directory; no target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=verify.ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--objdump', default='llvm-objdump')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    verify.require(not args.output.exists(), 'output must be new')
    data = args.binary.read_bytes()
    verify.require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == verify.SHA, 'node94 identity')
    elf = verify.Elf(data)
    spans = [('global-init.objdump.txt', 0x555aa30, 0x555aaa7),
             ('mutex-init.objdump.txt', 0x552a6c0, 0x552a77c),
             ('plt.objdump.txt', 0x56602f0, 0x5660300),
             ('plt.objdump.txt', 0x5661180, 0x56611b0),
             ('plt.objdump.txt', 0x5660b70, 0x5660b80),
             ('plt.objdump.txt', 0x5660430, 0x5660440)]
    exports = {}
    for name, start, end in spans:
        text = subprocess.check_output([args.objdump, '-d', f'--start-address={start:#x}', f'--stop-address={end:#x}', str(args.binary)], text=True)
        # Keep repository-relative naming independent of the materialized copy's location.
        text = text.replace(str(args.binary), 'artifacts/node/94/hl-node')
        exports[name] = exports.get(name, '') + text
    edges, branches, lines = [], [], 0
    for text in exports.values():
        for line in text.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
            if not match:
                continue
            lines += 1
            va, raw = int(match[1],16), bytes.fromhex(match[2])
            verify.require(elf.read(va,len(raw)) == raw, 'decoder raw bytes')
            if len(raw) == 5 and raw[0] in (0xe8,0xe9):
                edges.append(dict(site=hex(va), kind='call' if raw[0] == 0xe8 else 'jump', target=hex(va+5+int.from_bytes(raw[1:],'little',signed=True)),raw=raw.hex()))
            elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
                branches.append(dict(site=hex(va),raw=raw.hex(),target=hex(va+2+int.from_bytes(raw[1:],'little',signed=True))))
            elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
                branches.append(dict(site=hex(va),raw=raw.hex(),target=hex(va+6+int.from_bytes(raw[2:],'little',signed=True))))
    ranges = [dict(start=hex(a),end=hex(b),file_offset=hex(elf.offset(a,b-a)),sha256=hashlib.sha256(elf.read(a,b-a)).hexdigest()) for _,a,b in spans]
    frames = [elf.frame(o) for o in (0x2cf908,0x2ca18c)]
    fullframes = subprocess.check_output([args.objdump,'--dwarf=frames',str(args.binary)],text=True)
    selected = [block for block in fullframes.split('\n\n') if any(s in block for s in ('002cf908 0000001c','002ca18c 00000028'))]
    verify.require(len(selected) == 2, 'independent FDE export count')
    exports['frames.txt'] = '\n\n'.join(selected)+'\n'
    record = dict(target_release=94,target_sha256=verify.SHA,coordinate_system='ELF virtual addresses',source_commit='e5c9b6436876b2a4a39daef813171f9879317699',ranges=ranges,frames=frames,direct_edges=edges,branch_edges=branches,bindings=[elf.binding(a) for a in (0x5778ea0,0x57795e8,0x57795f0,0x57795f8,0x57792e0,0x5778f40)],data=[],nobits_globals=[dict(va=hex(a),width=w,section='.bss') for a,w in ((0x59b0de0,1),(0x59b0e20,1),(0x59b0e5c,4),(0x59b0e58,1))],retained_instruction_lines=lines,captured_binary_executed=False,progress_gate_requested=False)
    record['rip_references'] = []
    for site, width, displacement_offset in ((0x555aa3a,7,3),(0x555aa43,7,3),(0x555aa53,7,3),(0x555aa5a,7,3),(0x555aa71,7,2),(0x552a6c9,7,3),(0x56602f0,6,2),(0x5661180,6,2),(0x5661190,6,2),(0x56611a0,6,2),(0x5660b70,6,2),(0x5660430,6,2)):
        raw = elf.read(site,width)
        record['rip_references'].append(dict(site=hex(site),raw=raw.hex(),displacement_offset=displacement_offset,target=hex(site+width+int.from_bytes(raw[displacement_offset:displacement_offset+4],'little',signed=True))))
    args.output.mkdir(parents=True)
    for name,text in exports.items():
        (args.output/name).write_text(text)
    (args.output/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(ranges=len(ranges),claimed_fdes=2,claimed_bytes=307,instruction_lines=lines,output_created=True)))


if __name__ == '__main__':
    main()
