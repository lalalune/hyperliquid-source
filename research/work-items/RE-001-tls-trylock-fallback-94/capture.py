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
    spans = [('fallback.objdump.txt', 0x552a500, 0x552a66e),
             ('caller.objdump.txt', 0x555a4ed, 0x555a4f7),
             ('caller.objdump.txt', 0x555a640, 0x555a656),
             ('plt.objdump.txt', 0x5660e70, 0x5660e80),
             ('plt.objdump.txt', 0x5660220, 0x5660230),
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
    frames = [elf.frame(o) for o in (0x2ca120,)]
    fullframes = subprocess.check_output([args.objdump,'--dwarf=frames',str(args.binary)],text=True)
    selected = [block for block in fullframes.split('\n\n') if any(s in block for s in ('002ca120 00000040',))]
    verify.require(len(selected) == 1, 'independent FDE export count')
    exports['frames.txt'] = '\n\n'.join(selected)+'\n'
    record = dict(target_release=94,target_sha256=verify.SHA,coordinate_system='ELF virtual addresses',source_commit='e5c9b6436876b2a4a39daef813171f9879317699',ranges=ranges,frames=frames,direct_edges=edges,branch_edges=branches,bindings=[elf.binding(a) for a in (0x5779460,0x5778e38,0x5778f40,0x576d968)],data=[dict(va=hex(0x5788178),raw=elf.read(0x5788178,8).hex())],nobits_globals=[dict(va=hex(a),width=w,section='.bss') for a,w in ((0x5799c70,4),(0x59b0de0,1),(0x59b0e20,1))],retained_instruction_lines=lines,captured_binary_executed=False,progress_gate_requested=False)
    record['rip_references'] = []
    for site, width, displacement_offset in ((0x552a525,7,3),(0x552a540,7,3),(0x552a5ee,7,3),(0x555a4ed,7,3),(0x5660e70,6,2),(0x5660220,6,2),(0x5660430,6,2)):
        raw = elf.read(site,width)
        record['rip_references'].append(dict(site=hex(site),raw=raw.hex(),displacement_offset=displacement_offset,target=hex(site+width+int.from_bytes(raw[displacement_offset:displacement_offset+4],'little',signed=True))))
    args.output.mkdir(parents=True)
    for name,text in exports.items():
        (args.output/name).write_text(text)
    (args.output/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(ranges=len(ranges),claimed_fdes=1,claimed_bytes=366,instruction_lines=lines,output_created=True)))


if __name__ == '__main__':
    main()
