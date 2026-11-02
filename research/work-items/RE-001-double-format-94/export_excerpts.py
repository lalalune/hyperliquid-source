#!/usr/bin/env python3
"""Regenerate the verbatim excerpt files of this packet from the target binary.

Usage: python3 export_excerpts.py [path-to-hl-node-94.bin]
Defaults to ../../../work/hl-node-94.bin relative to this file.
The output files are window.objdump.txt, plt.objdump.txt, callers.objdump.txt,
frames.txt and relocations.txt in this directory. Instruction-level detail
lives only in these raw excerpts; records.json carries semantic records.
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
BIN = (Path(sys.argv[1]) if len(sys.argv) > 1
       else PACKET / '..' / '..' / '..' / 'work' / 'hl-node-94.bin').resolve()
FN_START, FN_END = 0x514C050, 0x514C1B5
PLT_TARGETS = (0x5660100, 0x5660430, 0x56604D0, 0x5660A00)


def objdump(start, stop):
    r = subprocess.run(['objdump', '-d', f'--start-address={hex(start)}',
                        f'--stop-address={hex(stop)}', str(BIN)],
                       capture_output=True, text=True, check=True)
    return r.stdout


def main():
    (PACKET / 'window.objdump.txt').write_text(objdump(FN_START, 0x514C1C0))
    plt = objdump(0x5660100, 0x5660B00)
    keep = [l for l in plt.splitlines()
            if any(l.strip().startswith(hex(a)[2:]) or f'{a:x}:' in l for a in PLT_TARGETS)]
    (PACKET / 'plt.objdump.txt').write_text('\n'.join(keep) + '\n')
    data = BIN.read_bytes()
    out = subprocess.run(['readelf', '-SW', str(BIN)], capture_output=True, text=True, check=True).stdout
    m = re.search(r'\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', out)
    tva, toff, tsize = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)
    tdata = data[toff:toff + tsize]
    calls = []
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack_from('<i', tdata, i + 1)[0]
            if tva + i + 5 + rel == FN_START:
                calls.append(tva + i)
    frames = subprocess.run(['objdump', '--dwarf=frames', str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    fdes = re.findall(r'FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)', frames)

    def enclosing(addr):
        for a, b in fdes:
            if int(a, 16) <= addr < int(b, 16):
                return {'start': hex(int(a, 16)), 'end': hex(int(b, 16))}
        return None

    parts = []
    for c in calls:
        parts.append(f'--- call site {hex(c)} (enclosing FDE {enclosing(c)}) ---\n'
                     + objdump(c - 0x40, c + 0x10))
    (PACKET / 'callers.objdump.txt').write_text('\n'.join(parts))
    fde = [l for l in frames.splitlines() if 'pc=000000000514c050..000000000514c1b5' in l]
    assert len(fde) == 1
    (PACKET / 'frames.txt').write_text(fde[0] + '\n')
    rela = subprocess.run(['readelf', '-r', str(BIN)], capture_output=True, text=True, check=True).stdout
    got = [l.strip() for l in rela.splitlines() if '5778378' in l]
    assert len(got) == 1
    (PACKET / 'relocations.txt').write_text(got[0] + '\n')
    print(f'regenerated excerpts; {len(calls)} caller sites')


if __name__ == '__main__':
    main()
