#!/usr/bin/env python3
"""Regenerate the verbatim excerpt files of this packet from the target binary.

Usage: python3 export_excerpts.py [path-to-hl-node-94.bin]
Defaults to ../../../work/hl-node-94.bin relative to this file.
The output files are window.objdump.txt, wrapper.objdump.txt,
cleanup-caller.objdump.txt, plt.objdump.txt, frames.txt and
relocations.txt in this directory. Instruction-level detail lives only
in these raw excerpts; records.json carries semantic records.
"""
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
BIN = (Path(sys.argv[1]) if len(sys.argv) > 1
       else PACKET / '..' / '..' / '..' / 'work' / 'hl-node-94.bin').resolve()
FN_START, FN_END = 0x514C1C0, 0x514C51D
WRAP_START, WRAP_END = 0x514C520, 0x514C57F
CLEAN_START, CLEAN_END = 0x5150BB0, 0x5150E4E
PLT_START, PLT_END = 0x5660440, 0x5660450


def objdump(start, stop):
    r = subprocess.run(['objdump', '-d', f'--start-address={hex(start)}',
                        f'--stop-address={hex(stop)}', str(BIN)],
                       capture_output=True, text=True, check=True)
    return r.stdout


def main():
    (PACKET / 'window.objdump.txt').write_text(objdump(FN_START, 0x514C520))
    (PACKET / 'wrapper.objdump.txt').write_text(objdump(WRAP_START, WRAP_END))
    (PACKET / 'cleanup-caller.objdump.txt').write_text(
        objdump(CLEAN_START, CLEAN_END))
    (PACKET / 'plt.objdump.txt').write_text(objdump(PLT_START, PLT_END))
    frames = subprocess.run(['readelf', '--debug-dump=frames-interp', str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    wanted = ('pc=000000000514c1c0..000000000514c51d',
              'pc=000000000514c520..000000000514c57f',
              'pc=0000000005150bb0..0000000005150e4e')
    fde = [l for l in frames.splitlines() if any(w in l for w in wanted)]
    assert len(fde) == 3, fde
    (PACKET / 'frames.txt').write_text('\n'.join(fde) + '\n')
    rela = subprocess.run(['readelf', '-r', str(BIN)],
                          capture_output=True, text=True, check=True).stdout
    got = [l.strip() for l in rela.splitlines() if '5778f48' in l]
    assert len(got) == 1, got
    (PACKET / 'relocations.txt').write_text(got[0] + '\n')
    print('regenerated excerpts')


if __name__ == '__main__':
    main()
