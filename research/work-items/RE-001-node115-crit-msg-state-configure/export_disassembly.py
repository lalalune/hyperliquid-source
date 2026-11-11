#!/usr/bin/env python3
"""Regenerate the GNU and LLVM exports and the readelf FDE excerpt (needs both toolchains on PATH)."""
import re
import subprocess
import tempfile
from pathlib import Path

import verify


def main():
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong node115 SHA-256')
    image = verify.Image(data)
    with tempfile.TemporaryDirectory(prefix='crit-msg-state-configure-') as temporary:
        snapshot = Path(temporary) / 'node115.elf'
        snapshot.write_bytes(data)
        snapshot.chmod(0o444)
        export(snapshot)
        fdes(image, snapshot)
    for name, (begin, end) in verify.windows().items():
        verify.export_rows(image, name, begin, end)
    print('PASS: regenerated crit_msg_state configure exports')


def export(snapshot):
    for name, (begin, end, fs, fe) in verify.all_windows().items():
        for provider, command in (('gnu', ['objdump', '-d', '-Mintel', '--insn-width=15']),
                                  ('llvm', ['llvm-objdump', '-d', '--x86-asm-syntax=intel'])):
            text = subprocess.check_output(command + [f'--start-address={fs:#x}', f'--stop-address={fe:#x}',
                                                      str(snapshot)], text=True)
            rows = [line for line in text.splitlines()
                    if (m := re.match(r'\s*([0-9a-f]+):', line)) and begin <= int(m[1], 16) < end]
            header = f'# {provider}: owning FDE {fs:#x}..{fe:#x} decoded; retained {begin:#x}..{end:#x}\n'
            (verify.PACKET / f'{name}.{provider}.txt').write_text(header + '\n'.join(rows) + '\n')


def fdes(image, snapshot):
    frame, = [s for s in image.sections if s['name'] == '.eh_frame']
    wanted = {fde - frame['address'] for fde in verify.fde_records(image).values()}
    text = subprocess.check_output(['readelf', '--debug-dump=frames', str(snapshot)], text=True)
    chunks = [c for c in text.split('\n\n') if (m := re.match(r'([0-9a-f]+) .*FDE ', c)) and int(m[1], 16) in wanted]
    verify.require(len(chunks) == len(wanted), 'missing readelf FDE')
    (verify.PACKET / 'fdes.readelf.txt').write_text('\n\n'.join(chunks) + '\n')


if __name__ == '__main__':
    main()
