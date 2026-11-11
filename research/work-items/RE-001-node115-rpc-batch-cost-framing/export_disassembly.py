#!/usr/bin/env python3
"""Regenerate the static exports with GNU binutils and LLVM on PATH."""
import re
import subprocess
import tempfile
from pathlib import Path
import verify


def main():
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong node115 SHA-256')
    image = verify.Image(data)
    with tempfile.TemporaryDirectory(prefix='rpc-batch-cost-framing-static-') as temporary:
        snapshot = Path(temporary) / 'node115.elf'
        snapshot.write_bytes(data)
        export_snapshot(image, snapshot)
    verify.build(data)
    print('PASS: regenerated complete rpc-batch-cost-framing FDE bodies')


def export_snapshot(image, snapshot):
    for name, bounds in {**verify.BODIES, **verify.SUPPORT}.items():
        begin, end = bounds[:2]
        fs, fe = (begin, end) if name in verify.BODIES else bounds[2:]
        for provider, command in [('gnu', ['objdump', '-d', '-Mintel', '--insn-width=15']),
                                  ('llvm', ['llvm-objdump', '-d', '--x86-asm-syntax=intel'])]:
            # Start at the owning FDE, including for small retained caller windows.
            text = subprocess.check_output(command + [f'--start-address={hex(fs)}',
                       f'--stop-address={hex(fe)}', str(snapshot)], cwd=verify.ROOT, text=True)
            rows = []
            for line in text.splitlines():
                match = re.match(r'\s*([0-9a-f]+):', line)
                if match and begin <= int(match[1], 16) < end:
                    rows.append(line)
            header = f'# {provider}: full owning FDE {hex(fs)}..{hex(fe)} decoded; retained {hex(begin)}..{hex(end)}\n'
            (verify.PACKET / f'{name}.{provider}.txt').write_text(header + '\n'.join(rows) + '\n')
        verify.export_rows(image, name, begin, end)
    frame, = [s for s in image.sections if s['name'] == '.eh_frame']
    wanted = {v[2] - frame['address'] for v in verify.BODIES.values()}
    text = subprocess.check_output(['readelf', '--debug-dump=frames', str(snapshot)],
                                    cwd=verify.ROOT, text=True)
    selected = []
    for chunk in text.split('\n\n'):
        match = re.match(r'([0-9a-f]+) .*FDE ', chunk)
        if match and int(match[1], 16) in wanted:
            selected.append(chunk)
    verify.require(len(selected) == len(wanted), 'missing readelf FDE')
    (verify.PACKET / 'fdes.readelf.txt').write_text('\n\n'.join(selected) + '\n')


if __name__ == '__main__':
    main()
