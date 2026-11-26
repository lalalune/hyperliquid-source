#!/usr/bin/env python3
"""Export complete retained FDEs through GNU and LLVM disassemblers."""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import verify


def main():
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target digest')
    verify.require(len(data) == verify.SIZE, 'wrong target size')
    gnu_objdump = shutil.which('gobjdump') or shutil.which('objdump')
    gnu_readelf = shutil.which('greadelf') or shutil.which('readelf')
    llvm_objdump = shutil.which('llvm-objdump')
    if not llvm_objdump and shutil.which('xcrun'):
        llvm_objdump = 'xcrun llvm-objdump'
    verify.require(gnu_objdump and gnu_readelf and llvm_objdump,
                   'GNU binutils and LLVM objdump must be on PATH')
    version = subprocess.check_output([gnu_objdump, '--version'], text=True).splitlines()[0]
    verify.require('GNU objdump' in version, 'GNU objdump is required, found: ' + version)
    with tempfile.TemporaryDirectory(prefix='vault-query-future-static-') as tmp:
        snap = Path(tmp) / 'node115.elf'
        snap.write_bytes(data)
        for name, (start, end) in verify.BODIES.items():
            for provider, command in (
                ('gnu', [gnu_objdump, '-d', '-Mintel', '--insn-width=15']),
                ('llvm', llvm_objdump.split() + ['-d', '--x86-asm-syntax=intel']),
            ):
                result = subprocess.check_output(
                    command + [f'--start-address={hex(start)}', f'--stop-address={hex(end)}', str(snap)],
                    text=True,
                )
                rows = []
                for line in result.splitlines():
                    match = re.match(r'\s*([0-9a-f]+):', line)
                    if match and start <= int(match[1], 16) < end:
                        rows.append(line)
                parsed = []
                cursor = start
                for line in rows:
                    match = re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)', line)
                    verify.require(match is not None, f'{provider} byte row: {name}')
                    va = int(match[1], 16)
                    raw = bytes.fromhex(match[2])
                    verify.require(va == cursor, f'{provider} gap/overlap: {name}')
                    verify.require(verify.Image(data).get(va, len(raw)) == raw,
                                   f'{provider} byte mismatch: {name}')
                    parsed.append((va, raw))
                    cursor += len(raw)
                verify.require(cursor == end, f'{provider} incomplete decode: {name}')
                if provider == 'gnu':
                    gnu_rows = parsed
                else:
                    verify.require(parsed == gnu_rows, f'GNU/LLVM boundaries differ: {name}')
                (verify.PACKET / f'{name}.{provider}.txt').write_text(
                    f'# {provider}: complete FDE {hex(start)}..{hex(end)}\n' + '\n'.join(rows) + '\n'
                )
        frames = subprocess.check_output(
            [gnu_readelf, '--debug-dump=frames', str(snap)], text=True
        )
        selected = []
        for chunk in frames.split('\n\n'):
            if any(f'pc={start:016x}..{end:016x}' in chunk
                   for start, end in verify.BODIES.values()):
                selected.append(chunk)
        verify.require(len(selected) == len(verify.BODIES), 'missing readelf FDE')
        (verify.PACKET / 'fdes.gnu.txt').write_text('\n\n'.join(selected) + '\n')
    verify.main()


if __name__ == '__main__':
    main()
