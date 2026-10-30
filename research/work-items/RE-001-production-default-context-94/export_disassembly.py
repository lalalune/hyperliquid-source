"""Optional static export using Capstone 5.0.6; no target code is executed."""
from pathlib import Path
import struct
import sys

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import production_default_static as tool

if capstone.__version__ != '5.0.6':
    raise SystemExit('This retained decoder export pins Capstone 5.0.6')
data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
result = tool.build(data)
secs = tool.sections(data)
read = lambda va, size: tool.read_va(data, secs, va, size)
body = read(tool.START, tool.END - tool.START)
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
instructions = list(decoder.disasm(body, tool.START))
assert sum(i.size for i in instructions) == len(body)
assert all(a.address + a.size == b.address for a, b in zip(instructions, instructions[1:]))
assert len(instructions) == 68
lines = [f'Capstone {capstone.__version__}; x86-64 Intel syntax; static only',
         f'Target SHA-256 {tool.SHA256}',
         f'VA {tool.START:#x}..{tool.END:#x} exclusive; {len(body)} bytes; {len(instructions)} instructions',
         f'Body SHA-256 {tool.BODY_SHA256}']
for kind in ('fde_va', 'cie_va'):
    va = int(result['range'][kind], 16)
    size = struct.unpack('<I', read(va, 4))[0] + 4
    lines.append(f'{kind} {va:#x} raw {read(va, size).hex()}')
lines += [f'{i.address:#x} {i.bytes.hex():30} {i.mnemonic} {i.op_str}'.rstrip() for i in instructions]
output = Path(__file__).with_name('window.capstone.txt')
output.write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
print(f'Exported all {len(instructions)} instructions and raw FDE/CIE records; no execution.')
