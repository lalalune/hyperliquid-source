"""Optional independent Capstone5.0.6 regeneration; never execute the capture."""
from pathlib import Path
import sys

import capstone

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from consensus_latency_gate import SCOPES, check_identity, require
from elf_index import sections

if capstone.__version__ != '5.0.6':
    raise SystemExit('This export requires Capstone5.0.6')
data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
check_identity(data)
secs = sections(data)
decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
lines = ['# Capstone5.0.6 x86-64, full two FDE-described scopes, static only.']
count = 0
for start, end in SCOPES:
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= start
               and end <= s['address'] + s['size']]
    require(len(matches) == 1, 'No unique native scope mapping')
    offset = matches[0]['offset'] + start - matches[0]['address']
    body = data[offset:offset + end - start]
    cursor = start
    for ins in decoder.disasm(body, start):
        require(ins.address == cursor, 'Noncontiguous native decoding')
        cursor += ins.size
        count += 1
        lines.append(f'{ins.address:#x}\t{ins.bytes.hex()}\t{ins.mnemonic} {ins.op_str}')
    require(cursor == end, 'Incomplete native decoding')
retained = Path(__file__).with_name('capstone-5.0.6.txt').read_text(encoding='utf-8')
require('\n'.join(lines) + '\n' == retained, 'Retained native export differs')
print(f'Capstone{capstone.__version__}: {count} instructions /1411 bytes; byte-identical export.')
