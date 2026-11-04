#!/usr/bin/env python3
"""Recover a bounded #115 read-32 leaf using strict instruction encodings."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x5821430, 0x58214a3
TEXT_START, TEXT_END = 0x1419300, 0x63f0a00
FDE, CIE = 0xf9c4a4, 0xca6ed8
EXPECTED_CALLERS = [0x4e04ea7, 0x4e182ed, 0x5434b3d, 0x5968dd8, 0x5ad0abc]
# Each item is the exact instruction encoding and its architectural operation.
# Conditional branch operands are decoded independently from their signed displacement.
OPS = [
 ('4889f8','mov rax,rdi'), ('833e01','cmp dword [rsi],1'), ('7524','jne 0x582145c'),
 ('488b4e20','mov rcx,[rsi+0x20]'), ('4883f9df','cmp rcx,-33 (unsigned)'),
 ('7711','ja 0x5821453'), ('488b5608','mov rdx,[rsi+8]'),
 ('4883c120','add rcx,32'), ('48894e20','mov [rsi+0x20],rcx'),
 ('4839d1','cmp rcx,rdx'), ('7609','jbe 0x582145c'),
 ('c6400802','mov byte [rax+8],2'), ('b101','mov cl,1'),
 ('8808','mov byte [rax],cl'), ('c3','ret'),
 ('488b4e18','mov rcx,[rsi+0x18]'), ('4883f91f','cmp rcx,31'),
 ('7715','ja 0x582147b'), ('ba20000000','mov edx,32'),
 ('4829ca','sub rdx,rcx'), ('c6400800','mov byte [rax+8],0'),
 ('48895010','mov [rax+0x10],rdx'), ('b101','mov cl,1'),
 ('8808','mov byte [rax],cl'), ('c3','ret'),
 ('488b5610','mov rdx,[rsi+0x10]'), ('488d7a20','lea rdi,[rdx+32]'),
 ('4883c1e0','add rcx,-32'), ('48897e10','mov [rsi+0x10],rdi'),
 ('48894e18','mov [rsi+0x18],rcx'), ('0f1002','movups xmm0,[rdx]'),
 ('0f104a10','movups xmm1,[rdx+0x10]'), ('0f114811','movups [rax+0x11],xmm1'),
 ('0f114001','movups [rax+1],xmm0'), ('31c9','xor ecx,ecx'),
 ('8808','mov byte [rax],cl'), ('c3','ret'),
]


def decode(body):
    """Reject any unrecognized byte, operand, immediate, branch or extent."""
    rows, pc = [], START
    for encoded, operation in OPS:
        expected = bytes.fromhex(encoded)
        offset = pc - START
        actual = body[offset:offset + len(expected)]
        if actual != expected:
            raise ValueError('Instruction or operand changed at %#x' % pc)
        row = {'address': pc, 'bytes': encoded, 'operation': operation}
        if expected[0] in (0x75, 0x77, 0x76):
            target = pc + 2 + struct.unpack('b', actual[1:2])[0]
            if operation.split()[-1] != hex(target):
                raise ValueError('Branch target changed')
            row['target'] = target
        rows.append(row)
        pc += len(expected)
    if pc != END or len(body) != END - START:
        raise ValueError('Instruction extent changed')
    boundaries = {r['address'] for r in rows}
    if any(r['target'] not in boundaries for r in rows if 'target' in r):
        raise ValueError('Branch to non-instruction boundary')
    return rows


def check_fde(fdes):
    matches = [f for f in fdes if f['start'] == START]
    expected = {'fde': FDE, 'cie': CIE, 'start': START, 'end': END, 'lsda': None}
    if matches != [expected]:
        raise ValueError('FDE identity or extent changed')
    if [f for f in fdes if f['start'] < END and f['end'] > START] != [expected]:
        raise ValueError('Overlapping FDE extent')
    ordered = sorted(fdes, key=lambda f: f['start'])
    i = next(i for i, f in enumerate(ordered) if f == expected)
    if ordered[i-1]['end'] != START - 11 or ordered[i+1]['start'] != END + 13:
        raise ValueError('Neighboring FDE bounds changed')
    return expected


def direct_target(site, encoding):
    if len(encoding) != 5 or encoding[0] not in (0xe8, 0xe9):
        raise ValueError('Not a direct rel32 call or jump')
    return site + 5 + struct.unpack('<i', encoding[1:])[0]


def validate_caller(site, encoding):
    if site not in EXPECTED_CALLERS or encoding[0] != 0xe8 or direct_target(site, encoding) != START:
        raise ValueError('Unexpected direct call target or site')


def scan_callers(data, text_offset):
    out = []
    limit = text_offset + TEXT_END - TEXT_START
    for opcode in (b'\xe8', b'\xe9'):
        pos = text_offset
        while True:
            pos = data.find(opcode, pos, limit - 4)
            if pos < 0:
                break
            site = TEXT_START + pos - text_offset
            enc = data[pos:pos+5]
            if direct_target(site, enc) == START:
                out.append({'site': site, 'kind': 'call' if opcode == b'\xe8' else 'jump', 'bytes': enc.hex()})
            pos += 1
    out.sort(key=lambda x: x['site'])
    if [r['site'] for r in out] != EXPECTED_CALLERS or any(r['kind'] != 'call' for r in out):
        raise ValueError('Direct-branch census changed')
    for row in out:
        validate_caller(row['site'], bytes.fromhex(row['bytes']))
    return out


def model(mode, count, limit, remaining, payload):
    """Model observable writes, assuming nonoverlapping, valid native memory."""
    max64 = (1 << 64) - 1
    if not 0 <= mode < (1 << 32):
        raise ValueError('mode must be the low 32-bit word')
    if any(not 0 <= n <= max64 for n in (count, limit, remaining)):
        raise ValueError('u64 input required')
    next_count = count
    if mode == 1:
        if count > max64 - 32:
            return {'tag': 1, 'error': 2, 'count': count, 'remaining': remaining}
        next_count = count + 32
        if next_count > limit:
            return {'tag': 1, 'error': 2, 'count': next_count, 'remaining': remaining}
    if remaining < 32:
        return {'tag': 1, 'error': 0, 'missing': 32 - remaining, 'count': next_count, 'remaining': remaining}
    if len(payload) < 32:
        raise ValueError('readable payload must contain 32 bytes')
    return {'tag': 0, 'value': payload[:32], 'count': next_count, 'remaining': remaining - 32, 'advance': 32}


def extract(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node #115 digest mismatch')
    secs = sections(data)
    text = [s for s in secs if s['name'] == '.text']
    if len(text) != 1 or text[0]['address'] != TEXT_START or text[0]['size'] != TEXT_END-TEXT_START or not text[0]['flags'] & 4:
        raise ValueError('Unexpected text section')
    off = text[0]['offset'] + START - TEXT_START
    body = data[off:off+END-START]
    insns = decode(body)
    cies, fdes = eh_frame_records(data, secs)
    fde = check_fde(fdes)
    if cies[CIE]['augmentation'] != 'zR' or cies[CIE]['fde_encoding'] != 0x1b:
        raise ValueError('Unexpected CIE')
    if data[off-11:off] != b'\xcc'*11 or data[off+len(body):off+len(body)+13] != b'\xcc'*13:
        raise ValueError('Padding changed')
    callers = scan_callers(data, text[0]['offset'])
    return {'target_sha256': SHA, 'target_size': len(data), 'coordinate': 'ELF virtual address',
            'window': {'start': START, 'end': END, 'size': len(body), 'file_offset': off,
                       'sha256': hashlib.sha256(body).hexdigest(), 'fde': fde,
                       'cie': cies[CIE], 'padding_before_int3': 11, 'padding_after_int3': 13},
            'instructions': insns, 'callees': [], 'raw_direct_branches_to_entry': callers,
            'text_scan': {'start': TEXT_START, 'end': TEXT_END, 'method': 'every byte e8/e9 with signed rel32'},
            'rule': {'read_bytes': 32, 'mode_test_bits': 32, 'limit_counter_bits': 64,
                     'success_tag': 0, 'error_tag': 1, 'limit_error': 2, 'short_error': 0}}


def render_readme(r):
    w = r['window']; n = len(r['instructions']); callers = r['raw_direct_branches_to_entry']
    walk = '\n'.join(f"- `0x{x['address']:x}` `{x['bytes']}`: `{x['operation']}`" for x in r['instructions'])
    sites = ', '.join('`0x%x`' % x['site'] for x in callers)
    return f'''# RE-001: node #115 checked 32-byte read

- Component: RE-001 function map; serialization is a possible use, not established ownership.
- Target: Linux x86-64 node #115, SHA-256 `{SHA}`; {r['target_size']} bytes.
- Source/base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no source implementation is claimed.
- Bounded question: what state and output does the function at `0x{START:x}` produce when asked to read its fixed-width value?
- Scope: valid, nonoverlapping state, output, and readable input memory; arithmetic and memory writes of this one leaf only.

The function reads 32 bytes or writes an error. If the low 32-bit mode is 1, it checks whether adding 32 to the u64 counter at state +0x20 would overflow; overflow returns tag 1/error 2 without updating the counter. Otherwise it stores the incremented counter and returns tag 1/error 2 if it exceeds the u64 limit at +8. Next, for any mode, fewer than 32 bytes at the u64 length at +0x18 returns tag 1/error 0 and the missing count at output +0x10. This short-input return retains any counter increment already made. With at least 32 bytes, it advances the pointer at state +0x10 by 32, reduces the length by 32, copies the original 32 bytes to output +1, and writes tag 0. The return register is the original output pointer. Output bytes not explicitly written are unspecified by this function.

## Evidence and instruction walk

All addresses are original ELF virtual addresses; `.text` file offset differs by 0x1000. The complete window is `0x{START:x}..0x{END:x}`, {w['size']} bytes, file offset `0x{w['file_offset']:x}`, SHA-256 `{w['sha256']}`. The FDE at `0x{FDE:x}` points to CIE `0x{CIE:x}` (zR, pcrel sdata4), has no LSDA, and covers exactly the window. The nearest FDEs end {w['padding_before_int3']} bytes before and begin {w['padding_after_int3']} bytes after; both intervening regions consist solely of INT3. Every path in the instruction walk below returns within the FDE. There are {len(r['callees'])} callees and no indirect transfers. The {n} instructions and all branch operands are decoded by exact encoding; the signed branch targets must land on listed instruction boundaries.

{walk}

The complete `.text` bytewise scan for E8/E9 signed rel32 encodings targeting the entry yields {len(callers)} matches: {sites}. All are E8 call encodings; focused disassembly shows these are call instructions in their surrounding functions. A bytewise scan can include false positives embedded in other instructions; it does not find indirect calls, other entry points, or prove a complete call graph. No external call or tail jump is in the bound body.

## Reproduction and novelty

Python 3.10+ standard library; ELF and unwind parsers in the repository; no captured executable is run. From repository root:

```sh
python3 tools/node115_checked_read32.py --out research/work-items/RE-001-node115-checked-read32/
python3 -m unittest tests.test_node115_checked_read32 -v
python3 research/work-items/RE-001-node115-checked-read32/verify.py
```

Before analysis, `rg -in '5821430|92410928' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt` returned no matches. There are no callee addresses requiring a separate novelty check. After adding this packet the same search naturally finds this work. No normalizations or byte masks are used.

## Limits and next step

This is an instruction-derived static theorem, not execution, a Rust reconstruction, an original source name, field identity, a protocol definition, or a full decoder. The proof assumes native pointers are valid and nonoverlapping; faults, wrapping pointer arithmetic, unwind behavior and aliasing are outside the model. The actual caller roles, initialization invariants, indirect references and whether this belongs to first-party code are unknown. No build, source comparison, whole-ELF equivalence, component gate, or progress change is claimed. Next, bind a caller's input construction and error handling to determine the format and provenance of the 32-byte field. New tool, model and prose are independently authored under the repository MIT license.
'''


VERIFY = '''#!/usr/bin/env python3
"""Check the packet whitelist, hashes, and freshly generated evidence."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

here = Path(__file__).resolve().parent
root = here.parents[2]
allowed = {'README.md', 'records.json', 'verify.py'}
if {p.name for p in here.iterdir()} != allowed | {'MANIFEST.sha256'}:
    raise SystemExit('Unexpected packet files')
rows = (here / 'MANIFEST.sha256').read_text().splitlines()
expected = {}
for row in rows:
    digest, name = row.split('  ', 1)
    if name not in allowed or name in expected or len(digest) != 64:
        raise SystemExit('Invalid manifest whitelist')
    expected[name] = digest
if set(expected) != allowed:
    raise SystemExit('Incomplete manifest')
for name, digest in expected.items():
    if hashlib.sha256((here / name).read_bytes()).hexdigest() != digest:
        raise SystemExit('Manifest mismatch: ' + name)
with tempfile.TemporaryDirectory() as tmp:
    subprocess.run([sys.executable, str(root / 'tools/node115_checked_read32.py'), '--out', tmp], check=True)
    for name in allowed | {'MANIFEST.sha256'}:
        if (here / name).read_bytes() != (Path(tmp) / name).read_bytes():
            raise SystemExit('Regenerated file differs: ' + name)
print('Packet whitelist, hashes and regeneration verified')
'''


def generate(out, data):
    r = extract(data)
    files = {'records.json': json.dumps(r, indent=2) + '\n', 'README.md': render_readme(r), 'verify.py': VERIFY}
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_text(content, encoding='utf-8')
    (out / 'MANIFEST.sha256').write_text(''.join(hashlib.sha256(files[n].encode()).hexdigest() + '  ' + n + '\n' for n in sorted(files)), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    args = parser.parse_args()
    generate(args.out, args.binary.read_bytes())
